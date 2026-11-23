//! 本地 PostgreSQL 对端。测试脚本控制协议消息，客户端使用真正的 Compio 套接字。
#![allow(dead_code, reason = "每个集成测试独立编译，只使用所需的对端操作")]

#[path = "prepared_peer.rs"]
pub(crate) mod prepared;

#[path = "tcp_options.rs"]
mod tcp_options;
pub(super) use tcp_options::TCP_OPTIONS;

use std::{
    future::Future,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use compio_postgres::{AuthenticationPolicy, QueryLimits, TcpConfig, WireLimits};

pub(crate) const DEADLINE: Duration = Duration::from_secs(10);
pub(crate) const IO_DEADLINE: Duration = Duration::from_secs(3);
const MAX_REQUEST_LEN: usize = 8 * 1024 * 1024;

pub(crate) fn run<T>(future: impl Future<Output = T>) -> T {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(DEADLINE, future)
            .await
            .expect("本地数据库对端测试超时")
    })
}

pub(crate) fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 1024,
        max_result_bytes: 64 * 1024,
        max_metadata_bytes: 16 * 1024,
    }
}

pub(crate) struct Peer {
    pub(crate) endpoint: SocketAddr,
    max_request_len: usize,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Peer {
    pub(crate) fn start(
        script: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
    ) -> Self {
        Self::start_with(script, DEADLINE, IO_DEADLINE, MAX_REQUEST_LEN)
    }

    pub(crate) fn short_queries(
        script: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
    ) -> Self {
        Self::start_with(
            script,
            prepared::DEADLINE,
            prepared::IO_DEADLINE,
            prepared::MAX_REQUEST_LEN,
        )
    }

    pub(crate) fn start_with(
        script: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
        accept_limit: Duration,
        io_limit: Duration,
        max_request_len: usize,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + accept_limit;
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            socket.set_nonblocking(false)?;
            socket.set_nodelay(true)?;
            socket.set_read_timeout(Some(io_limit))?;
            socket.set_write_timeout(Some(io_limit))?;
            script(&mut socket)
        });
        Self {
            endpoint,
            max_request_len,
            worker: Some(worker),
        }
    }

    pub(crate) fn config(&self) -> TcpConfig {
        self.config_with_limits(WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: self.max_request_len,
            max_messages_per_request: 128,
        })
    }

    pub(crate) fn config_with_limits(&self, limits: WireLimits) -> TcpConfig {
        TcpConfig::plaintext(
            self.endpoint,
            "test",
            "test",
            AuthenticationPolicy::AllowAuthenticationOk,
            limits,
            TCP_OPTIONS,
        )
    }

    pub(crate) fn finish(mut self) {
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("本地对端线程发生 panic")
            .expect("本地对端 I/O 失败");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unexpected frontend fixture sequence",
    )
}

fn read_body(socket: &mut TcpStream, maximum: usize) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let length = usize::try_from(i32::from_be_bytes(length)).map_err(|_| invalid())?;
    if !(4..=maximum).contains(&length) {
        return Err(invalid());
    }
    let mut bytes = vec![0; length - 4];
    socket.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn expect(socket: &mut TcpStream, tag: u8) -> io::Result<Vec<u8>> {
    read_tag(socket, tag, MAX_REQUEST_LEN)
}

pub(crate) fn read_tag(socket: &mut TcpStream, tag: u8, maximum: usize) -> io::Result<Vec<u8>> {
    let mut actual = [0];
    socket.read_exact(&mut actual)?;
    if actual[0] != tag {
        return Err(invalid());
    }
    read_body(socket, maximum)
}

pub(crate) fn name(bytes: &[u8]) -> io::Result<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| invalid())
}

pub(crate) fn targets_statement(body: &[u8], statement: &str) -> bool {
    body.strip_prefix(b"S")
        .and_then(|name| name.strip_suffix(b"\0"))
        == Some(statement.as_bytes())
}

pub(crate) fn frame(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let length = i32::try_from(bytes.len() + 4).unwrap();
    let mut output = Vec::with_capacity(bytes.len() + 5);
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

pub(crate) fn ready(status: u8) -> Vec<u8> {
    frame(b'Z', &[status])
}

pub(crate) fn handshake(socket: &mut TcpStream) -> io::Result<()> {
    handshake_with_limit(socket, MAX_REQUEST_LEN, 17)
}

fn handshake_with_limit(socket: &mut TcpStream, maximum: usize, process_id: i32) -> io::Result<()> {
    if read_body(socket, maximum)?.get(..4) != Some(196_610_i32.to_be_bytes().as_slice()) {
        return Err(invalid());
    }
    let mut response = frame(b'R', &0_i32.to_be_bytes());
    response.extend(frame(b'S', b"server_version\x0019.0\0"));
    response.extend(frame(b'S', b"client_encoding\0UTF8\0"));
    let mut key = [0; 12];
    key[..4].copy_from_slice(&process_id.to_be_bytes());
    response.extend(frame(b'K', &key));
    response.extend(ready(b'I'));
    socket.write_all(&response)
}

pub(crate) fn prepare(
    socket: &mut TcpStream,
    parameters: &[u32],
    columns: &[u32],
) -> io::Result<String> {
    prepare_with_status(socket, parameters, columns, b'I')
}

pub(crate) fn prepare_with_status(
    socket: &mut TcpStream,
    parameters: &[u32],
    columns: &[u32],
    status: u8,
) -> io::Result<String> {
    let prepared = name(&expect(socket, b'P')?)?;
    let described = expect(socket, b'D')?;
    if !targets_statement(&described, &prepared) || !expect(socket, b'S')?.is_empty() {
        return Err(invalid());
    }
    let mut response = frame(b'1', &[]);
    let mut params = Vec::from(u16::try_from(parameters.len()).unwrap().to_be_bytes());
    for oid in parameters {
        params.extend_from_slice(&oid.to_be_bytes());
    }
    response.extend(frame(b't', &params));
    if columns.is_empty() {
        response.extend(frame(b'n', &[]));
    } else {
        let mut description = Vec::from(u16::try_from(columns.len()).unwrap().to_be_bytes());
        for (index, oid) in columns.iter().enumerate() {
            description.extend_from_slice(format!("column_{index}\0").as_bytes());
            description.extend_from_slice(&0_u32.to_be_bytes());
            description.extend_from_slice(&0_i16.to_be_bytes());
            description.extend_from_slice(&oid.to_be_bytes());
            description.extend_from_slice(&(if *oid == 23 { 4_i16 } else { -1_i16 }).to_be_bytes());
            description.extend_from_slice(&(-1_i32).to_be_bytes());
            description.extend_from_slice(&0_i16.to_be_bytes());
        }
        response.extend(frame(b'T', &description));
    }
    response.extend(ready(status));
    socket.write_all(&response)?;
    Ok(prepared)
}

pub(crate) fn execution(socket: &mut TcpStream, statement: &str) -> io::Result<()> {
    let bind = expect(socket, b'B')?;
    if bind.first() != Some(&0)
        || name(&bind[1..])? != statement
        || expect(socket, b'E')? != [0, 0, 0, 0, 0]
        || !expect(socket, b'S')?.is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn row(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut body = Vec::from(u16::try_from(values.len()).unwrap().to_be_bytes());
    for value in values {
        match value {
            None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
            Some(bytes) => {
                body.extend_from_slice(&i32::try_from(bytes.len()).unwrap().to_be_bytes());
                body.extend_from_slice(bytes);
            }
        }
    }
    frame(b'D', &body)
}

pub(crate) fn result(value: i32, status: u8) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    response.extend(row(&[Some(&value.to_be_bytes())]));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response.extend(ready(status));
    response
}

pub(crate) fn sql_error(code: &str, status: u8) -> Vec<u8> {
    let mut body = Vec::from(&b"SERROR\0C"[..]);
    body.extend_from_slice(code.as_bytes());
    body.extend_from_slice(b"\0Mfixture database failure\0\0");
    let mut response = frame(b'E', &body);
    response.extend(ready(status));
    response
}

pub(crate) fn control(
    socket: &mut TcpStream,
    sql: &[u8],
    command: &[u8],
    status: u8,
) -> io::Result<()> {
    if expect(socket, b'Q')? != sql {
        return Err(invalid());
    }
    let mut response = frame(b'C', command);
    response.extend(ready(status));
    socket.write_all(&response)
}

pub(crate) fn close_statement(socket: &mut TcpStream, statement: &str) -> io::Result<()> {
    close_statement_with_status(socket, statement, b'I')
}

pub(crate) fn close_statement_with_status(
    socket: &mut TcpStream,
    statement: &str,
    status: u8,
) -> io::Result<()> {
    let close = expect(socket, b'C')?;
    if !targets_statement(&close, statement) || !expect(socket, b'S')?.is_empty() {
        return Err(invalid());
    }
    let mut response = frame(b'3', &[]);
    response.extend(ready(status));
    socket.write_all(&response)
}

pub(crate) fn eof(socket: &mut TcpStream) -> io::Result<()> {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        Ok(_) => Err(invalid()),
        Err(error) => Err(error),
    }
}

/// 已提交的前端请求可能还有尾部字节。读完它们后确认套接字已关闭。
pub(crate) fn drain_until_close(socket: &mut TcpStream) -> io::Result<()> {
    let deadline = Instant::now() + IO_DEADLINE;
    let mut pending = [0; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket.set_read_timeout(Some(remaining))?;
        match socket.read(&mut pending) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "等待客户端关闭连接超时",
    ))
}
