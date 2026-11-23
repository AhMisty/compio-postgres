//! 预备语句协议夹具。每个客户端请求最多 8 KiB。

use std::{
    future::Future,
    io::{self, Write},
    net::TcpStream,
    time::Duration,
};

use compio_postgres::WireLimits;

use super::{frame, invalid, name};

pub(super) const MAX_REQUEST_LEN: usize = 8192;
pub(crate) const DEADLINE: Duration = Duration::from_secs(8);

pub(crate) const IO_DEADLINE: Duration = Duration::from_secs(2);

pub(crate) fn run<T>(future: impl Future<Output = T>) -> T {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(DEADLINE, future)
            .await
            .expect("general query deadline")
    })
}

pub(crate) fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: MAX_REQUEST_LEN,
        max_frame_len: MAX_REQUEST_LEN - 1,
        max_request_len: MAX_REQUEST_LEN,
        max_messages_per_request: 128,
    }
}

pub(crate) fn body(socket: &mut TcpStream) -> io::Result<Vec<u8>> {
    super::read_body(socket, MAX_REQUEST_LEN)
}

pub(crate) fn expect(socket: &mut TcpStream, tag: u8) -> io::Result<Vec<u8>> {
    super::read_tag(socket, tag, MAX_REQUEST_LEN)
}

pub(crate) fn ready() -> Vec<u8> {
    super::ready(b'I')
}

pub(crate) fn handshake(socket: &mut TcpStream) -> io::Result<()> {
    super::handshake_with_limit(socket, MAX_REQUEST_LEN, 11)
}

pub(crate) fn description(columns: &[(&str, u32, i16)], formats: &[i16]) -> Vec<u8> {
    let mut bytes = Vec::from(u16::try_from(columns.len()).unwrap().to_be_bytes());
    for (index, (name, oid, size)) in columns.iter().enumerate() {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&0_i16.to_be_bytes());
        bytes.extend_from_slice(&oid.to_be_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&(-1_i32).to_be_bytes());
        bytes.extend_from_slice(&formats[index].to_be_bytes());
    }
    frame(b'T', &bytes)
}

pub(crate) fn preparation_response(parameters: &[u32], columns: &[(&str, u32, i16)]) -> Vec<u8> {
    let mut response = frame(b'1', &[]);
    let mut params = Vec::from(u16::try_from(parameters.len()).unwrap().to_be_bytes());
    for oid in parameters {
        params.extend_from_slice(&oid.to_be_bytes());
    }
    response.extend(frame(b't', &params));
    response.extend(if columns.is_empty() {
        frame(b'n', &[])
    } else {
        description(columns, &vec![0; columns.len()])
    });
    response.extend(ready());
    response
}

pub(crate) fn read_prepare(socket: &mut TcpStream) -> io::Result<String> {
    let prepared = name(&expect(socket, b'P')?)?;
    let described = expect(socket, b'D')?;
    if !super::targets_statement(&described, &prepared) || !expect(socket, b'S')?.is_empty() {
        return Err(invalid());
    }
    Ok(prepared)
}

pub(crate) fn prepare(
    socket: &mut TcpStream,
    parameters: &[u32],
    columns: &[(&str, u32, i16)],
) -> io::Result<String> {
    let prepared = read_prepare(socket)?;
    socket.write_all(&preparation_response(parameters, columns))?;
    Ok(prepared)
}

pub(crate) fn execution(
    socket: &mut TcpStream,
    statement: &str,
    portal_describe: bool,
) -> io::Result<()> {
    let bind = expect(socket, b'B')?;
    if bind.first() != Some(&0) || name(&bind[1..])? != statement {
        return Err(invalid());
    }
    if portal_describe && expect(socket, b'D')? != b"P\0" {
        return Err(invalid());
    }
    if expect(socket, b'E')? != [0, 0, 0, 0, 0] || !expect(socket, b'S')?.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn row(values: &[Option<&[u8]>]) -> Vec<u8> {
    super::row(values)
}

pub(crate) fn database_error(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (tag, value) in [(b'S', severity), (b'C', code), (b'M', message)] {
        bytes.push(tag);
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    bytes.push(0);
    frame(b'E', &bytes)
}

pub(crate) fn close_complete(status: u8) -> Vec<u8> {
    let mut result = frame(b'3', &[]);
    result.extend(super::ready(status));
    result
}

pub(crate) fn invalid_statement() -> Vec<u8> {
    frame(b'E', b"SERROR\0C26000\0Mfixture statement error\0\0")
}

pub(crate) fn no_data(status: u8) -> Vec<u8> {
    let mut result = frame(b'1', &[]);
    result.extend(frame(b't', &0_u16.to_be_bytes()));
    result.extend(frame(b'n', &[]));
    result.extend(super::ready(status));
    result
}

pub(crate) fn prepare_no_data(socket: &mut TcpStream, status: u8) -> io::Result<String> {
    let statement = read_prepare(socket)?;
    socket.write_all(&no_data(status))?;
    Ok(statement)
}

pub(crate) fn expect_closes(socket: &mut TcpStream, names: &[String]) -> io::Result<()> {
    for statement in names {
        let close = expect(socket, b'C')?;
        if !super::targets_statement(&close, statement) || !expect(socket, b'S')?.is_empty() {
            return Err(invalid());
        }
    }
    Ok(())
}
