use crate::{
    Error,
    client::{IsolationLevel, TransactionAccess, TransactionDeferrability, TransactionOptions},
    protocol::{Format, QueryTail, STANDARD_IDENTIFIER_BYTES, TxCommand},
    types::{Oid, Parameter},
};

const MESSAGE_LENGTH_BYTES: usize = size_of::<i32>();
const BIND_COUNT_BYTES: usize = 3 * size_of::<u16>();
const SYNC_LENGTH: i32 = MESSAGE_LENGTH_BYTES as i32;
const SYNC_PACKET: &[u8; 5] = b"S\0\0\0\x04";
const UNNAMED_DESCRIBE_PACKET: &[u8; 7] = b"D\0\0\0\x06P\0";
const UNNAMED_EXECUTE_PACKET: &[u8; 10] = b"E\0\0\0\x09\0\0\0\0\0";

/// 用最短的 Bind 和 Execute 估算成员数上限，组尾保留一个 Sync。
pub(crate) fn group_members_fit(member_count: usize, max_bytes: usize) -> bool {
    // 一字节消息标签、消息长度、两个未命名对象和三个计数。
    let bind_bytes =
        1 + MESSAGE_LENGTH_BYTES + 2 * c"".to_bytes_with_nul().len() + BIND_COUNT_BYTES;
    let member_bytes = bind_bytes + UNNAMED_EXECUTE_PACKET.len();
    max_bytes
        .checked_sub(SYNC_PACKET.len())
        .is_some_and(|available| member_count <= available / member_bytes)
}

/// 已编码的 PostgreSQL 语句名或门户名，最后一字节是唯一的 NUL。
#[derive(Clone, Copy)]
pub(crate) struct WireName<'a>(&'a [u8]);

impl<'a> From<&'a std::ffi::CStr> for WireName<'a> {
    fn from(value: &'a std::ffi::CStr) -> Self {
        Self(value.to_bytes_with_nul())
    }
}

impl<'a> WireName<'a> {
    pub(crate) fn bytes_with_nul(self) -> &'a [u8] {
        self.0
    }
}

const STATEMENT_NAME_BYTES: usize = 2 + 20 + 1;

/// 名称随登记槽保存。冒号保留客户端命名空间，最长的十进制 u64 占 20 字节。
pub(crate) struct StatementName {
    bytes: [u8; STATEMENT_NAME_BYTES],
    length: u8,
}

impl StatementName {
    pub(crate) const UNNAMED: Self = Self {
        bytes: [0; STATEMENT_NAME_BYTES],
        length: 1,
    };

    pub(crate) fn numbered(id: u64) -> Result<Self, Error> {
        use std::io::Write;
        let mut name = Self::UNNAMED;
        let capacity = name.bytes.len();
        let mut remaining = name.bytes.as_mut_slice();
        write!(remaining, ":p{id}\0").map_err(|_| Error::Broken)?;
        name.length = u8::try_from(capacity - remaining.len()).map_err(|_| Error::Broken)?;
        Ok(name)
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "名称长度来自成功写入定长缓冲区的字节数，未命名语句固定占一字节"
    )]
    pub(crate) fn wire(&self) -> WireName<'_> {
        WireName(&self.bytes[..usize::from(self.length)])
    }
}

/// 追加一个命名语句的 Parse、Describe 和 Sync，直接写入参数 OID。
pub(crate) fn append_prepare(
    output: &mut Vec<u8>,
    statement: WireName<'_>,
    sql: &str,
    parameter_oids: &[crate::types::Oid],
    max_bytes: usize,
) -> Result<(), Error> {
    let parse_length = parse_length(statement, sql, parameter_oids.len(), max_bytes)?;
    let describe_length = message_length(&[1, statement.bytes_with_nul().len()])?;
    let addition = bounded_output_length(&[parse_length, describe_length, SYNC_LENGTH], max_bytes)?;
    reserve_packet_append(output, addition, max_bytes)?;
    write_header(output, b'P', parse_length);
    output.extend_from_slice(statement.bytes_with_nul());
    write_cstring(output, sql);
    output.extend_from_slice(&count_u16(parameter_oids.len())?.to_be_bytes());
    for oid in parameter_oids {
        output.extend_from_slice(&oid.0.to_be_bytes());
    }
    write_header(output, b'D', describe_length);
    output.push(b'S');
    output.extend_from_slice(statement.bytes_with_nul());
    write_tail(output, QueryTail::Sync);
    Ok(())
}

#[cfg(test)]
pub(crate) fn close(statement: &std::ffi::CStr) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    append_close_sync(&mut output, statement.into(), usize::MAX)?;
    Ok(output)
}

/// 追加 Close 和独立的 Sync。先检查追加后的完整长度，再修改已编码前缀。
pub(crate) fn append_close_sync(
    output: &mut Vec<u8>,
    statement: WireName<'_>,
    max_bytes: usize,
) -> Result<(), Error> {
    let close_length = message_length(&[1, statement.bytes_with_nul().len()])?;
    let addition = bounded_output_length(&[close_length, SYNC_LENGTH], max_bytes)?;
    reserve_packet_append(output, addition, max_bytes)?;
    write_header(output, b'C', close_length);
    output.push(b'S');
    output.extend_from_slice(statement.bytes_with_nul());
    write_tail(output, QueryTail::Sync);
    Ok(())
}

/// Close 消息头、关闭对象的类型字节、带终止符的名称和独立 Sync。
pub(crate) fn close_sync_bytes(statement: WireName<'_>) -> usize {
    1 + MESSAGE_LENGTH_BYTES + 1 + statement.bytes_with_nul().len() + SYNC_PACKET.len()
}

// 独占 Portal 守卫保证每个会话同时只使用一个门户名称。
const PORTAL_NAME: WireName<'static> = WireName(c"compio-postgres:portal".to_bytes_with_nul());

pub(crate) fn bind_portal(
    take_buffer: impl FnOnce() -> Result<Vec<u8>, Error>,
    parameters: &StatementParameters<'_>,
    max_bytes: usize,
    type_error: &'static str,
) -> Result<Vec<u8>, Error> {
    let shape = parameters.measure(type_error)?;
    let execute_length = message_length(&[PORTAL_NAME.bytes_with_nul().len(), 4])?;
    let suffix = output_length(&[execute_length, SYNC_LENGTH])?;
    let bind_budget = max_bytes.checked_sub(suffix).ok_or(REQUEST_LIMIT)?;
    let (bind, bind_bytes) = BindSize::new(
        PORTAL_NAME,
        parameters.statement,
        parameters.values.len(),
        parameters.result_formats.len(),
    )?
    .plan(shape, bind_budget)?;
    let capacity = bind_bytes + suffix;
    let mut output = reuse_bytes(take_buffer()?, capacity, max_bytes)?;
    write_bind(
        &mut output,
        PORTAL_NAME,
        parameters.statement,
        parameters.values,
        parameters.result_formats,
        &bind,
    );
    Ok(output)
}

/// 把 Execute 和 Sync 接在待发送的 Bind 后；已绑定的门户只需发送这两个消息。
pub(crate) fn append_portal_fetch(
    output: &mut Vec<u8>,
    max_rows: i32,
    max_bytes: usize,
) -> Result<(), Error> {
    let execute_length = message_length(&[PORTAL_NAME.bytes_with_nul().len(), 4])?;
    reserve_packet_append(
        output,
        output_length(&[execute_length, SYNC_LENGTH])?,
        max_bytes,
    )?;
    write_header(output, b'E', execute_length);
    output.extend_from_slice(PORTAL_NAME.bytes_with_nul());
    output.extend_from_slice(&max_rows.to_be_bytes());
    write_tail(output, QueryTail::Sync);
    Ok(())
}

pub(crate) fn close_portal(output: Vec<u8>, max_bytes: usize) -> Result<Vec<u8>, Error> {
    let close_length = message_length(&[1, PORTAL_NAME.bytes_with_nul().len()])?;
    let capacity = bounded_output_length(&[close_length, SYNC_LENGTH], max_bytes)?;
    let mut output = reuse_bytes(output, capacity, max_bytes)?;
    write_header(&mut output, b'C', close_length);
    output.push(b'P');
    output.extend_from_slice(PORTAL_NAME.bytes_with_nul());
    write_tail(&mut output, QueryTail::Sync);
    Ok(output)
}

/// 写入前已验证的预备语句执行请求。参数在长度检查到实际编码期间保持不变。
pub(crate) struct PreparedExecution<'a> {
    statement: WireName<'a>,
    parameters: &'a [Parameter<'a>],
    result_formats: &'a [Format],
    bind: BindLayout,
    encoded_len: usize,
    describe: bool,
    tail: QueryTail,
}

/// 暂存窗口成员时保留的 Bind 布局，后接固定的 Execute 和 Sync。
#[derive(Clone, Copy)]
pub(crate) struct WindowExecutionLayout(BindLayout);

impl WindowExecutionLayout {
    pub(crate) fn encoded_len(&self) -> usize {
        // 原包已验证长度，Bind 消息长度外另计一字节标签。
        usize::try_from(self.0.length.cast_unsigned())
            .unwrap_or(usize::MAX)
            .saturating_add(1 + UNNAMED_EXECUTE_PACKET.len() + SYNC_PACKET.len())
    }
}

impl<'a> PreparedExecution<'a> {
    fn untyped(
        statement: WireName<'a>,
        parameters: &'a [Parameter<'a>],
        result_formats: &'a [Format],
        describe: bool,
        tail: QueryTail,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        let size = BindSize::unnamed(statement, parameters.len(), result_formats.len())?;
        let suffix = execution_suffix_length(describe, tail);
        let bind_budget = max_bytes.checked_sub(suffix).ok_or(REQUEST_LIMIT)?;
        let minimum = size.minimum_packet_bytes()?;
        let max_payload = bind_budget.checked_sub(minimum).ok_or(REQUEST_LIMIT)?;
        let shape = ParameterShape::untyped(parameters, max_payload)?;
        let (bind, bind_bytes) = size.plan(shape, bind_budget)?;
        Ok(Self {
            statement,
            parameters,
            result_formats,
            bind,
            encoded_len: bind_bytes + suffix,
            describe,
            tail,
        })
    }

    pub(crate) fn checked(
        parameters: &StatementParameters<'a>,
        tail: QueryTail,
        max_bytes: usize,
        type_error: &'static str,
        check_layout: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let shape = parameters.measure(type_error)?;
        check_layout()?;
        let suffix = execution_suffix_length(false, tail);
        let bind_budget = max_bytes.checked_sub(suffix).ok_or(REQUEST_LIMIT)?;
        let (bind, bind_bytes) = parameters.bind_size.plan(shape, bind_budget)?;
        Ok(Self {
            statement: parameters.statement,
            parameters: parameters.values,
            result_formats: parameters.result_formats,
            bind,
            encoded_len: bind_bytes + suffix,
            describe: false,
            tail,
        })
    }

    /// 重新绑定相同的预备语句和不可变参数。调用方须先重新校验语句身份与有效性。
    pub(crate) fn reuse_window(
        statement: WireName<'a>,
        parameters: &'a [Parameter<'a>],
        result_formats: &'a [Format],
        layout: WindowExecutionLayout,
    ) -> Self {
        Self {
            statement,
            parameters,
            result_formats,
            bind: layout.0,
            encoded_len: layout.encoded_len(),
            describe: false,
            tail: QueryTail::Sync,
        }
    }

    pub(crate) fn window_layout(&self) -> WindowExecutionLayout {
        debug_assert!(!self.describe && self.tail == QueryTail::Sync);
        WindowExecutionLayout(self.bind)
    }

    #[cfg(feature = "diagnostics")]
    pub(crate) fn payload_bytes(&self) -> usize {
        self.bind.payload_bytes
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.encoded_len
    }
    /// 将已验证的执行请求和选定的结束消息追加到有界发送包。
    pub(crate) fn append_to(&self, output: &mut Vec<u8>, max_bytes: usize) -> Result<(), Error> {
        reserve_packet_append(output, self.encoded_len(), max_bytes)?;
        self.write(output);
        Ok(())
    }

    pub(crate) fn encode_into(&self, output: Vec<u8>, max_bytes: usize) -> Result<Vec<u8>, Error> {
        let mut output = reuse_bytes(output, self.encoded_len(), max_bytes)?;
        self.write(&mut output);
        Ok(output)
    }

    fn write(&self, output: &mut Vec<u8>) {
        write_execution(
            output,
            self.statement,
            self.parameters,
            self.result_formats,
            &self.bind,
            self.describe,
        );
        write_tail(output, self.tail);
    }
}

fn reserve_packet_append(
    output: &mut Vec<u8>,
    encoded_len: usize,
    max_bytes: usize,
) -> Result<(), Error> {
    let Some(required) = output.len().checked_add(encoded_len) else {
        return Err(Error::Limit("frontend packet size overflow"));
    };
    check_capacity(required, max_bytes)?;
    if output.capacity() > max_bytes {
        if !output.is_empty() {
            return Err(Error::Limit("frontend packet backing exceeds its bound"));
        }
        *output = Vec::new();
    }
    if required > output.capacity() {
        let capacity = required
            .max(output.capacity().saturating_mul(2))
            .min(max_bytes);
        output
            .try_reserve_exact(capacity - output.len())
            .map_err(|_| Error::Limit("cannot grow frontend packet"))?;
    }
    if output.capacity() > max_bytes {
        return Err(Error::Limit("frontend packet backing exceeds its bound"));
    }
    Ok(())
}

/// 为已编码的一组执行请求追加一个 Sync。
pub(crate) fn append_sync(output: &mut Vec<u8>, max_bytes: usize) -> Result<(), Error> {
    reserve_packet_append(output, SYNC_PACKET.len(), max_bytes)?;
    write_tail(output, QueryTail::Sync);
    Ok(())
}

/// 将多次执行编码到同一发送包，各自保留独立的 Sync。
#[cfg(test)]
pub(crate) fn execute_prepared_pipeline(
    executions: &[PreparedExecution<'_>],
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for execution in executions {
        execution.append_to(&mut output, max_bytes)?;
    }
    Ok(output)
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn tags(bytes: &[u8]) -> Vec<u8> {
        let mut cursor = bytes;
        let mut result = Vec::new();
        while !cursor.is_empty() {
            result.push(cursor[0]);
            let length =
                usize::try_from(i32::from_be_bytes(cursor[1..5].try_into().unwrap())).unwrap();
            cursor = &cursor[1 + length..];
        }
        result
    }

    #[test]
    fn group_uses_open_executions_and_one_exactly_bounded_sync() {
        let parameters = [Parameter::int4(7)];
        let formats = [Format::Binary];
        let open = PreparedExecution::untyped(
            c"s".into(),
            &parameters,
            &formats,
            false,
            QueryTail::Open,
            1024,
        )
        .unwrap();
        let independent = PreparedExecution::untyped(
            c"s".into(),
            &parameters,
            &formats,
            false,
            QueryTail::Sync,
            1024,
        )
        .unwrap();
        assert_eq!(independent.encoded_len(), open.encoded_len() + 5);
        let exact = open.encoded_len() * 2 + 5;
        let mut group = Vec::new();
        for _ in 0..2 {
            open.append_to(&mut group, exact).unwrap();
        }
        assert_eq!(tags(&group), b"BEBE");
        let mut too_small = group.clone();
        assert!(matches!(
            append_sync(&mut too_small, exact - 1),
            Err(Error::Limit(_))
        ));
        assert_eq!(tags(&too_small), b"BEBE");
        append_sync(&mut group, exact).unwrap();
        assert_eq!(tags(&group), b"BEBES");
        assert_eq!(group.len(), exact);
        let mut separate = Vec::new();
        for _ in 0..2 {
            independent.append_to(&mut separate, 1024).unwrap();
        }
        assert_eq!(tags(&separate), b"BESBES");
    }
}

pub(crate) fn one_shot(
    take_buffer: impl FnOnce() -> Result<Vec<u8>, Error>,
    sql: &str,
    parameters: &[Parameter<'_>],
    result_formats: &[Format],
    describe_portal: bool,
    tail: QueryTail,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let parse_length = parse_length(c"".into(), sql, parameters.len(), max_bytes)?;
    let parse_bytes = output_length(&[parse_length])?;
    let execution_budget = max_bytes.checked_sub(parse_bytes).ok_or(REQUEST_LIMIT)?;
    let execution = PreparedExecution::untyped(
        c"".into(),
        parameters,
        result_formats,
        describe_portal,
        tail,
        execution_budget,
    )?;
    let capacity = execution.encoded_len() + parse_bytes;
    let mut output = reuse_bytes(take_buffer()?, capacity, max_bytes)?;
    write_header(&mut output, b'P', parse_length);
    output.push(0);
    write_cstring(&mut output, sql);
    output.extend_from_slice(&execution.bind.parameter_count.to_be_bytes());
    for parameter in parameters {
        output.extend_from_slice(&parameter.oid().0.to_be_bytes());
    }
    execution.write(&mut output);
    Ok(output)
}

/// 接手已完成发送的缓冲区前先校验整个 Q 消息的大小。单语句约束由调用方保证。
pub(crate) struct SimpleQueryPacket<'sql> {
    sql: SimpleQuerySql<'sql>,
    length: i32,
    capacity: usize,
    max_bytes: usize,
}

enum SimpleQuerySql<'sql> {
    Text(&'sql str),
    QuotedIdentifier {
        prefix: &'static str,
        name: &'sql str,
    },
    Begin(TransactionOptions),
}

impl<'sql> SimpleQueryPacket<'sql> {
    pub(crate) fn simple(sql: &'sql str, max_bytes: usize) -> Result<Self, Error> {
        let length = message_length(&[sql.len(), 1])?;
        let capacity = bounded_output_length(&[length], max_bytes)?;
        validate_cstring(sql, "SQL contains a NUL byte")?;
        Ok(Self {
            sql: SimpleQuerySql::Text(sql),
            length,
            capacity,
            max_bytes,
        })
    }

    pub(crate) fn begin(options: TransactionOptions, max_bytes: usize) -> Result<Self, Error> {
        if options == TransactionOptions::default() {
            return Self::simple("BEGIN", max_bytes);
        }
        let [isolation, access, deferrability] = begin_clauses(options);
        let length = message_length(&[5, isolation.len(), access.len(), deferrability.len(), 1])?;
        Ok(Self {
            sql: SimpleQuerySql::Begin(options),
            length,
            capacity: bounded_output_length(&[length], max_bytes)?,
            max_bytes,
        })
    }

    /// 生成固定事务控制 SQL，名称按带引号的标识符编码。命令标签和随后的 Ready 状态分别确认。
    pub(crate) fn transaction(command: TxCommand<'sql>, max_bytes: usize) -> Result<Self, Error> {
        let (prefix, name) = match command {
            TxCommand::Begin => return Self::simple("BEGIN", max_bytes),
            TxCommand::Commit { chain: false } => return Self::simple("COMMIT", max_bytes),
            TxCommand::Commit { chain: true } => {
                return Self::simple("COMMIT AND CHAIN", max_bytes);
            }
            TxCommand::Rollback { chain: false } => return Self::simple("ROLLBACK", max_bytes),
            TxCommand::Rollback { chain: true } => {
                return Self::simple("ROLLBACK AND CHAIN", max_bytes);
            }
            TxCommand::Savepoint(name) => ("SAVEPOINT", name),
            TxCommand::ReleaseSavepoint(name) => ("RELEASE SAVEPOINT", name),
            TxCommand::RollbackToSavepoint(name) => ("ROLLBACK TO SAVEPOINT", name),
        };
        Self::quoted_identifier(prefix, name, max_bytes)
    }

    pub(crate) fn quoted_identifier(
        prefix: &'static str,
        name: &'sql str,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        // PostgreSQL 标准构建会截断超过 63 字节的标识符，避免不同名称指向同一个对象。
        if name.is_empty() || name.len() > STANDARD_IDENTIFIER_BYTES || name.as_bytes().contains(&0)
        {
            return Err(Error::InvalidInput(
                "the identifier must contain 1..=63 UTF-8 bytes and no NUL",
            ));
        }
        let quotes = name.bytes().filter(|byte| *byte == b'"').count();
        let length = message_length(&[prefix.len(), 3, name.len(), quotes, 1])?;
        let capacity = bounded_output_length(&[length], max_bytes)?;
        Ok(Self {
            sql: SimpleQuerySql::QuotedIdentifier { prefix, name },
            length,
            capacity,
            max_bytes,
        })
    }

    pub(crate) fn encode_into(self, output: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut output = reuse_bytes(output, self.capacity, self.max_bytes)?;
        write_header(&mut output, b'Q', self.length);
        match self.sql {
            SimpleQuerySql::Text(sql) => output.extend_from_slice(sql.as_bytes()),
            SimpleQuerySql::QuotedIdentifier { prefix, name } => {
                output.extend_from_slice(prefix.as_bytes());
                output.extend_from_slice(b" \"");
                for byte in name.bytes() {
                    output.push(byte);
                    if byte == b'"' {
                        output.push(byte);
                    }
                }
                output.push(b'"');
            }
            SimpleQuerySql::Begin(options) => {
                output.extend_from_slice(b"BEGIN");
                for clause in begin_clauses(options) {
                    output.extend_from_slice(clause.as_bytes());
                }
            }
        }
        output.push(0);
        Ok(output)
    }
}

fn begin_clauses(options: TransactionOptions) -> [&'static str; 3] {
    let isolation = match options.isolation {
        None => "",
        Some(IsolationLevel::ReadUncommitted) => " ISOLATION LEVEL READ UNCOMMITTED",
        Some(IsolationLevel::ReadCommitted) => " ISOLATION LEVEL READ COMMITTED",
        Some(IsolationLevel::RepeatableRead) => " ISOLATION LEVEL REPEATABLE READ",
        Some(IsolationLevel::Serializable) => " ISOLATION LEVEL SERIALIZABLE",
    };
    let access = match options.access {
        None => "",
        Some(TransactionAccess::ReadOnly) => " READ ONLY",
        Some(TransactionAccess::ReadWrite) => " READ WRITE",
    };
    let deferrability = match options.deferrability {
        None => "",
        Some(TransactionDeferrability::Deferrable) => " DEFERRABLE",
        Some(TransactionDeferrability::NotDeferrable) => " NOT DEFERRABLE",
    };
    [isolation, access, deferrability]
}

pub(crate) fn terminate(buffer: Vec<u8>, max_bytes: usize) -> Result<Vec<u8>, Error> {
    control(b'X', buffer, max_bytes)
}

#[cfg(test)]
pub(crate) fn simple_query(sql: &str, max_bytes: usize) -> Result<Vec<u8>, Error> {
    SimpleQueryPacket::simple(sql, max_bytes)?.encode_into(Vec::new())
}

#[cfg(test)]
pub(crate) fn transaction(command: TxCommand<'_>, max_bytes: usize) -> Result<Vec<u8>, Error> {
    SimpleQueryPacket::transaction(command, max_bytes)?.encode_into(Vec::new())
}

/// 把一个不透明 CopyData 负载复制到有界连续存储，保留其原始字节。
#[cfg(test)]
pub(crate) fn copy_data(bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>, Error> {
    CopyDataBatch::new(&[bytes], max_bytes)?.encode_into(Vec::new())
}

/// 修改发送包前验证全部 CopyData 切片。每个切片保留独立帧；结束 COPY 或发送 Sync 须另行指定。
pub(crate) struct CopyDataBatch<'input> {
    chunks: &'input [&'input [u8]],
    capacity: usize,
    work_units: usize,
    max_bytes: usize,
}

impl<'input> CopyDataBatch<'input> {
    pub(crate) fn new(chunks: &'input [&'input [u8]], max_bytes: usize) -> Result<Self, Error> {
        let mut capacity = 0_usize;
        let mut work_units = 0;
        for chunk in chunks {
            let length = message_length(&[chunk.len()])?;
            let frame_bytes = output_length(&[length])?;
            let Some(next) = capacity.checked_add(frame_bytes) else {
                return Err(Error::Limit("COPY batch packet length overflow"));
            };
            check_capacity(next, max_bytes)?;
            capacity = next;
            // 每个帧至少消耗一个计量单位。
            work_units += crate::scheduler::byte_work_units(frame_bytes);
        }
        Ok(Self {
            chunks,
            capacity,
            work_units,
            max_bytes,
        })
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        // 已验证的包容量包含各帧的五字节帧头。
        self.capacity - self.chunks.len() * 5
    }

    pub(crate) fn work_units(&self) -> usize {
        self.work_units
    }

    pub(crate) fn encode_into(self, output: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut output = reuse_bytes(output, self.capacity, self.max_bytes)?;
        for chunk in self.chunks {
            // 构造时已验证同一批切片的每个帧长。
            let length = (chunk.len() + size_of::<i32>()) as i32;
            write_header(&mut output, b'd', length);
            output.extend_from_slice(chunk);
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::copy_in(chunk.len());
        }
        Ok(output)
    }
}

/// 在取得已回收的发送缓冲区前，预检 COPY 结束消息和指定的后续消息。
pub(crate) struct CopyEnd<'a> {
    message: Option<&'a str>,
    tail: QueryTail,
    length: i32,
    capacity: usize,
    max_bytes: usize,
}

impl<'a> CopyEnd<'a> {
    pub(crate) fn new(
        message: Option<&'a str>,
        tail: QueryTail,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        let length = match message {
            Some(message) => message_length(&[message.len(), 1])?,
            None => SYNC_LENGTH,
        };
        let Some(capacity) = output_length(&[length])?.checked_add(tail_length(tail)) else {
            return Err(Error::Limit("COPY termination length overflow"));
        };
        check_capacity(capacity, max_bytes)?;
        if let Some(message) = message {
            validate_cstring(message, "COPY failure message contains a NUL byte")?;
        }
        Ok(Self {
            message,
            tail,
            length,
            capacity,
            max_bytes,
        })
    }

    pub(crate) fn encode_into(self, output: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut output = reuse_bytes(output, self.capacity, self.max_bytes)?;
        write_header(
            &mut output,
            if self.message.is_some() { b'f' } else { b'c' },
            self.length,
        );
        if let Some(message) = self.message {
            write_cstring(&mut output, message);
        }
        write_tail(&mut output, self.tail);
        Ok(output)
    }
}

#[cfg(test)]
fn copy_end(message: Option<&str>, tail: QueryTail, max_bytes: usize) -> Result<Vec<u8>, Error> {
    CopyEnd::new(message, tail, max_bytes)?.encode_into(Vec::new())
}

pub(crate) fn sync(buffer: Vec<u8>, max_bytes: usize) -> Result<Vec<u8>, Error> {
    control(b'S', buffer, max_bytes)
}

fn control(tag: u8, buffer: Vec<u8>, max_bytes: usize) -> Result<Vec<u8>, Error> {
    let mut output = reuse_bytes(buffer, 5, max_bytes)?;
    write_header(&mut output, tag, SYNC_LENGTH);
    Ok(output)
}

fn parse_length(
    statement: WireName<'_>,
    sql: &str,
    parameter_count: usize,
    max_bytes: usize,
) -> Result<i32, Error> {
    count_u16(parameter_count)?;
    let oid_bytes = parameter_count
        .checked_mul(4)
        .ok_or(Error::Limit("parameter OID length overflow"))?;
    let length = message_length(&[statement.bytes_with_nul().len(), sql.len(), 1, 2, oid_bytes])?;
    bounded_output_length(&[length], max_bytes)?;
    validate_cstring(sql, "SQL contains a NUL byte")?;
    Ok(length)
}

/// 已核对数量的参数切片和预备语句 OID；构造 Bind 时逐项校验类型。
pub(crate) struct StatementParameters<'a> {
    values: &'a [Parameter<'a>],
    oids: &'a [Oid],
    statement: WireName<'a>,
    result_formats: &'a [Format],
    bind_size: BindSize,
}

impl<'a> StatementParameters<'a> {
    pub(crate) fn new(
        values: &'a [Parameter<'a>],
        oids: &'a [Oid],
        statement: WireName<'a>,
        result_formats: &'a [Format],
        bind_size: BindSize,
        count_error: &'static str,
    ) -> Result<Self, Error> {
        if values.len() != oids.len() {
            return Err(Error::InvalidInput(count_error));
        }
        Ok(Self {
            values,
            oids,
            statement,
            result_formats,
            bind_size,
        })
    }

    /// COPY 由服务端响应单独报告列格式。其 Bind 使用默认的结果格式。
    pub(crate) fn use_default_result_formats(&mut self) {
        self.bind_size.minimum_packet_bytes -= u32::from(self.bind_size.result_count) * 2;
        self.bind_size.result_count = 0;
        self.result_formats = &[];
    }

    fn measure(&self, type_error: &'static str) -> Result<ParameterShape, Error> {
        ParameterShape::measure(self.values.iter().zip(self.oids), |parameter, oid, _| {
            if parameter.oid() != *oid {
                return Err(Error::InvalidInput(type_error));
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
struct ParameterShape {
    payload_bytes: usize,
    uniform_format: Option<Format>,
}

impl ParameterShape {
    fn untyped(values: &[Parameter<'_>], max_payload: usize) -> Result<Self, Error> {
        Self::measure(values.iter().map(|value| (value, ())), |_, (), bytes| {
            check_capacity(bytes, max_payload)
        })
    }

    fn measure<'a, M>(
        mut values: impl Iterator<Item = (&'a Parameter<'a>, M)>,
        mut check: impl FnMut(&Parameter<'a>, M, usize) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let Some((first, metadata)) = values.next() else {
            return Ok(Self {
                payload_bytes: 0,
                uniform_format: Some(Format::Text),
            });
        };
        let format = first.format();
        let mut uniform_format = Some(format);
        let mut payload_bytes = first.payload_len();
        check(first, metadata, payload_bytes)?;
        for (parameter, metadata) in values.by_ref() {
            payload_bytes = payload_bytes.saturating_add(parameter.payload_len());
            check(parameter, metadata, payload_bytes)?;
            if parameter.format() != format {
                uniform_format = None;
                break;
            }
        }
        // 已知是混合格式，剩余参数只核对 OID 和数据长度。超出 usize 的总长度必然也超出协议上限。
        for (parameter, metadata) in values {
            payload_bytes = payload_bytes.saturating_add(parameter.payload_len());
            check(parameter, metadata, payload_bytes)?;
        }
        Ok(Self {
            payload_bytes,
            uniform_format,
        })
    }
}

#[derive(Clone, Copy)]
struct BindLayout {
    #[cfg(feature = "diagnostics")]
    payload_bytes: usize,
    length: i32,
    parameter_count: u16,
    format_count: u16,
    uniform_format: Format,
    result_count: u16,
}

/// 与参数值无关的 Bind 长度和计数。预备语句在接收描述时保存未命名 portal 的布局。
#[derive(Debug, Clone, Copy)]
pub(crate) struct BindSize {
    minimum_packet_bytes: u32,
    parameter_count: u16,
    result_count: u16,
}

impl BindSize {
    pub(crate) fn unnamed(
        statement: WireName<'_>,
        parameter_count: usize,
        result_count: usize,
    ) -> Result<Self, Error> {
        Self::new(c"".into(), statement, parameter_count, result_count)
    }

    fn new(
        portal: WireName<'_>,
        statement: WireName<'_>,
        parameter_count: usize,
        result_count: usize,
    ) -> Result<Self, Error> {
        let parameter_count = count_u16(parameter_count)?;
        let result_count = count_u16(result_count)?;
        // 即使全部使用文本格式并传入 NULL，每个参数仍须写入四字节长度。
        let minimum_length = message_length(&[
            portal.bytes_with_nul().len(),
            statement.bytes_with_nul().len(),
            BIND_COUNT_BYTES,
            usize::from(parameter_count) * 4,
            usize::from(result_count) * 2,
        ])?;
        Ok(Self {
            // 消息长度检查已保证取值为正，额外一字节是 Bind 标签。
            minimum_packet_bytes: minimum_length.cast_unsigned() + 1,
            parameter_count,
            result_count,
        })
    }

    fn minimum_packet_bytes(self) -> Result<usize, Error> {
        usize::try_from(self.minimum_packet_bytes)
            .map_err(|_| Error::Limit("frontend output length overflow"))
    }

    fn plan(self, shape: ParameterShape, max_bytes: usize) -> Result<(BindLayout, usize), Error> {
        let minimum_packet_bytes = self.minimum_packet_bytes()?;
        const OVERFLOW: Error = Error::Limit("Bind message length overflow");
        let Some(payload_packet_bytes) = minimum_packet_bytes.checked_add(shape.payload_bytes)
        else {
            check_capacity(minimum_packet_bytes, max_bytes)?;
            return Err(OVERFLOW);
        };
        let (format_count, uniform_format) = match shape.uniform_format {
            Some(Format::Text) => (0, Format::Text),
            Some(Format::Binary) => (1, Format::Binary),
            None => (self.parameter_count, Format::Text),
        };
        let Some(packet_bytes) = payload_packet_bytes.checked_add(usize::from(format_count) * 2)
        else {
            check_capacity(payload_packet_bytes, max_bytes)?;
            return Err(OVERFLOW);
        };
        check_capacity(packet_bytes, max_bytes)?;
        let length = i32::try_from(packet_bytes - 1)
            .map_err(|_| Error::Limit("Bind message exceeds its wire length limit"))?;
        Ok((
            BindLayout {
                #[cfg(feature = "diagnostics")]
                payload_bytes: shape.payload_bytes,
                length,
                parameter_count: self.parameter_count,
                format_count,
                uniform_format,
                result_count: self.result_count,
            },
            packet_bytes,
        ))
    }
}

fn execution_suffix_length(describe: bool, tail: QueryTail) -> usize {
    let describe_bytes = if describe {
        UNNAMED_DESCRIBE_PACKET.len()
    } else {
        0
    };
    UNNAMED_EXECUTE_PACKET.len() + describe_bytes + tail_length(tail)
}

fn write_execution(
    output: &mut Vec<u8>,
    statement: WireName<'_>,
    parameters: &[Parameter<'_>],
    result_formats: &[Format],
    layout: &BindLayout,
    describe: bool,
) {
    write_bind(
        output,
        c"".into(),
        statement,
        parameters,
        result_formats,
        layout,
    );
    if describe {
        // 描述未命名门户。
        output.extend_from_slice(UNNAMED_DESCRIBE_PACKET);
    }
    // 执行未命名门户，不限制行数。
    output.extend_from_slice(UNNAMED_EXECUTE_PACKET);
}

#[inline]
fn write_bind(
    output: &mut Vec<u8>,
    portal: WireName<'_>,
    statement: WireName<'_>,
    parameters: &[Parameter<'_>],
    result_formats: &[Format],
    layout: &BindLayout,
) {
    write_header(output, b'B', layout.length);
    output.extend_from_slice(portal.bytes_with_nul());
    output.extend_from_slice(statement.bytes_with_nul());
    output.extend_from_slice(&layout.format_count.to_be_bytes());
    if layout.format_count == 1 {
        output.extend_from_slice(&layout.uniform_format.code().to_be_bytes());
    } else if layout.format_count != 0 {
        for parameter in parameters {
            output.extend_from_slice(&parameter.format().code().to_be_bytes());
        }
    }
    output.extend_from_slice(&layout.parameter_count.to_be_bytes());
    for parameter in parameters {
        parameter.append_bind_field(output);
    }
    output.extend_from_slice(&layout.result_count.to_be_bytes());
    for format in result_formats {
        output.extend_from_slice(&format.code().to_be_bytes());
    }
}

fn tail_length(tail: QueryTail) -> usize {
    match tail {
        QueryTail::Sync | QueryTail::Flush => 5,
        QueryTail::Open => 0,
    }
}

fn write_tail(output: &mut Vec<u8>, tail: QueryTail) {
    match tail {
        QueryTail::Sync => output.extend_from_slice(SYNC_PACKET),
        QueryTail::Flush => output.extend_from_slice(b"H\0\0\0\x04"),
        QueryTail::Open => {}
    }
}

fn count_u16(count: usize) -> Result<u16, Error> {
    u16::try_from(count).map_err(|_| Error::Limit("PostgreSQL field count exceeds u16"))
}

const REQUEST_LIMIT: Error = Error::Limit("the encoded request exceeds its configured limit");

fn check_capacity(capacity: usize, max_bytes: usize) -> Result<(), Error> {
    if capacity > max_bytes {
        return Err(REQUEST_LIMIT);
    }
    Ok(())
}

fn bounded_output_length(lengths: &[i32], max_bytes: usize) -> Result<usize, Error> {
    let capacity = output_length(lengths)?;
    check_capacity(capacity, max_bytes)?;
    Ok(capacity)
}

fn validate_cstring(value: &str, message: &'static str) -> Result<(), Error> {
    if value.as_bytes().contains(&0) {
        return Err(Error::InvalidInput(message));
    }
    Ok(())
}

fn message_length(parts: &[usize]) -> Result<i32, Error> {
    let Some(length) = parts.iter().try_fold(MESSAGE_LENGTH_BYTES, |length, part| {
        length.checked_add(*part)
    }) else {
        return Err(Error::Limit("frontend message length overflow"));
    };
    i32::try_from(length)
        .map_err(|_| Error::Limit("frontend message exceeds its wire length limit"))
}

fn output_length(lengths: &[i32]) -> Result<usize, Error> {
    lengths.iter().try_fold(0_usize, |total, length| {
        let length = usize::try_from(*length)
            .map_err(|_| Error::Limit("invalid frontend message length"))?;
        let Some(total) = total
            .checked_add(1)
            .and_then(|total| total.checked_add(length))
        else {
            return Err(Error::Limit("frontend output length overflow"));
        };
        Ok(total)
    })
}

fn reuse_bytes(mut output: Vec<u8>, capacity: usize, max_bytes: usize) -> Result<Vec<u8>, Error> {
    check_capacity(capacity, max_bytes)?;
    output.clear();
    if output.capacity() > max_bytes {
        output = Vec::new();
    }
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Limit("frontend output allocation failed"))?;
    if output.capacity() > max_bytes {
        return Err(Error::Limit("frontend retained capacity exceeds its limit"));
    }
    Ok(output)
}

fn write_header(output: &mut Vec<u8>, tag: u8, length: i32) {
    let [a, b, c, d] = length.to_be_bytes();
    output.extend_from_slice(&[tag, a, b, c, d]);
}

fn write_cstring(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(value.as_bytes());
    output.push(0);
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "diagnostics")]
    #[global_allocator]
    static GLOBAL: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

    #[cfg(feature = "diagnostics")]
    #[test]
    #[ignore = "分配诊断须单独运行，以隔离进程级计数"]
    fn simple_and_transaction_packets_reuse_retired_tx_without_allocation() {
        use super::SimpleQueryPacket;
        let mut output = Vec::with_capacity(4096);
        output.extend_from_slice(b"retired packet");
        let pointer = output.as_ptr();
        let region = stats_alloc::Region::new(GLOBAL);
        for _ in 0..4096 {
            output = SimpleQueryPacket::transaction(TxCommand::Begin, 4096)
                .unwrap()
                .encode_into(output)
                .unwrap();
            std::hint::black_box(&output);
            output = SimpleQueryPacket::simple("SELECT 1", 4096)
                .unwrap()
                .encode_into(output)
                .unwrap();
            std::hint::black_box(&output);
            output = SimpleQueryPacket::transaction(TxCommand::Commit { chain: false }, 4096)
                .unwrap()
                .encode_into(output)
                .unwrap();
            std::hint::black_box(&output);
        }
        let reused = region.change();
        assert_eq!(reused.allocations, 0);
        assert_eq!(reused.reallocations, 0);
        assert_eq!(output.as_ptr(), pointer);
        assert_eq!(output, b"Q\0\0\0\x0bCOMMIT\0");
        drop(output);
        let region = stats_alloc::Region::new(GLOBAL);
        for _ in 0..4096 {
            std::hint::black_box(transaction(TxCommand::Begin, 4096).unwrap());
            std::hint::black_box(simple_query("SELECT 1", 4096).unwrap());
            std::hint::black_box(transaction(TxCommand::Commit { chain: false }, 4096).unwrap());
        }
        let fresh = region.change();
        assert_eq!(fresh.allocations, 4096 * 3);
        assert_eq!(fresh.reallocations, 0);
    }

    #[test]
    fn simple_packets_keep_wire_bytes_and_bound_completed_backing() {
        use super::SimpleQueryPacket;
        let mut output = Vec::with_capacity(4096);
        output.extend_from_slice(b"retired packet");
        let pointer = output.as_ptr();
        let output = SimpleQueryPacket::transaction(TxCommand::Savepoint("a\"b;COMMIT"), 4096)
            .unwrap()
            .encode_into(output)
            .unwrap();
        assert_eq!(output.as_ptr(), pointer);
        assert_eq!(output, b"Q\0\0\0\x1cSAVEPOINT \"a\"\"b;COMMIT\"\0");
        let packet = SimpleQueryPacket::simple("SELECT 1", 64).unwrap();
        let output = packet.encode_into(output).unwrap();
        assert_eq!(output, b"Q\0\0\0\x0dSELECT 1\0");
        assert!(output.capacity() <= 64);
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    #[ignore = "分配诊断须单独运行，以隔离进程级计数"]
    fn finite_pipeline_reuses_tx_without_allocating_execution_descriptors() {
        use crate::types::{Oid, Parameter};

        let parameters = [Parameter::int4(7), Parameter::null(Oid::TEXT, Format::Text)];
        let formats = [Format::Binary, Format::Text];
        let statement = c"s".into();
        let bind_size =
            super::BindSize::unnamed(statement, parameters.len(), formats.len()).unwrap();
        // 独立构造协议字节，覆盖混合格式、NULL、二进制 int4 及各自的 Sync。
        let cycle = b"B\0\0\0\x21\0s\0\0\x02\0\x01\0\0\0\x02\
                      \0\0\0\x04\0\0\0\x07\xff\xff\xff\xff\0\x02\0\x01\0\0\
                      E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04";
        let count = 64;
        let expected = cycle.repeat(count);
        let mut output = Vec::with_capacity(4096);
        output.extend_from_slice(b"retired packet");
        output.clear();
        let pointer = output.as_ptr();
        let region = stats_alloc::Region::new(GLOBAL);
        for _ in 0..count {
            let checked = super::StatementParameters::new(
                &parameters,
                &[Oid::INT4, Oid::TEXT],
                statement,
                &formats,
                bind_size,
                "test OID",
            )
            .unwrap();
            let execution =
                PreparedExecution::checked(&checked, QueryTail::Sync, 4096, "test OID", || Ok(()))
                    .unwrap();
            execution.append_to(&mut output, 4096).unwrap();
        }
        let stats = region.change();
        assert_eq!(stats.allocations, 0);
        assert_eq!(stats.reallocations, 0);
        assert_eq!(output.as_ptr(), pointer);
        assert_eq!(output, expected);
    }

    #[test]
    fn window_packet_grows_geometrically_within_its_limit_and_reuses_storage() {
        let execution =
            PreparedExecution::untyped(c"s".into(), &[], &[], false, QueryTail::Sync, 1024)
                .unwrap();
        let count = 129;
        let maximum = execution.encoded_len() * count + 7;
        let executions: Vec<_> = (0..count)
            .map(|_| {
                PreparedExecution::untyped(c"s".into(), &[], &[], false, QueryTail::Sync, maximum)
                    .unwrap()
            })
            .collect();
        let expected = super::execute_prepared_pipeline(&executions, maximum).unwrap();
        let mut output = Vec::new();
        let mut growths = 0;
        for _ in 0..count {
            let previous = output.capacity();
            execution.append_to(&mut output, maximum).unwrap();
            growths += usize::from(output.capacity() != previous);
            assert!(output.capacity() <= maximum);
        }
        assert_eq!(output, expected);
        assert!(
            growths <= 9,
            "unexpected allocation growth count: {growths}"
        );
        assert_eq!(output.capacity(), maximum);

        let pointer = output.as_ptr();
        let capacity = output.capacity();
        output.clear();
        for _ in 0..count {
            execution.append_to(&mut output, maximum).unwrap();
            assert_eq!(output.as_ptr(), pointer);
            assert_eq!(output.capacity(), capacity);
        }
        assert_eq!(output, expected);
        assert!(matches!(
            execution.append_to(&mut output, maximum),
            Err(Error::Limit(_))
        ));
        assert_eq!(output, expected);
        assert_eq!(output.capacity(), capacity);
    }

    #[test]
    fn window_packet_replaces_only_empty_backing_above_its_limit() {
        let execution =
            PreparedExecution::untyped(c"s".into(), &[], &[], false, QueryTail::Sync, 1024)
                .unwrap();
        let maximum = execution.encoded_len();
        let mut empty = Vec::with_capacity(maximum + 1);
        execution.append_to(&mut empty, maximum).unwrap();
        assert_eq!(empty.len(), maximum);
        assert!(empty.capacity() <= maximum);

        let mut occupied = Vec::with_capacity(maximum + 2);
        occupied.push(b'!');
        let pointer = occupied.as_ptr();
        let capacity = occupied.capacity();
        assert!(matches!(
            execution.append_to(&mut occupied, maximum + 1),
            Err(Error::Limit(_))
        ));
        assert_eq!(occupied, b"!");
        assert_eq!(occupied.as_ptr(), pointer);
        assert_eq!(occupied.capacity(), capacity);
    }

    #[test]
    fn direct_parameter_encoding_preserves_wire_bytes_and_reuses_only_bounded_storage() {
        use crate::types::{Oid, Parameter};
        let parameters = [
            Parameter::int4(42),
            Parameter::text(Oid::TEXT, ""),
            Parameter::null(Oid::INT4, Format::Binary),
        ];
        let expected = b"B\0\0\0\x25\0s\0\0\x03\0\x01\0\0\0\x01\0\x03\0\0\0\x04\0\0\0\x2a\0\0\0\0\xff\xff\xff\xff\0\x01\0\x01E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04";
        let mut storage = Vec::with_capacity(512);
        storage.extend_from_slice(b"old packet");
        let pointer = storage.as_ptr();
        let packet = PreparedExecution::untyped(
            c"s".into(),
            &parameters,
            &[Format::Binary],
            false,
            QueryTail::Sync,
            65536,
        )
        .unwrap()
        .encode_into(storage, 65536)
        .unwrap();
        assert_eq!(packet, expected);
        assert_eq!(packet.as_ptr(), pointer);
        assert_eq!(packet.capacity(), 512);
        let bounded = PreparedExecution::untyped(
            c"s".into(),
            &parameters,
            &[Format::Binary],
            false,
            QueryTail::Sync,
            expected.len(),
        )
        .unwrap()
        .encode_into(packet, expected.len())
        .unwrap();
        assert_eq!(bounded, expected);
        assert!(bounded.capacity() <= expected.len());
    }

    #[test]
    fn prepared_bind_keeps_fixed_mixed_raw_and_null_fields_and_its_exact_budget() {
        use crate::types::Uuid;

        let parameters = [
            Parameter::int2(-2),
            Parameter::int8(42),
            Parameter::uuid(Uuid([0xab; 16])),
            Parameter::binary(Oid::INT4, b"raw"),
            Parameter::null(Oid::TEXT, Format::Text),
        ];
        let oids = [Oid::INT2, Oid::INT8, Oid::UUID, Oid::INT4, Oid::TEXT];
        let formats = [Format::Text, Format::Binary];
        let name = c"s".into();
        let size = super::BindSize::unnamed(name, oids.len(), formats.len()).unwrap();
        let mut checked =
            super::StatementParameters::new(&parameters, &oids, name, &formats, size, "count")
                .unwrap();
        let mut expected = b"B\0\0\0\x4c\0s\0\0\x05\0\x01\0\x01\0\x01\0\x01\0\0\0\x05".to_vec();
        expected.extend_from_slice(b"\0\0\0\x02\xff\xfe\0\0\0\x08\0\0\0\0\0\0\0\x2a\0\0\0\x10");
        expected.extend_from_slice(&[0xab; 16]);
        expected.extend_from_slice(
            b"\0\0\0\x03raw\xff\xff\xff\xff\0\x02\0\0\0\x01E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04",
        );
        let execution = PreparedExecution::checked(
            &checked,
            QueryTail::Sync,
            expected.len(),
            "type",
            || Ok(()),
        )
        .unwrap();
        assert_eq!(execution.encoded_len(), expected.len());
        #[cfg(feature = "diagnostics")]
        let before = crate::diagnostics::snapshot();
        assert_eq!(
            execution.encode_into(Vec::new(), expected.len()).unwrap(),
            expected
        );
        #[cfg(feature = "diagnostics")]
        assert_eq!(
            crate::diagnostics::snapshot()
                .delta(before)
                .unwrap()
                .frontend_parameter_bytes_copied,
            29
        );
        let reused =
            PreparedExecution::reuse_window(name, &parameters, &formats, execution.window_layout());
        assert_eq!(reused.encoded_len(), expected.len());
        assert_eq!(
            reused.encode_into(Vec::new(), expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            PreparedExecution::checked(
                &checked,
                QueryTail::Sync,
                expected.len() - 1,
                "type",
                || Ok(())
            ),
            Err(Error::Limit(_))
        ));
        checked.use_default_result_formats();
        let copy_bind = PreparedExecution::checked(
            &checked,
            QueryTail::Sync,
            expected.len(),
            "type",
            || Ok(()),
        )
        .unwrap();
        assert_eq!(copy_bind.encoded_len() + 4, expected.len());
        assert_eq!(
            copy_bind.encode_into(Vec::new(), expected.len()).unwrap(),
            execute(
                c"s",
                &parameters,
                &[],
                false,
                QueryTail::Sync,
                expected.len()
            )
            .unwrap()
        );
    }

    #[test]
    fn measured_bind_reports_packet_capacity_before_wire_length_or_arithmetic_overflow() {
        let size = super::BindSize::unnamed(c"s".into(), 1, 0).unwrap();
        assert_eq!(size_of::<super::BindSize>(), 8);
        let minimum = size.minimum_packet_bytes().unwrap();
        let overflow = super::ParameterShape {
            payload_bytes: usize::MAX,
            uniform_format: Some(Format::Text),
        };
        assert!(matches!(
            size.plan(overflow, minimum - 1),
            Err(Error::Limit(
                "the encoded request exceeds its configured limit"
            ))
        ));
        assert!(matches!(
            size.plan(overflow, usize::MAX),
            Err(Error::Limit("Bind message length overflow"))
        ));

        let bound = usize::try_from(i32::MAX).unwrap() + 1;
        let exact = super::ParameterShape {
            payload_bytes: bound - minimum,
            uniform_format: Some(Format::Text),
        };
        let above = super::ParameterShape {
            payload_bytes: exact.payload_bytes + 1,
            ..exact
        };
        assert!(
            matches!(size.plan(exact, bound), Ok((layout, bytes)) if layout.length == i32::MAX && bytes == bound)
        );
        assert!(matches!(
            size.plan(above, bound),
            Err(Error::Limit(
                "the encoded request exceeds its configured limit"
            ))
        ));
        assert!(matches!(
            size.plan(above, bound + 1),
            Err(Error::Limit("Bind message exceeds its wire length limit"))
        ));
    }

    use super::{
        PreparedExecution, close, copy_data, copy_end, execute_prepared_pipeline, message_length,
        one_shot, simple_query, sync, terminate, transaction,
    };
    use crate::{
        Error,
        protocol::{Format, QueryTail, TxCommand},
        types::{Oid, Parameter},
    };

    fn prepare(
        statement: &std::ffi::CStr,
        sql: &str,
        oids: &[Oid],
        max_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        super::append_prepare(&mut output, statement.into(), sql, oids, max_bytes)?;
        Ok(output)
    }

    fn execute(
        statement: &std::ffi::CStr,
        parameters: &[Parameter<'_>],
        formats: &[Format],
        describe: bool,
        tail: QueryTail,
        max_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        PreparedExecution::untyped(
            statement.into(),
            parameters,
            formats,
            describe,
            tail,
            max_bytes,
        )?
        .encode_into(Vec::new(), max_bytes)
    }

    fn encode_scalar(statement: &std::ffi::CStr, value: Option<i32>) -> Result<Vec<u8>, Error> {
        let bytes = value.map(i32::to_be_bytes);
        execute(
            statement,
            &[Parameter::raw(
                Oid::INT4,
                Format::Binary,
                bytes.as_ref().map(|value| value.as_slice()),
            )],
            &[Format::Binary],
            false,
            QueryTail::Sync,
            usize::MAX,
        )
    }

    fn encode_batch(
        statement: &std::ffi::CStr,
        values: &[Option<i32>],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut packet = Vec::new();
        let formats = [Format::Binary];
        for value in values {
            let parameters = [value.map_or(
                crate::types::Parameter::null(crate::types::Oid::INT4, Format::Binary),
                crate::types::Parameter::int4,
            )];
            let execution = PreparedExecution::untyped(
                statement.into(),
                &parameters,
                &formats,
                false,
                QueryTail::Sync,
                maximum,
            )?;
            execution.append_to(&mut packet, maximum)?;
        }
        Ok(packet)
    }

    #[test]
    fn prepare_encodes_parse_describe_and_sync() {
        let output =
            prepare(c"s", "SELECT $1::int4", &[Oid::INT4], usize::MAX).expect("valid prepare");
        let expected = b"P\0\0\0\x1cs\0SELECT $1::int4\0\0\x01\0\0\0\x17\
                         D\0\0\0\x07Ss\0\
                         S\0\0\0\x04";
        assert_eq!(output, expected);
    }

    #[test]
    fn execute_encodes_binary_int4_and_unlimited_portal() {
        let output = encode_scalar(c"s", Some(42)).expect("valid execute");
        let expected = b"B\0\0\0\x19\0s\0\0\x01\0\x01\0\x01\0\0\0\x04\0\0\0\x2a\0\x01\0\x01\
                         E\0\0\0\x09\0\0\0\0\0\
                         S\0\0\0\x04";
        assert_eq!(output, expected);
    }

    #[test]
    fn execute_encodes_null_without_a_value_body() {
        let output = encode_scalar(c"s", None).expect("valid null execute");
        let expected = b"B\0\0\0\x15\0s\0\0\x01\0\x01\0\x01\xff\xff\xff\xff\0\x01\0\x01\
                         E\0\0\0\x09\0\0\0\0\0\
                         S\0\0\0\x04";
        assert_eq!(output, expected);
    }

    #[test]
    fn execute_preserves_signed_int4_boundaries() {
        let minimum = encode_scalar(c"s", Some(i32::MIN)).expect("valid minimum");
        let maximum = encode_scalar(c"s", Some(i32::MAX)).expect("valid maximum");
        assert_eq!(&minimum[18..22], &[0x80, 0, 0, 0]);
        assert_eq!(&maximum[18..22], &[0x7f, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn batch_matches_independent_cycles_for_mixed_values() {
        let values = [Some(i32::MIN), None, Some(0), Some(i32::MAX)];
        let mut expected = Vec::new();
        for value in values {
            expected.extend(encode_scalar(c"é", value).expect("valid independent cycle"));
        }
        let output = encode_batch(c"é", &values, expected.len()).expect("valid batch");
        assert_eq!(output, expected);
    }

    #[test]
    fn batch_accepts_exact_limit_and_rejects_one_byte_less() {
        let values = [None, Some(42), None];
        // 语句名为 s 时，包含 Execute 和 Sync 的 NULL 请求占 37 字节，int4 请求占 41 字节。
        let output = encode_batch(c"s", &values, 115).expect("exact batch limit");
        assert_eq!(output.len(), 115);
        assert!(matches!(
            encode_batch(c"s", &values, 114),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn empty_batch_encodes_no_messages() {
        let output = encode_batch(c"s", &[], 0).expect("empty batch");
        assert!(output.is_empty());
        assert_eq!(output.capacity(), 0);
    }

    #[test]
    fn close_encodes_statement_target_and_sync_in_the_retired_backing() {
        let mut output = Vec::with_capacity(64);
        let backing = output.as_ptr();
        super::append_close_sync(&mut output, c"s".into(), 64).expect("valid close");
        assert_eq!(output.as_ptr(), backing);
        assert_eq!(output, b"C\0\0\0\x07Ss\0S\0\0\0\x04");
    }

    #[test]
    fn string_lengths_count_utf8_bytes() {
        let output = close(c"é").expect("valid UTF-8 statement name");
        assert_eq!(output, b"C\0\0\0\x08S\xc3\xa9\0S\0\0\0\x04");
    }

    #[test]
    fn prepare_rejects_embedded_nul_in_sql() {
        assert!(matches!(
            prepare(c"s", "SELECT\0$1", &[Oid::INT4], usize::MAX),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn generated_wire_names_are_decimal_and_have_a_single_terminator() {
        for (id, text) in [
            (0, c":p0"),
            (9, c":p9"),
            (10, c":p10"),
            (u64::MAX, c":p18446744073709551615"),
        ] {
            let name = super::StatementName::numbered(id).unwrap();
            assert_eq!(name.wire().bytes_with_nul(), text.to_bytes_with_nul());
        }
        assert_eq!(
            super::StatementName::UNNAMED.wire().bytes_with_nul(),
            c"".to_bytes_with_nul()
        );
    }

    #[test]
    fn general_encoders_accept_the_unnamed_prepared_slot() {
        let expected = b"P\0\0\0\x10\0SELECT 1\0\0\0D\0\0\0\x06S\0S\0\0\0\x04";
        assert_eq!(
            prepare(c"", "SELECT 1", &[], expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            prepare(c"", "SELECT 1", &[], expected.len() - 1),
            Err(Error::Limit(_))
        ));
        assert_eq!(close(c"").unwrap(), b"C\0\0\0\x06S\0S\0\0\0\x04");
        let plan =
            super::PreparedExecution::untyped(c"".into(), &[], &[], false, QueryTail::Open, 128)
                .unwrap();
        let mut packet = Vec::new();
        plan.append_to(&mut packet, 128).unwrap();
        assert_eq!(packet, b"B\0\0\0\x0c\0\0\0\0\0\0\0\0E\0\0\0\x09\0\0\0\0\0");
    }

    #[test]
    fn message_length_checks_wire_and_arithmetic_limits() {
        let maximum = usize::try_from(i32::MAX).expect("i32 wire limit fits usize");
        assert_eq!(
            message_length(&[maximum - 4]).expect("largest wire length"),
            i32::MAX
        );
        assert!(matches!(
            message_length(&[maximum - 3]),
            Err(Error::Limit(_))
        ));
        assert!(matches!(
            message_length(&[usize::MAX]),
            Err(Error::Limit(_))
        ));
        assert!(matches!(
            message_length(&[1, usize::MAX]),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn prepare_encodes_multiple_parameter_oids() {
        let expected = b"P\0\0\0\x1ds\0SELECT $1,$2\0\0\x02\0\0\0\x17\0\0\0\x19\
                         D\0\0\0\x07Ss\0S\0\0\0\x04";
        assert_eq!(
            prepare(
                c"s",
                "SELECT $1,$2",
                &[Oid::INT4, Oid::TEXT],
                expected.len()
            )
            .expect("prepare"),
            expected
        );
        assert!(matches!(
            prepare(
                c"s",
                "SELECT $1,$2",
                &[Oid::INT4, Oid::TEXT],
                expected.len() - 1
            ),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn typed_prepare_append_preserves_wire_bytes_and_failed_prefix() {
        let expected = b"P\0\0\0\x1ds\0SELECT $1,$2\0\0\x02\0\0\0\x17\0\0\0\x19\
                         D\0\0\0\x07Ss\0S\0\0\0\x04";
        let mut packet = Vec::new();
        super::append_prepare(
            &mut packet,
            c"s".into(),
            "SELECT $1,$2",
            &[crate::types::Oid::INT4, crate::types::Oid::TEXT],
            expected.len(),
        )
        .unwrap();
        assert_eq!(packet, expected);
        assert!(matches!(
            super::append_prepare(
                &mut packet,
                c"s".into(),
                "SELECT $1,$2",
                &[crate::types::Oid::INT4, crate::types::Oid::TEXT],
                expected.len() * 2 - 1
            ),
            Err(Error::Limit(_))
        ));
        assert_eq!(packet, expected);
        assert!(matches!(
            super::append_prepare(&mut packet, c"s".into(), "bad\0SQL", &[], 4096),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(packet, expected);
    }

    #[test]
    fn bind_encodes_mixed_parameter_and_result_formats() {
        let parameters = [
            Parameter::raw(Oid::INT4, Format::Text, Some(b"hi")),
            Parameter::raw(Oid::INT4, Format::Binary, Some(b"\0\x01")),
        ];
        let expected = b"B\0\0\0\x21\0s\0\0\x02\0\0\0\x01\0\x02\
                         \0\0\0\x02hi\0\0\0\x02\0\x01\0\x02\0\x01\0\0\
                         E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04";
        assert_eq!(
            execute(
                c"s",
                &parameters,
                &[Format::Binary, Format::Text],
                false,
                QueryTail::Sync,
                expected.len()
            )
            .expect("mixed Bind"),
            expected
        );
        assert!(matches!(
            execute(
                c"s",
                &parameters,
                &[Format::Binary, Format::Text],
                false,
                QueryTail::Sync,
                expected.len() - 1
            ),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn bind_compresses_uniform_formats_and_keeps_null_distinct_from_empty() {
        let text = [
            Parameter::raw(Oid::INT4, Format::Text, None),
            Parameter::raw(Oid::INT4, Format::Text, Some(b"")),
        ];
        let expected_text = b"B\0\0\0\x15\0s\0\0\0\0\x02\xff\xff\xff\xff\0\0\0\0\0\0\
                              E\0\0\0\x09\0\0\0\0\0";
        assert_eq!(
            execute(
                c"s",
                &text,
                &[],
                false,
                QueryTail::Open,
                expected_text.len()
            )
            .expect("all text"),
            expected_text
        );
        let binary = [
            Parameter::raw(Oid::INT4, Format::Binary, None),
            Parameter::raw(Oid::INT4, Format::Binary, Some(b"\0\0\0\x2a")),
        ];
        let expected_binary = b"B\0\0\0\x1d\0s\0\0\x01\0\x01\0\x02\xff\xff\xff\xff\
                                \0\0\0\x04\0\0\0\x2a\0\x01\0\x01\
                                E\0\0\0\x09\0\0\0\0\0H\0\0\0\x04";
        assert_eq!(
            execute(
                c"s",
                &binary,
                &[Format::Binary],
                false,
                QueryTail::Flush,
                expected_binary.len()
            )
            .expect("all binary"),
            expected_binary
        );
    }

    #[test]
    fn late_mixed_parameter_format_is_charged_before_packet_admission() {
        let parameters = [
            Parameter::raw(Oid::INT4, Format::Text, None),
            Parameter::raw(Oid::INT4, Format::Text, None),
            Parameter::raw(Oid::INT4, Format::Binary, None),
        ];
        let expected = b"B\0\0\0\x1f\0s\0\0\x03\0\0\0\0\0\x01\0\x03\
                         \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0\
                         E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04";
        assert_eq!(
            execute(
                c"s",
                &parameters,
                &[],
                false,
                QueryTail::Sync,
                expected.len(),
            )
            .expect("late mixed formats fit their exact wire bound"),
            expected,
        );
        // 混合 Bind 需要三个显式格式码，只有 NULL 长度字段能放下时必须在追加前拒绝。
        let mut packet = Vec::from(b"private prefix".as_slice());
        let result =
            PreparedExecution::untyped(c"s".into(), &parameters, &[], false, QueryTail::Sync, 31)
                .and_then(|execution| execution.append_to(&mut packet, 128));
        assert!(matches!(result, Err(Error::Limit(_))));
        assert_eq!(packet, b"private prefix");
        assert!(matches!(
            execute(
                c"s",
                &parameters,
                &[],
                false,
                QueryTail::Sync,
                expected.len() - 1,
            ),
            Err(Error::Limit(_)),
        ));
    }

    #[test]
    fn one_shot_describes_the_bound_portal_in_the_same_batch() {
        let expected = b"P\0\0\0\x10\0SELECT 1\0\0\0\
                         B\0\0\0\x0c\0\0\0\0\0\0\0\0\
                         D\0\0\0\x06P\0E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04";
        assert_eq!(
            one_shot(
                || Ok(Vec::new()),
                "SELECT 1",
                &[],
                &[],
                true,
                QueryTail::Sync,
                expected.len()
            )
            .expect("one shot"),
            expected
        );
        assert!(matches!(
            one_shot(
                || Ok(Vec::new()),
                "SELECT 1",
                &[],
                &[],
                true,
                QueryTail::Sync,
                expected.len() - 1
            ),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn simple_query_encodes_text_without_claiming_it_is_one_statement() {
        assert_eq!(simple_query("", 6).expect("empty Q"), b"Q\0\0\0\x05\0");
        let expected = b"Q\0\0\0\x17SELECT 1; SELECT 2\0";
        assert_eq!(
            simple_query("SELECT 1; SELECT 2", expected.len()).expect("Q text"),
            expected
        );
        assert!(matches!(
            simple_query("SELECT\0 1", 128),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn transaction_commands_quote_savepoint_identifiers() {
        assert_eq!(
            transaction(TxCommand::Begin, 11).expect("BEGIN"),
            b"Q\0\0\0\x0aBEGIN\0"
        );
        assert_eq!(
            transaction(TxCommand::Commit { chain: true }, 22).expect("COMMIT AND CHAIN"),
            b"Q\0\0\0\x15COMMIT AND CHAIN\0"
        );
        assert_eq!(
            transaction(TxCommand::Rollback { chain: false }, 14).expect("ROLLBACK"),
            b"Q\0\0\0\x0dROLLBACK\0"
        );
        let quoted = b"Q\0\0\0\x1cSAVEPOINT \"a\"\"b;COMMIT\"\0";
        assert_eq!(
            transaction(TxCommand::Savepoint("a\"b;COMMIT"), quoted.len())
                .expect("quoted identifier"),
            quoted
        );
        assert!(matches!(
            transaction(TxCommand::Savepoint("a\"b;COMMIT"), quoted.len() - 1),
            Err(Error::Limit(_))
        ));
        assert_eq!(
            transaction(TxCommand::ReleaseSavepoint("s"), 27).expect("RELEASE"),
            b"Q\0\0\0\x1aRELEASE SAVEPOINT \"s\"\0"
        );
        assert_eq!(
            transaction(TxCommand::RollbackToSavepoint("s"), 31).expect("ROLLBACK TO"),
            b"Q\0\0\0\x1eROLLBACK TO SAVEPOINT \"s\"\0"
        );
        assert!(matches!(
            transaction(TxCommand::Savepoint("s\0x"), 128),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            transaction(TxCommand::Savepoint(""), 128),
            Err(Error::InvalidInput(_))
        ));
        let longest = "é".repeat(31) + "x";
        let too_long = longest.clone() + "x";
        assert!(transaction(TxCommand::Savepoint(&longest), 128).is_ok());
        assert!(matches!(
            transaction(TxCommand::Savepoint(&too_long), 128),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn copy_controls_preserve_opaque_data_and_never_add_an_implicit_sync() {
        assert_eq!(
            copy_data(b"\0\xff\x80", 8).expect("opaque COPY bytes"),
            b"d\0\0\0\x07\0\xff\x80"
        );
        assert_eq!(copy_data(&[], 5).expect("empty COPY bytes"), b"d\0\0\0\x04");
        assert!(matches!(copy_data(b"\0\xff\x80", 7), Err(Error::Limit(_))));
        assert_eq!(
            copy_end(None, QueryTail::Open, 5).expect("CopyDone"),
            b"c\0\0\0\x04"
        );
        assert_eq!(
            copy_end(Some("stop"), QueryTail::Open, 10).expect("CopyFail"),
            b"f\0\0\0\x09stop\0"
        );
        let packet = vec![0; 128];
        let storage = packet.as_ptr();
        let packet = sync(packet, 128).expect("Sync");
        assert_eq!(packet, b"S\0\0\0\x04");
        assert_eq!(packet.as_ptr(), storage);
        let packet = terminate(packet, 5).expect("Terminate");
        assert_eq!(packet, b"X\0\0\0\x04");
        assert_eq!(packet.capacity(), 5);
        assert!(matches!(sync(packet, 4), Err(Error::Limit(_))));
        assert!(matches!(
            copy_end(None, QueryTail::Open, 4),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn copy_end_checks_the_complete_packet_before_encoding() {
        assert_eq!(
            copy_end(None, QueryTail::Sync, 10).expect("done and Sync"),
            b"c\0\0\0\x04S\0\0\0\x04"
        );
        assert!(matches!(
            copy_end(None, QueryTail::Sync, 9),
            Err(Error::Limit(_))
        ));
        assert_eq!(
            copy_end(Some("stop"), QueryTail::Sync, 15).expect("fail and Sync"),
            b"f\0\0\0\x09stop\0S\0\0\0\x04"
        );
        assert!(matches!(
            copy_end(Some("stop"), QueryTail::Sync, 14),
            Err(Error::Limit(_))
        ));
        assert!(matches!(
            copy_end(Some("s\0x"), QueryTail::Sync, 128),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(
            copy_end(None, QueryTail::Flush, 10).expect("explicit Flush"),
            b"c\0\0\0\x04H\0\0\0\x04"
        );
    }

    #[test]
    fn parameter_count_over_the_wire_limit_is_rejected() {
        let parameters =
            vec![Parameter::raw(Oid::INT4, Format::Text, None); usize::from(u16::MAX) + 1];
        assert!(matches!(
            execute(c"s", &parameters, &[], false, QueryTail::Sync, usize::MAX),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn explicit_result_format_count_is_not_compressed_away() {
        let expected = b"B\0\0\0\x11\0s\0\0\0\0\0\0\x02\0\x01\0\x01\
                         E\0\0\0\x09\0\0\0\0\0";
        assert_eq!(
            execute(
                c"s",
                &[],
                &[Format::Binary, Format::Binary],
                false,
                QueryTail::Open,
                expected.len()
            )
            .expect("explicit two-column formats"),
            expected,
        );
    }

    #[test]
    fn transaction_end_variants_preserve_chain_selection() {
        assert_eq!(
            transaction(TxCommand::Commit { chain: false }, 12).expect("COMMIT"),
            b"Q\0\0\0\x0bCOMMIT\0"
        );
        assert_eq!(
            transaction(TxCommand::Rollback { chain: true }, 24).expect("ROLLBACK AND CHAIN"),
            b"Q\0\0\0\x17ROLLBACK AND CHAIN\0"
        );
        assert_eq!(
            transaction(TxCommand::Savepoint("é"), 20).expect("UTF-8 savepoint"),
            b"Q\0\0\0\x13SAVEPOINT \"\xc3\xa9\"\0"
        );
    }

    #[test]
    fn prepared_pipeline_preserves_names_formats_nulls_and_each_sync() {
        let parameters = [
            Parameter::raw(Oid::INT4, Format::Text, Some(b"7")),
            Parameter::raw(Oid::INT4, Format::Binary, None),
        ];
        let executions = [
            PreparedExecution::untyped(c"s".into(), &[], &[], false, QueryTail::Sync, 128).unwrap(),
            PreparedExecution::untyped(
                c"t".into(),
                &parameters,
                &[Format::Binary],
                false,
                QueryTail::Sync,
                128,
            )
            .unwrap(),
        ];
        // 预期的两段 Bind 分别覆盖零参数和混合格式参数，后者包含单字节文本、NULL 与二进制结果。
        let expected = b"B\0\0\0\x0d\0s\0\0\0\0\0\0\0\
                         E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04\
                         B\0\0\0\x1c\0t\0\0\x02\0\0\0\x01\0\x02\0\0\0\x017\xff\xff\xff\xff\0\x01\0\x01\
                         E\0\0\0\x09\0\0\0\0\0S\0\0\0\x04";
        assert_eq!(
            execute_prepared_pipeline(&executions, expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            execute_prepared_pipeline(&executions, expected.len() - 1),
            Err(Error::Limit(_))
        ));
        assert!(execute_prepared_pipeline(&[], 0).unwrap().is_empty());
    }
}
