# compio-postgres

为 Compio 服务连接 PostgreSQL 19，使用前后端协议 3.2。
应用服务和数据库 I/O 在同一 Compio worker 上运行。
短查询直接使用连接或租借 worker 上的热连接。
本地连接池、流水线和有界派发器可按负载组合使用。

## 接入

需要 Rust 1.100。将依赖加入应用的 `Cargo.toml`。

```toml
[dependencies]
compio-postgres = "0.1"
compio = { version = "0.19.2", default-features = false, features = ["net"] }
```

TCP、事务、COPY 与批处理使用统一的跨平台接口。
连接、查询结果和错误类型位于 crate 根，PostgreSQL 参数和编解码类型位于 `types`。
原生传输沿用所属 Compio runtime 的驱动，默认在 Linux 使用 io_uring，在 Windows 使用 IOCP，在 macOS 使用 polling。
TLS 默认编译启用。通过 `TcpConfig::tls` 指定服务端名称和可信 CA。
双向 TLS 还需客户端证书链和私钥。
明文 TCP 使用 `TcpConfig::plaintext`，Unix socket 使用 `UnixConfig::plaintext` 和绝对文件路径。

使用 `WireLimits::short_queries()` 和 `ClientOptions::short_queries()` 时，常见的短响应可在一次发送和一次接收中处理。
单行结果可在接收区直接解码。持有行或整批结果需明确选择保留空间。
派发器用于有意共享连接和排队的工作，直接查询与池的直接租借无需派发任务。

应用负责解析域名、选择地址和故障转移，可在建连时调用 Compio 的 `ToSocketAddrsAsync`。
TCP 配置接收选定的 `SocketAddr`，TLS 使用配置的服务端名称校验证书。
取消请求沿用原连接的地址和安全配置。

## 普通用法

应用启动时由可信 CA、证书验证用的服务器名、选定的地址和登录参数构造一次 `ClientOptions`。
在处理请求的 worker 上建立连接，并为每条连接准备语句。
池预热可克隆配置以复用信任根。
下面的标量查询在收到恰好一行、服务端确认 Ready、本地发送完成后返回值。

```rust
use compio_postgres::{
    AuthenticationPolicy, ClientOptions, Error, OnError, PreparedStatementStorage, ResultFormats,
    SecureConfig, Statement, TcpConfig, TcpNoDelay, TcpOptions, TlsConfig, TlsConnection,
    TlsNegotiation, TlsOptions, TlsResumption, TlsVersions, WireLimits,
    types::{Format, Oid, Parameter},
};
use std::{net::SocketAddr, num::NonZeroUsize};

fn connection_options(
    address: SocketAddr, server_name: &str, ca_pem: &[u8],
    user: &str, database: &str, password: String,
) -> Result<ClientOptions<SecureConfig>, Error> {
    let tls = TlsConfig::from_ca_pem(server_name, ca_pem, TlsOptions {
        negotiation: TlsNegotiation::Direct,
        versions: TlsVersions::Tls13,
        resumption: TlsResumption::Disabled,
        send_buffer_limit: NonZeroUsize::new(64 * 1024),
    })?;
    let config = TcpConfig::tls(
        address, user, database,
        AuthenticationPolicy::ScramSha256 { password, max_iterations: 100_000 },
        WireLimits::short_queries(), tls, TcpOptions::new(TcpNoDelay::Enabled),
    );
    Ok(ClientOptions::short_queries(config))
}

async fn connect(options: ClientOptions<SecureConfig>) -> Result<(TlsConnection, Statement), Error> {
    let mut client = TlsConnection::connect(options).await?;
    let statement = client.prepare(
        "SELECT $1::int4",
        &[Oid::INT4],
        PreparedStatementStorage::Named,
        ResultFormats::All(Format::Binary),
    ).await?;
    Ok((client, statement))
}

async fn query_value(
    client: &mut TlsConnection, statement: &Statement, value: i32,
) -> Result<i32, Error> {
    client.query(statement, &[Parameter::int4(value)])
        .one::<i32>(OnError::RecoverExplicitly).await
}
```

允许零行时使用 `zero_or_one`，执行零列命令使用 `command_ready`。
映射多列使用 `map_provisional_one` 或 `map_provisional_zero_or_one`。
映射回调在 Ready 前借用行，返回给调用方的结果须等待 Ready 和本地发送完成。
临时 SQL 可用 `one_shot` 在一个往返内执行。
它会替换未命名语句，发现结果布局错误时 SQL 可能已经执行。

需要数据库并行执行时，在同一 worker 上使用多条连接。
通过 `streaming_batch` 共享一条连接时，PostgreSQL 顺序执行 SQL，客户端可在等待前项结果时发送后项。
每个批成员有独立的 Sync，`max_inflight` 限制在途请求，`max_requests` 限制整批输入。
提交前已知超额会直接失败，惰性输入超额时应检查错误中的执行进度。
要保留下批输入，传入 `iter.by_ref().take(n)`。
`collect_ready` 收集已确认的成员结果，每项仍需检查 SQL 错误。
选择 `stream_provisional` 或 `visit_provisional` 时，行可以早于最终确认交付。

## 协议和类型范围

| 场景 | 支持范围 |
| --- | --- |
| 认证 | SCRAM-SHA-256、SCRAM-SHA-256-PLUS，或显式信任直接返回 AuthenticationOk 的端点。 |
| 会话 | 参数化查询、命名与未命名语句、事务与保存点、portal、流水线、LISTEN/NOTIFY、使用可变长密钥的取消请求。 |
| 批量传输 | COPY FROM STDIN 和 COPY TO STDOUT。 |
| 编解码 | 布尔、整数、浮点、文本、字节、UUID、日期时间、网络地址、位串、JSON/JSONB、JSONPath、XML、numeric、money、oid8 和 regdatabase。数组、复合类型、range 及 multirange 可按布局借用与编码。 |
| 自定义类型 | `Parameter::raw` 和 `RawValue` 保留 OID、格式和原始值。应用可实现 `Decode`，也可启用 `postgres-types`。在服务预热时从目标库校验并缓存布局，普通查询即可直接解码。预热示例见 [本地 API 文档](docs/testing.md#本地检查) 中的 `types::CompositeLayout`。 |

`types::encode_scaled_numeric` 与 `NumericView::to_scaled_i128` 在指定小数位数下精确转换定点数。
编码结果 `ScaledNumeric` 在值内存放二进制载荷，可重复绑定，无需堆分配。
`NumericView` 可借用 PostgreSQL 的完整精度和非有限值。
`PgMoney` 保留二进制整数，金额的小数位数取决于数据库会话的 `lc_monetary`。
一次处理数组、复合值或多区间时，可用对应视图的 `visit` 在校验时直接观察成员。
回调可能先看到合法前缀，再收到尾部错误；需要先确认完整布局或多次遍历时用 `parse`。
全文检索、几何、扩展类型与应用自定义类型通过原始值或应用编解码处理。

启动包固定请求协议 3.2，收到版本协商响应时结束建连。
服务端须报告 `server_version` 主版本为 19、会话的 `client_encoding` 为 `UTF8`。
本库实现业务 SQL 使用的协议子集。流复制（含双向 CopyBoth）、独立 FunctionCall 消息、OAuth、GSSAPI/SSPI、明文密码和 MD5 认证均在支持范围之外。
SQL 函数可通过普通查询调用。[PostgreSQL 19 前后端协议](https://www.postgresql.org/docs/19/protocol.html)

## 错误、中止与恢复

批次提前结束时，`BatchError::progress` 记录已经接纳、确认和交付的成员数。
`BatchError::origin` 给出失败来源。输入校验与额度错误在执行前后采用同一分类。
`collect_ready` 的错误还通过 `completed` 返还已保留的结果前缀。
使用访问器或写入调用方缓冲区的终端时，错误类型为 `BatchError<()>`。

| 查询的本地失败策略 | 行为 |
| --- | --- |
| `DrainToReady` | 按恢复预算清理已接纳的工作，再交付错误。清理失败时保留原错误和清理错误。 |
| `RecoverExplicitly` | 根据 `reuse_state()` 选择恢复或丢弃连接。在连接或原事务上用 `recover_to_ready()` 排空查询响应，也可以用 `recover_to_ready_with_limits(max_rows, max_bytes)` 指定本次限额。 |
| `Discard` | 发送交接后遇到本地失败会禁止复用。若批次已完成全部接纳项，随后才发现输入超额，连接仍可复用。 |

借用流的放弃行为由 `AbandonPolicy` 指定。
单查询的自动清理使用本次查询的行数和字节限额。
批次只为已交给传输且尚未收到 Ready 的成员计算清理额度，按成员限额求和，并采用适用的窗口总限额。
自动清理另行计数。达到数据额度时保留待恢复进度，应用可以显式指定新的额度继续排空。
数据额度只控制读取量，等待服务端的截止时间由应用管理。
发送完成、取消送达、收到 Ready 和提交事务是独立的边界。
需要清理数据库会话时，显式调用 `reset_session()`。
其执行的 `DISCARD ALL` 会使旧语句句柄失效。

## 可选组件

| Cargo 特性 | 用途 |
| --- | --- |
| `tls`（默认） | TCP 上的 TLS 和客户端证书认证。 |
| `service` | worker 本地连接池、有界 FIFO 和派发器。 |
| `postgres-types` | 使用生态类型转换。 |
| `uuid` | `uuid::Uuid` 可直接解码，使用 `Parameter::from(uuid)` 内联编码。 |
| `time` | `Date`、`Time`、`PlainDateTime`、`OffsetDateTime` 可直接解码，以 `Parameter::try_from(value)` 内联编码。写入须精确到微秒，带时区时间戳读为 UTC。无穷值与 24:00:00 可使用原生 PostgreSQL 类型读取。 |
| `serde_json` | `serde_json::Value` 可直接解码。`types::encode_json` 在指定字节预算内编码 JSON 或 JSONB，返回值可重复绑定。需要保留精确十进制或超大整数时可借用 `JsonText`，也可由应用启用 serde_json 的 `arbitrary_precision`。 |
| `window-cache` | 在指定内存上限内保留批次发送缓冲。 |
| `diagnostics` | 读取本线程的 I/O 尝试、协议帧和库内显式复制计数。 |

## 随包指南

| 内容 | 本地文件 | 在线阅读 |
| --- | --- | --- |
| 协议预算、同步边界和传输调优 | [docs/expert.md](docs/expert.md) | [专家指南](https://docs.rs/crate/compio-postgres/latest/source/docs/expert.md) |
| 连接租借、隔离和派发 | [docs/service.md](docs/service.md) | [服务指南](https://docs.rs/crate/compio-postgres/latest/source/docs/service.md) |
| 运行示例、检查和真库测试 | [docs/testing.md](docs/testing.md) | [验证指南](https://docs.rs/crate/compio-postgres/latest/source/docs/testing.md) |
| 吞吐和尾延迟测量 | [docs/bench.md](docs/bench.md) | [基准指南](https://docs.rs/crate/compio-postgres/latest/source/docs/bench.md) |

[API 参考](https://docs.rs/compio-postgres) · [MIT 许可证](LICENSE)
