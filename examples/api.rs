//! 使用 TLS、明文 TCP 或 Unix 套接字运行预备语句和流水线。连接参数见随包的 `docs/testing.md`。
#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unreachable
)]

mod support;

use compio_postgres::{
    AbandonPolicy, AllocationPolicy, BatchControl, BatchEvent, BatchOptions, Client, ClientOptions,
    Error, OnError, OwnedOutput, PreparedStatementStorage, ResultFormats, TcpConnection,
    WireTransport,
    types::{Format, Oid, Parameter},
};
use std::{env, error};
use support::{Config, Transport};

fn main() -> Result<(), Box<dyn error::Error>> {
    let mut args = env::args_os().skip(1);
    let arg = args.next();
    let name = arg
        .as_ref()
        .map(|arg| arg.to_str().ok_or("传输方式须为有效的 Unicode"))
        .transpose()?;
    let transport = match name {
        None | Some("-h" | "--help") => {
            println!("用法：cargo run --example api -- {}", Transport::CHOICES);
            return Ok(());
        }
        Some(name) => Transport::parse(name)?,
    };
    if args.next().is_some() {
        return Err("请指定一种传输方式".into());
    }
    let runtime = compio::runtime::Runtime::new()?;
    let config = transport.config(&runtime)?;
    runtime.block_on(async {
        match config {
            Config::Tcp(config) => {
                run(TcpConnection::connect(ClientOptions::short_queries(config)).await?).await
            }
            #[cfg(feature = "tls")]
            Config::Tls(config) => {
                run(
                    compio_postgres::TlsConnection::connect(ClientOptions::short_queries(config))
                        .await?,
                )
                .await
            }
            #[cfg(unix)]
            Config::Unix(config) => {
                run(
                    compio_postgres::UnixConnection::connect(ClientOptions::short_queries(config))
                        .await?,
                )
                .await
            }
        }
    })
}

async fn run<T: WireTransport>(mut connection: Client<T>) -> Result<(), Box<dyn error::Error>> {
    let statement = connection
        .prepare(
            "SELECT $1::int4",
            &[Oid::INT4],
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Binary),
        )
        .await?;
    let value = connection
        .query(&statement, &[Parameter::int4(73)])
        .one::<i32>(OnError::RecoverExplicitly)
        .await?;
    println!("已确认的标量结果：{value}");

    let query = connection.execution_options().query;
    let batch = BatchOptions {
        member_limits: query.limits,
        max_inflight: 4,
        max_requests: 16,
        max_queued_request_bytes: 64 * 1024,
        max_diagnostic_bytes: 16 * 1024,
        scheduling: query.scheduling,
    };
    let report = connection
        .streaming_batch((0..16).map(|value| statement.bind_one(Parameter::int4(value))))
        .with_options(batch)
        .collect_ready(
            OwnedOutput {
                max_bytes: 4 * 1024 * 1024,
                allocation: AllocationPolicy::Grow,
            },
            OnError::RecoverExplicitly,
        )
        .await?;
    let count = report.results.len();
    for (expected, result) in (0_i32..).zip(report.results) {
        let result = result?;
        let mut rows = result.rows.rows();
        let row = rows.next().ok_or("批成员未返回结果行")??;
        let mut fields = row.decoder();
        let value = fields.decode_next::<i32>()?;
        fields.finish()?;
        if value != expected || rows.next().is_some() {
            return Err("批成员的结果与输入不符".into());
        }
    }
    println!("已成功完成 {count} 个批成员");

    connection
        .streaming_batch((0..16).map(|value| statement.bind_one(Parameter::int4(value))))
        .with_options(batch)
        .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
            if let BatchEvent::Ready { index, outcome, .. } = event {
                outcome.map_err(|error| Error::Database(error.clone()))?;
                println!("第 {index} 项已确认");
            }
            Ok(BatchControl::Continue)
        })
        .await?;
    connection.terminate().await?;
    Ok(())
}
