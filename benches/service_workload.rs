#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unreachable
)]

use std::{
    cell::Cell,
    env, error,
    future::Future,
    io,
    rc::Rc,
    time::{Duration, Instant, SystemTime},
};

use compio_postgres::{
    AbandonPolicy, BatchControl, BatchEvent, BatchOptions, Client, ClientOptions, DatabaseError,
    Error, OnError, PreparedStatementStorage, ResultFormats, Statement, TcpConnection,
    TransactionEnd, WireTransport,
    types::{Format, Oid, Parameter},
};

#[path = "../examples/support/mod.rs"]
mod support;
use support::{Config, Transport};

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
const ITEMS: i32 = 5_000;
const BATCH_SIZE: u16 = 32;
const ARRIVALS: u32 = 2_000;
const ARRIVAL_INTERVAL: Duration = Duration::from_micros(750);
const BINARY: ResultFormats = ResultFormats::All(Format::Binary);
const RECOVER: OnError = OnError::RecoverExplicitly;

#[derive(Clone, Copy)]
enum Workload {
    Direct,
    #[cfg(feature = "service")]
    Connections,
    #[cfg(feature = "service")]
    Pool,
    #[cfg(feature = "service")]
    Inline,
    #[cfg(feature = "service")]
    Scan,
    #[cfg(feature = "service")]
    Ready,
}

async fn bounded<T>(phase: &str, work: impl Future<Output = T>) -> Result<T> {
    compio::time::timeout(Duration::from_secs(120), work)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{phase} timed out")).into())
}

async fn fixture<T: WireTransport>(
    client: &mut Client<T>,
    schema: &str,
    create: bool,
) -> Result<()> {
    let commands = if create {
        vec![
            format!("CREATE SCHEMA {schema}"),
            format!(
                "CREATE TABLE {schema}.items (id int PRIMARY KEY, title text NOT NULL, flags bool NOT NULL, balance bigint NOT NULL)"
            ),
            format!(
                "INSERT INTO {schema}.items SELECT i, 'item-' || i, i % 2 = 0, i::bigint * 1000 FROM generate_series(1, {ITEMS}) AS s(i)"
            ),
            format!("CREATE TABLE {schema}.writes (id int PRIMARY KEY, n bigint NOT NULL)"),
            format!("INSERT INTO {schema}.writes VALUES (1, 0)"),
            format!("ANALYZE {schema}.items"),
        ]
    } else {
        vec![
            "SET LOCAL lock_timeout = '5s'".to_owned(),
            format!("DROP TABLE {schema}.items, {schema}.writes RESTRICT"),
            format!("DROP SCHEMA {schema} RESTRICT"),
        ]
    };
    let mut tx = client.begin_transaction().await?;
    for sql in commands {
        tx.one_shot(&sql, &[], BINARY)
            .command_ready(RECOVER)
            .await?;
    }
    if tx.commit().await?.transaction_end != Some(TransactionEnd::Committed) {
        return Err("fixture transaction did not commit".into());
    }
    Ok(())
}

async fn prepare<T: WireTransport>(
    client: &mut Client<T>,
    sql: &str,
) -> std::result::Result<Statement, Error> {
    client
        .prepare(sql, &[Oid::INT4], PreparedStatementStorage::Named, BINARY)
        .await
}

async fn detail<T: WireTransport>(
    client: &mut Client<T>,
    statement: &Statement,
    key: i32,
) -> std::result::Result<(), Error> {
    client
        .query(statement, &[Parameter::int4(key)])
        .map_provisional_one(RECOVER, |row| {
            let mut fields = row.decoder();
            let id = fields.decode_next::<i32>()?;
            let title = fields.decode_next::<&str>()?;
            let flag = fields.decode_next::<bool>()?;
            let balance = fields.decode_next::<i64>()?;
            fields.finish()?;
            if id != key
                || title
                    .strip_prefix("item-")
                    .and_then(|n| n.parse::<i32>().ok())
                    != Some(id)
                || flag != (id % 2 == 0)
                || balance != i64::from(id) * 1000
            {
                return Err(Error::InvalidInput("detail row disagrees with the fixture"));
            }
            Ok(())
        })
        .await?;
    Ok(())
}

fn batch_options<T: WireTransport>(client: &Client<T>) -> BatchOptions {
    let query = client.execution_options().query;
    BatchOptions {
        member_limits: query.limits,
        max_requests: usize::from(BATCH_SIZE),
        max_inflight: 16,
        max_queued_request_bytes: 64 * 1024,
        max_diagnostic_bytes: 16 * 1024,
        scheduling: query.scheduling,
    }
}

async fn batch<T: WireTransport>(client: &mut Client<T>, statement: &Statement) -> Result<usize> {
    let limits = batch_options(client);
    let members = (1..=BATCH_SIZE).map(|key| statement.bind_one(Parameter::int4(i32::from(key))));
    let mut rows = 0;
    let mut confirmed = 0;
    let progress = client
        .streaming_batch(members)
        .with_options(limits)
        .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
            match event {
                BatchEvent::Row { index, row } => {
                    let mut fields = row.decoder();
                    let value = fields.decode_next::<i32>()?;
                    fields.finish()?;
                    if index != rows || usize::try_from(value).ok() != Some(index + 1) {
                        return Err(Error::InvalidInput(
                            "pipeline member returned an unexpected index or key",
                        ));
                    }
                    rows += 1;
                }
                BatchEvent::Ready { index, outcome, .. } => {
                    outcome.map_err(|error| Error::Database(error.clone()))?;
                    if index != confirmed || rows != confirmed + 1 {
                        return Err(Error::InvalidInput(
                            "pipeline confirmation does not match its row",
                        ));
                    }
                    confirmed += 1;
                }
                _ => {}
            }
            Ok(BatchControl::Continue)
        })
        .await?;
    if rows != usize::from(BATCH_SIZE) || confirmed != rows || progress.confirmed != confirmed {
        return Err("pipeline row or Ready count disagrees with the batch size".into());
    }
    Ok(rows)
}

async fn scalar_batch<T: WireTransport>(
    client: &mut Client<T>,
    statement: &Statement,
    output: &mut Vec<std::result::Result<i32, DatabaseError>>,
) -> Result<usize> {
    let limits = batch_options(client);
    let members = (1..=BATCH_SIZE).map(|key| statement.bind_one(Parameter::int4(i32::from(key))));
    let progress = client
        .streaming_batch(members)
        .with_options(limits)
        .collect_one_into_ready(output, RECOVER)
        .await?;
    let rows = output.len();
    if rows != usize::from(BATCH_SIZE) || progress.confirmed != rows {
        return Err("scalar pipeline count disagrees with the batch size".into());
    }
    for (key, result) in (1..=BATCH_SIZE).zip(output.drain(..)) {
        if result? != i32::from(key) {
            return Err("scalar pipeline member returned an unexpected key".into());
        }
    }
    Ok(rows)
}

fn report(name: &str, count: usize, elapsed: Duration, samples: &mut [Duration]) {
    let rate = count as f64 / elapsed.as_secs_f64();
    samples.sort_unstable();
    if samples.is_empty() {
        println!("{name},{count},{rate:.3},,");
    } else {
        let percentile =
            |p: usize| samples[(samples.len() * p).div_ceil(100) - 1].as_secs_f64() * 1e6;
        println!(
            "{name},{count},{rate:.3},{:.3},{:.3}",
            percentile(50),
            percentile(99)
        );
    }
}

async fn mixed<T: WireTransport + 'static>(
    foreground: &mut Client<T>,
    detail_query: &Statement,
    mut background: Client<T>,
    read: Statement,
) -> Result<()> {
    let stopped = Rc::new(Cell::new(false));
    let background_stop = Rc::clone(&stopped);
    let mut samples = Vec::with_capacity(usize::try_from(ARRIVALS)?);
    let start = Instant::now();
    let task = compio::runtime::spawn(async move {
        let mut queries = 0;
        while !background_stop.get() {
            queries += batch(&mut background, &read).await?;
        }
        let elapsed = start.elapsed();
        background.terminate().await?;
        Ok::<_, Box<dyn error::Error>>((queries, elapsed))
    });
    let foreground_result = async {
        for n in 0..ARRIVALS {
            let arrival = start + ARRIVAL_INTERVAL * n;
            if Instant::now() < arrival {
                compio::time::sleep_until(arrival).await;
            }
            detail(foreground, detail_query, i32::try_from(n)? + 1).await?;
            samples.push(arrival.elapsed());
        }
        Ok::<_, Box<dyn error::Error>>((samples, start.elapsed()))
    }
    .await;
    stopped.set(true);
    let background_result = task
        .await
        .map_err(|_| io::Error::other("background task terminated"))?;
    let (mut samples, duration) = foreground_result?;
    let (count, background_duration) = background_result?;
    report("mixed_front", samples.len(), duration, &mut samples);
    report("mixed_batch", count, background_duration, &mut []);
    Ok(())
}

async fn workloads<T: WireTransport + 'static>(
    mut foreground: Client<T>,
    mut background: Client<T>,
    schema: &str,
) -> Result<()> {
    let read = prepare(
        &mut foreground,
        &format!("SELECT id, title, flags, balance FROM {schema}.items WHERE id = $1"),
    )
    .await?;
    let write = prepare(
        &mut foreground,
        &format!("UPDATE {schema}.writes SET n=n+1 WHERE id=$1 RETURNING n"),
    )
    .await?;
    let pipeline = prepare(
        &mut background,
        &format!("SELECT id FROM {schema}.items WHERE id=$1"),
    )
    .await?;
    for key in 1..=256 {
        detail(&mut foreground, &read, key).await?;
    }
    for _ in 0..16 {
        batch(&mut background, &pipeline).await?;
    }

    let mut samples = Vec::with_capacity(usize::try_from(ITEMS)?);
    let start = Instant::now();
    for key in 1..=ITEMS {
        let sent = Instant::now();
        detail(&mut foreground, &read, key).await?;
        samples.push(sent.elapsed());
    }
    report("detail", samples.len(), start.elapsed(), &mut samples);
    samples.clear();
    let start = Instant::now();
    for expected in 1..=500 {
        let sent = Instant::now();
        let mut tx = foreground.begin_transaction().await?;
        let value = tx
            .query(&write, &[Parameter::int4(1)])
            .one::<i64>(RECOVER)
            .await?;
        if value != expected {
            return Err("write did not increment the fixture counter".into());
        }
        if tx.commit().await?.transaction_end != Some(TransactionEnd::Committed) {
            return Err("write transaction did not commit".into());
        }
        samples.push(sent.elapsed());
    }
    report("commit", samples.len(), start.elapsed(), &mut samples);
    let start = Instant::now();
    let mut rows = 0;
    for _ in 0..512 {
        rows += batch(&mut background, &pipeline).await?;
    }
    report("batch", rows, start.elapsed(), &mut []);

    let mut scalar_results = Vec::with_capacity(usize::from(BATCH_SIZE));
    for _ in 0..16 {
        scalar_batch(&mut background, &pipeline, &mut scalar_results).await?;
    }
    let start = Instant::now();
    let mut rows = 0;
    for _ in 0..512 {
        rows += scalar_batch(&mut background, &pipeline, &mut scalar_results).await?;
    }
    report("scalar_batch", rows, start.elapsed(), &mut []);
    mixed(&mut foreground, &read, background, pipeline).await?;
    foreground.terminate().await?;
    Ok(())
}

#[cfg(feature = "service")]
mod pooled {
    use super::*;
    use compio_postgres::service::{
        DispatchLimits, DispatchOperation, LocalDispatcher, LocalPool, PoolEntry, PoolReuse,
        PrewarmFailure, QueueLimits, ReleaseOutcome, SessionHygiene,
    };
    use std::num::NonZeroUsize;

    const CONNECTIONS: usize = 8;
    const WAVES: usize = 256;

    struct Lookup;

    impl<T: WireTransport> DispatchOperation<T, Statement> for Lookup {
        type Request = i32;
        type Response = std::result::Result<(), Error>;

        async fn execute_one(
            &self,
            client: &mut Client<T>,
            state: &mut Statement,
            key: i32,
        ) -> (Self::Response, SessionHygiene) {
            let result = detail(client, state, key).await;
            let hygiene = if result.is_ok() {
                SessionHygiene::Verified
            } else {
                SessionHygiene::Quarantine
            };
            (result, hygiene)
        }
    }

    async fn measure<L>(
        name: &str,
        lanes: &mut [L],
        query: impl AsyncFn(&mut L, i32) -> Result<()>,
    ) -> Result<()> {
        let lanes: &mut [L; CONNECTIONS] = lanes
            .try_into()
            .map_err(|_| format!("service benchmark requires {CONNECTIONS} lanes"))?;
        let mut samples = Vec::with_capacity(CONNECTIONS * WAVES);
        let mut start = Instant::now();
        for wave in 0..=WAVES {
            if wave == 1 {
                start = Instant::now();
            }
            let query = &query;
            let sample = |index, lane| async move {
                let key = i32::try_from(wave * CONNECTIONS + index)? % ITEMS + 1;
                let sent = Instant::now();
                query(lane, key).await?;
                Ok::<_, Box<dyn error::Error>>(sent.elapsed())
            };
            let [a, b, c, d, e, f, g, h] = lanes;
            let (a, b, c, d, e, f, g, h) = futures_util::join!(
                sample(0_usize, a),
                sample(1, b),
                sample(2, c),
                sample(3, d),
                sample(4, e),
                sample(5, f),
                sample(6, g),
                sample(7, h),
            );
            for result in [a, b, c, d, e, f, g, h] {
                let elapsed = result?;
                if wave != 0 {
                    samples.push(elapsed);
                }
            }
        }
        report(name, samples.len(), start.elapsed(), &mut samples);
        Ok(())
    }

    pub(super) async fn run<T: WireTransport + 'static>(
        connect: impl AsyncFn() -> std::result::Result<Client<T>, Error>,
        schema: &str,
        workload: Workload,
    ) -> Result<()> {
        let capacity = NonZeroUsize::new(CONNECTIONS).ok_or("empty service benchmark")?;
        let turn_budget = NonZeroUsize::new(2 * CONNECTIONS).ok_or("empty service benchmark")?;
        let sql = format!("SELECT id, title, flags, balance FROM {schema}.items WHERE id = $1");
        let connect_prepared = async || {
            let mut client = connect().await?;
            let statement = prepare(&mut client, &sql).await?;
            Ok::<_, Error>((client, statement))
        };
        if matches!(workload, Workload::Connections) {
            let mut connections = Vec::with_capacity(CONNECTIONS);
            for _ in 0..CONNECTIONS {
                connections.push(connect_prepared().await?);
            }
            measure(
                "connections",
                &mut connections,
                async |(client, statement), key| Ok(detail(client, statement, key).await?),
            )
            .await?;
            for (client, _) in connections {
                client.terminate().await?;
            }
            return Ok(());
        }
        let mut pool = LocalPool::try_new(capacity, PoolReuse::VerifyOnRelease)?;
        pool.prewarm(async || {
            let (client, statement) = connect_prepared()
                .await
                .map_err(PrewarmFailure::Uncertain)?;
            Ok(PoolEntry::new(client, statement))
        })
        .await?;
        let dispatcher = |pool, pending| {
            LocalDispatcher::try_new(
                pool,
                Lookup,
                DispatchLimits {
                    queue: QueueLimits {
                        max_items: pending,
                        max_charged_bytes: size_of::<i32>() * pending,
                    },
                    max_reply_slots: pending,
                    max_work_per_turn: turn_budget,
                },
            )
        };
        let pool = match workload {
            Workload::Pool => {
                measure("pool", &mut [(); CONNECTIONS], async |_, key| {
                    let mut lease = pool.try_acquire()?.ok_or("pool has no connection")?;
                    let (client, statement) = lease.client_and_state();
                    detail(client, statement, key).await?;
                    if lease.release(SessionHygiene::Verified) != ReleaseOutcome::Returned {
                        return Err("pool quarantined a completed lookup".into());
                    }
                    Ok(())
                })
                .await?;
                pool
            }
            Workload::Inline => {
                let dispatcher = dispatcher(pool, 0)?;
                measure("inline", &mut [(); CONNECTIONS], async |_, key| {
                    dispatcher.try_submit_inline(key).await??;
                    Ok(())
                })
                .await?;
                dispatcher.into_pool()
            }
            Workload::Scan | Workload::Ready => {
                let dispatcher = Rc::new(dispatcher(pool, CONNECTIONS)?);
                let (name, driver) = if matches!(workload, Workload::Scan) {
                    ("scan", Rc::clone(&dispatcher).spawn_scanned()?)
                } else {
                    ("ready", Rc::clone(&dispatcher).spawn_ready()?)
                };
                let result = measure(name, &mut [(); CONNECTIONS], async |_, key| {
                    dispatcher.submit_queued(key, size_of::<i32>()).await??;
                    Ok(())
                })
                .await;
                dispatcher.close_intake();
                driver
                    .await
                    .map_err(|_| io::Error::other("dispatch driver terminated"))??;
                result?;
                Rc::try_unwrap(dispatcher)
                    .map_err(|_| "dispatch driver is still active")?
                    .into_pool()
            }
            Workload::Direct | Workload::Connections => {
                return Err("expected a pooled benchmark".into());
            }
        };
        while let Some(lease) = pool.try_acquire()? {
            lease.close().await?;
        }
        if pool.occupancy().vacant != CONNECTIONS {
            return Err("pooled connections did not retire".into());
        }
        Ok(())
    }
}

async fn run<T: WireTransport + 'static>(
    connect: impl AsyncFn() -> std::result::Result<Client<T>, Error>,
    workload: Workload,
) -> Result<()> {
    let mut control = bounded("control connection", connect()).await??;
    if matches!(workload, Workload::Direct)
        && !bounded(
            "check fsync",
            control
                .one_shot("SELECT current_setting('fsync') = 'on'", &[], BINARY)
                .one::<bool>(RECOVER),
        )
        .await??
    {
        return Err("the logged transaction benchmark requires PostgreSQL fsync=on".into());
    }
    let schema = format!(
        "compio_bench_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos()
    );
    eprintln!("benchmark schema {schema}");
    bounded("create fixture", fixture(&mut control, &schema, true)).await??;
    println!("workload,count,operations_per_second,p50_us,p99_us");
    let result = bounded("workload", async {
        match workload {
            Workload::Direct => workloads(connect().await?, connect().await?, &schema).await,
            #[cfg(feature = "service")]
            _ => pooled::run(connect, &schema, workload).await,
        }
    })
    .await
    .flatten();
    let cleanup = bounded("remove fixture", fixture(&mut control, &schema, false))
        .await
        .flatten();
    if let Err(error) = &cleanup {
        eprintln!("cleanup of {schema} failed: {error}");
    }
    result?;
    cleanup?;
    bounded("close control connection", control.terminate()).await??;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1).filter(|arg| arg != "--bench");
    let modes = if cfg!(feature = "service") {
        "direct|connections|pool|inline|scan|ready"
    } else {
        "direct"
    };
    let name = args.next();
    let name = name
        .as_ref()
        .map(|name| name.to_str().ok_or("传输方式须为有效的 Unicode"))
        .transpose()?;
    let name = match name {
        Some(name) if !matches!(name, "--help" | "-h") => name,
        _ => {
            println!(
                "用法：cargo bench --bench service_workload -- {} [{modes}]",
                Transport::CHOICES
            );
            return Ok(());
        }
    };
    let transport = Transport::parse(name)?;
    let mode = args.next();
    let mode = mode
        .as_ref()
        .map(|mode| mode.to_str().ok_or("负载名称须为有效的 Unicode"))
        .transpose()?;
    let workload = match mode {
        None | Some("direct") => Workload::Direct,
        #[cfg(feature = "service")]
        Some("connections") => Workload::Connections,
        #[cfg(feature = "service")]
        Some("pool") => Workload::Pool,
        #[cfg(feature = "service")]
        Some("inline") => Workload::Inline,
        #[cfg(feature = "service")]
        Some("scan") => Workload::Scan,
        #[cfg(feature = "service")]
        Some("ready") => Workload::Ready,
        #[cfg(not(feature = "service"))]
        Some("connections" | "pool" | "inline" | "scan" | "ready") => {
            return Err("concurrent connection benchmarks require the service feature".into());
        }
        _ => return Err(format!("expected workload {modes}").into()),
    };
    if args.next().is_some() {
        return Err("expected a transport and an optional workload".into());
    }
    let runtime = compio::runtime::Runtime::new()?;
    eprintln!("transport={name} driver={:?}", runtime.driver_type());
    #[cfg(target_os = "linux")]
    if !runtime.driver_type().is_iouring() {
        return Err("the Linux benchmark requires io_uring".into());
    }
    match transport.config(&runtime)? {
        Config::Tcp(config) => {
            let options =
                ClientOptions::short_queries(config.startup_parameter("synchronous_commit", "on"));
            runtime.block_on(run(|| TcpConnection::connect(options.clone()), workload))
        }
        #[cfg(feature = "tls")]
        Config::Tls(config) => {
            let options =
                ClientOptions::short_queries(config.startup_parameter("synchronous_commit", "on"));
            runtime.block_on(run(
                || compio_postgres::TlsConnection::connect(options.clone()),
                workload,
            ))
        }
        #[cfg(unix)]
        Config::Unix(config) => {
            let options =
                ClientOptions::short_queries(config.startup_parameter("synchronous_commit", "on"));
            runtime.block_on(run(
                || compio_postgres::UnixConnection::connect(options.clone()),
                workload,
            ))
        }
    }
}
