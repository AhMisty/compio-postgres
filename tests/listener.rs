#[path = "support/live.rs"]
mod live;
#[path = "support/peer.rs"]
mod peer;

use compio_postgres::{Error, expert::TcpSession};
use std::io::Write;

fn notification(message: &str) -> Vec<u8> {
    let mut body = Vec::from(17_i32.to_be_bytes());
    body.extend_from_slice(b"name\"with_quote\0");
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    peer::frame(b'A', &body)
}

#[test]
fn listener_delivers_notifications_inside_and_between_subscription_boundaries() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        assert_eq!(
            peer::expect(socket, b'Q')?,
            b"LISTEN \"name\"\"with_quote\"\0"
        );
        let mut response = peer::frame(b'C', b"LISTEN\0");
        response.extend(notification("in listen"));
        response.extend(peer::ready(b'I'));
        response.extend(notification("idle"));
        socket.write_all(&response)?;
        assert_eq!(
            peer::expect(socket, b'Q')?,
            b"UNLISTEN \"name\"\"with_quote\"\0"
        );
        let mut response = notification("in unlisten");
        response.extend(peer::frame(b'C', b"UNLISTEN\0"));
        response.extend(peer::ready(b'I'));
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut listener = TcpSession::connect(peer.config())
            .await
            .unwrap()
            .into_listener(compio_postgres::ExecutionScheduling::Uninterrupted)
            .unwrap();
        assert!(matches!(
            listener.listen("bad\0name", |_| {}).await,
            Err(Error::InvalidInput(_))
        ));
        let channel = "name\"with_quote";
        let mut delivered = 0;
        listener
            .listen(channel, |event| {
                delivered += 1;
                assert_eq!(
                    (event.process_id, event.channel, event.payload),
                    (17, channel, "in listen")
                );
            })
            .await
            .unwrap();
        assert_eq!(delivered, 1);
        assert_eq!(
            listener
                .next_notification(|event| event.payload.to_owned())
                .await
                .unwrap(),
            "idle"
        );
        listener
            .unlisten(channel, |event| {
                delivered += 1;
                assert_eq!(event.payload, "in unlisten");
            })
            .await
            .unwrap();
        assert_eq!(delivered, 2);
        listener.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn buffered_notifications_yield_to_another_worker_task_without_losing_order() {
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    struct Yielded(AtomicBool);
    impl Wake for Yielded {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        let mut batch = Vec::new();
        for number in 0..257 {
            batch.extend(notification(&number.to_string()));
        }
        socket.write_all(&batch)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut listener = TcpSession::connect(peer.config())
            .await
            .unwrap()
            .into_listener(compio_postgres::ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(128).unwrap(),
            })
            .unwrap();
        let number =
            |event: compio_postgres::Notification<'_>| event.payload.parse::<usize>().unwrap();
        for expected in 0..128 {
            assert_eq!(listener.next_notification(number).await.unwrap(), expected);
        }
        let competing = compio::runtime::spawn(async { 73 });
        {
            // 即使第 129 条通知尚未抵达，主动唤醒也能区分协作让步与等待 socket。
            let yielded = Arc::new(Yielded(AtomicBool::new(false)));
            let waker = Waker::from(yielded.clone());
            let mut next = std::pin::pin!(listener.next_notification(number));
            assert!(
                next.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert!(yielded.0.load(Ordering::Relaxed));
            assert_eq!(competing.await.unwrap(), 73);
            assert_eq!(next.await.unwrap(), 128);
        }
        for expected in 129..257 {
            assert_eq!(listener.next_notification(number).await.unwrap(), expected);
        }
        listener.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn a_listener_keeps_its_pending_receive_after_a_foreign_runtime_poll() {
    use compio::runtime::Runtime;
    use std::{
        future::Future,
        pin::pin,
        sync::mpsc,
        task::{Context, Poll, Waker},
    };

    let (release, gate) = mpsc::channel();
    let peer = peer::Peer::start(move |socket| {
        peer::handshake(socket)?;
        gate.recv_timeout(peer::IO_DEADLINE).unwrap();
        socket.write_all(&notification("owner"))?;
        peer::eof(socket)
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut listener = owner
        .block_on(TcpSession::connect(peer.config()))
        .unwrap()
        .into_listener(compio_postgres::ExecutionScheduling::Uninterrupted)
        .unwrap();
    {
        let mut next = pin!(listener.next_notification(|event| event.payload.to_owned()));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(owner.enter(|| next.as_mut().poll(&mut cx)).is_pending());
        assert!(matches!(
            foreign.enter(|| next.as_mut().poll(&mut cx)),
            Poll::Ready(Err(Error::InvalidInput(_)))
        ));
    }
    release.send(()).unwrap();
    owner.block_on(async {
        let message = compio::time::timeout(
            peer::DEADLINE,
            listener.next_notification(|event| event.payload.to_owned()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(message, "owner");
        listener.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn subscriptions_deliver_committed_notifications_until_unlisten() {
    use compio_postgres::{
        ClientOptions, OnError, PreparedStatementStorage, ResultFormats, TcpConnection, WireLimits,
        types::{Format, Oid, Parameter},
    };

    const CHANNEL: &str = "cpg_listener_test\"channel";
    const MARKER: &str = "cpg_listener_test_marker";
    let options = ClientOptions::short_queries(live::tcp_config(
        WireLimits::short_queries(),
        peer::TCP_OPTIONS,
    ));
    peer::run(async {
        let mut sender = TcpConnection::connect(options.clone()).await.unwrap();
        let mut listener = TcpConnection::connect(options)
            .await
            .unwrap()
            .into_listener(compio_postgres::ExecutionScheduling::Uninterrupted)
            .unwrap();
        let sender_pid = sender.server_info().process_id;
        let notify = sender
            .prepare(
                "SELECT pg_catalog.pg_notify($1, $2) IS NULL",
                &[Oid::TEXT, Oid::TEXT],
                PreparedStatementStorage::Named,
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let send = async |sender: &mut TcpConnection, channel, payload| {
            sender
                .query(
                    &notify,
                    &[Parameter::string(channel), Parameter::string(payload)],
                )
                .one::<bool>(OnError::RecoverExplicitly)
                .await
                .unwrap();
        };

        listener.listen(CHANNEL, |_| {}).await.unwrap();
        listener.listen(MARKER, |_| {}).await.unwrap();
        send(&mut sender, CHANNEL, "通知").await;
        listener
            .next_notification(|event| {
                assert_eq!(
                    (event.process_id, event.channel, event.payload),
                    (sender_pid, CHANNEL, "通知")
                );
            })
            .await
            .unwrap();

        listener.unlisten(CHANNEL, |_| {}).await.unwrap();
        send(&mut sender, CHANNEL, "已取消订阅").await;
        send(&mut sender, MARKER, "边界").await;
        // 两条通知来自同一连接顺序提交的事务，收到标记即可确认先提交的通知未交付。
        listener
            .next_notification(|event| {
                assert_eq!(
                    (event.process_id, event.channel, event.payload),
                    (sender_pid, MARKER, "边界")
                );
            })
            .await
            .unwrap();
        listener.close_local().await.unwrap();
        sender.terminate().await.unwrap();
    });
}
