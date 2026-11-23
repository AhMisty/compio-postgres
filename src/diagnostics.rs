//! 当前线程的诊断计数。启用特性后才记录，不参与协议、额度或复用决策。
//! 原生提交尝试不代表内核已经接纳，TLS 明文轮询次数也不等于系统调用次数。
use std::cell::RefCell;

// 字段声明和差值使用同一份清单，新增计数器时两处同时生效。
macro_rules! counters {
    ($($(#[$doc:meta])* $field:ident,)*) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct Counters {
            $($(#[$doc])* pub $field: u64,)*
            pub overflowed: bool,
        }

        impl Counters {
            const ZERO: Self = Self { $($field: 0,)* overflowed: false };

            /// 计算同一线程前后两次快照的差值。
            pub fn delta(self, before: Self) -> Option<Self> {
                if self.overflowed || before.overflowed {
                    return None;
                }
                Some(Self {
                    $($field: self.$field.checked_sub(before.$field)?,)*
                    overflowed: false,
                })
            }
        }
    };
}

counters! {
    native_frame_polls,
    native_send_polls,
    native_send_pending_polls,
    native_receive_polls,
    native_receive_pending_polls,
    cooperative_yields,
    native_send_attempts,
    native_receive_attempts,
    native_send_successes,
    native_receive_successes,
    native_bytes_sent,
    native_bytes_received,
    readiness_send_attempts,
    readiness_receive_attempts,
    readiness_bytes_sent,
    readiness_bytes_received,
    readiness_send_would_block,
    readiness_receive_would_block,
    tls_plaintext_write_polls,
    tls_plaintext_read_polls,
    tls_plaintext_written,
    tls_plaintext_received,
    /// TLS 传输内暂存的分片帧头与拼接的帧体字节。
    tls_plaintext_bytes_copied,
    /// 直接从 TLS 明文存储借出的整帧或帧体字节。整帧借用包含帧头。
    tls_plaintext_bytes_borrowed,
    /// Windows 套接字适配层复制给 TLS 读取端的密文字节。
    tls_ciphertext_read_bytes_copied,
    /// Windows 套接字适配层接收并复制的 TLS 密文字节。
    tls_ciphertext_write_bytes_copied,
    /// 派发器发出的驱动、维护及回复唤醒次数，分别计数。
    dispatcher_driver_wakes,
    dispatcher_maintenance_wakes,
    dispatcher_reply_wakes,
    backend_frames,
    rx_suffix_bytes_compacted,
    /// 准备读取时，未读帧仍可在原位置完整容纳，因而跳过移动的次数。后续读取仍可能需要移动。
    rx_compactions_skipped,
    /// 上述操作保留在原位置的后缀字节总数。短读后，同一后缀可以被再次计入。
    rx_suffix_bytes_retained_in_place,
    /// 复制到自有行存储的字段字节数，不含分配器在扩容时移动的内存。
    owned_field_bytes_copied,
    frontend_parameter_bytes_copied,
    /// 成功编译固定重放组的次数。
    frozen_groups_compiled,
    /// 成功编译的固定重放组所生成的完整协议包字节数。
    frozen_packet_bytes_encoded,
    /// 成功编译固定重放组时复制的参数字节数，不含协议头。
    frozen_parameter_bytes_copied,
    /// 已由 begin_send 接纳的重放次数；须另行确认发送和 SQL 执行结果。
    frozen_group_replays,
    /// 已接纳的重放包总字节数。
    frozen_packet_bytes_replayed,
    copy_in_payload_bytes_copied,
    /// next_chunk 交付的 COPY 数据字节数，与 TCP 分包及 TLS 记录无关。
    copy_out_chunks_delivered,
    copy_out_payload_bytes_delivered,
    /// 从接收缓冲复制到收集结果的载荷字节数，分配器内部搬移另计。
    copy_out_payload_bytes_copied,
    tx_queue_packets_moved,
}

thread_local! {
    static COUNTERS: RefCell<Counters> = const { RefCell::new(Counters::ZERO) };
}

pub fn snapshot() -> Counters {
    COUNTERS.with(|cell| *cell.borrow())
}

fn record(f: impl FnOnce(&mut Counters)) {
    COUNTERS.with(|cell| f(&mut cell.borrow_mut()));
}

fn add(value: &mut u64, amount: usize, overflow: &mut bool) {
    if let Some(next) = u64::try_from(amount)
        .ok()
        .and_then(|amount| value.checked_add(amount))
    {
        *value = next;
    } else {
        *value = u64::MAX;
        *overflow = true;
    }
}
pub(crate) fn native_frame_poll() {
    record(|c| add(&mut c.native_frame_polls, 1, &mut c.overflowed));
}
pub(crate) fn native_send_poll() {
    record(|c| add(&mut c.native_send_polls, 1, &mut c.overflowed));
}
pub(crate) fn native_send_pending_poll() {
    record(|c| add(&mut c.native_send_pending_polls, 1, &mut c.overflowed));
}
pub(crate) fn native_receive_poll() {
    record(|c| add(&mut c.native_receive_polls, 1, &mut c.overflowed));
}
pub(crate) fn native_receive_pending_poll() {
    record(|c| add(&mut c.native_receive_pending_polls, 1, &mut c.overflowed));
}
pub(crate) fn cooperative_yield() {
    record(|c| add(&mut c.cooperative_yields, 1, &mut c.overflowed));
}
pub(crate) fn send_attempt() {
    record(|c| add(&mut c.native_send_attempts, 1, &mut c.overflowed));
}
pub(crate) fn receive_attempt() {
    record(|c| add(&mut c.native_receive_attempts, 1, &mut c.overflowed));
}
pub(crate) fn sent(n: usize) {
    record(|c| {
        add(&mut c.native_send_successes, 1, &mut c.overflowed);
        add(&mut c.native_bytes_sent, n, &mut c.overflowed);
    });
}
pub(crate) fn received(n: usize) {
    record(|c| {
        add(&mut c.native_receive_successes, 1, &mut c.overflowed);
        add(&mut c.native_bytes_received, n, &mut c.overflowed);
    });
}
#[cfg(target_os = "linux")]
pub(crate) fn readiness_send_attempt() {
    record(|c| add(&mut c.readiness_send_attempts, 1, &mut c.overflowed));
}
#[cfg(target_os = "linux")]
pub(crate) fn readiness_receive_attempt() {
    record(|c| add(&mut c.readiness_receive_attempts, 1, &mut c.overflowed));
}
#[cfg(target_os = "linux")]
pub(crate) fn readiness_sent(n: usize) {
    record(|c| add(&mut c.readiness_bytes_sent, n, &mut c.overflowed));
}
#[cfg(target_os = "linux")]
pub(crate) fn readiness_received(n: usize) {
    record(|c| add(&mut c.readiness_bytes_received, n, &mut c.overflowed));
}
#[cfg(target_os = "linux")]
pub(crate) fn readiness_send_would_block() {
    record(|c| add(&mut c.readiness_send_would_block, 1, &mut c.overflowed));
}
#[cfg(target_os = "linux")]
pub(crate) fn readiness_receive_would_block() {
    record(|c| add(&mut c.readiness_receive_would_block, 1, &mut c.overflowed));
}
#[cfg(feature = "tls")]
pub(crate) fn tls_write_poll() {
    record(|c| add(&mut c.tls_plaintext_write_polls, 1, &mut c.overflowed));
}
#[cfg(feature = "tls")]
pub(crate) fn tls_read_poll() {
    record(|c| add(&mut c.tls_plaintext_read_polls, 1, &mut c.overflowed));
}
#[cfg(feature = "tls")]
pub(crate) fn tls_written(n: usize) {
    record(|c| add(&mut c.tls_plaintext_written, n, &mut c.overflowed));
}
#[cfg(feature = "tls")]
pub(crate) fn tls_received(n: usize) {
    record(|c| add(&mut c.tls_plaintext_received, n, &mut c.overflowed));
}
#[cfg(feature = "tls")]
pub(crate) fn tls_plaintext_copied(n: usize) {
    record(|c| add(&mut c.tls_plaintext_bytes_copied, n, &mut c.overflowed));
}
#[cfg(feature = "tls")]
pub(crate) fn tls_plaintext_borrowed(n: usize) {
    record(|c| add(&mut c.tls_plaintext_bytes_borrowed, n, &mut c.overflowed));
}
#[cfg(all(feature = "tls", windows))]
pub(crate) fn tls_ciphertext_read_copied(n: usize) {
    record(|c| {
        add(
            &mut c.tls_ciphertext_read_bytes_copied,
            n,
            &mut c.overflowed,
        )
    });
}
#[cfg(all(feature = "tls", windows))]
pub(crate) fn tls_ciphertext_write_copied(n: usize) {
    record(|c| {
        add(
            &mut c.tls_ciphertext_write_bytes_copied,
            n,
            &mut c.overflowed,
        )
    });
}
#[cfg(feature = "service")]
pub(crate) fn dispatcher_driver_wake() {
    record(|c| add(&mut c.dispatcher_driver_wakes, 1, &mut c.overflowed));
}
#[cfg(feature = "service")]
pub(crate) fn dispatcher_maintenance_wake() {
    record(|c| add(&mut c.dispatcher_maintenance_wakes, 1, &mut c.overflowed));
}
#[cfg(feature = "service")]
pub(crate) fn dispatcher_reply_wake() {
    record(|c| add(&mut c.dispatcher_reply_wakes, 1, &mut c.overflowed));
}
pub(crate) fn frame() {
    record(|c| add(&mut c.backend_frames, 1, &mut c.overflowed));
}
pub(crate) fn compact(n: usize) {
    record(|c| add(&mut c.rx_suffix_bytes_compacted, n, &mut c.overflowed));
}
pub(crate) fn compaction_skipped(n: usize) {
    record(|c| {
        add(&mut c.rx_compactions_skipped, 1, &mut c.overflowed);
        add(
            &mut c.rx_suffix_bytes_retained_in_place,
            n,
            &mut c.overflowed,
        );
    });
}
pub(crate) fn owned_copy(n: usize) {
    record(|c| add(&mut c.owned_field_bytes_copied, n, &mut c.overflowed));
}
pub(crate) fn parameter_copy(n: usize) {
    record(|c| add(&mut c.frontend_parameter_bytes_copied, n, &mut c.overflowed));
}
pub(crate) fn frozen_compile(packet_bytes: usize, parameter_bytes: usize) {
    record(|c| {
        add(&mut c.frozen_groups_compiled, 1, &mut c.overflowed);
        add(
            &mut c.frozen_packet_bytes_encoded,
            packet_bytes,
            &mut c.overflowed,
        );
        add(
            &mut c.frozen_parameter_bytes_copied,
            parameter_bytes,
            &mut c.overflowed,
        );
    });
}
pub(crate) fn frozen_replay(packet_bytes: usize) {
    record(|c| {
        add(&mut c.frozen_group_replays, 1, &mut c.overflowed);
        add(
            &mut c.frozen_packet_bytes_replayed,
            packet_bytes,
            &mut c.overflowed,
        );
    });
}
pub(crate) fn copy_in(n: usize) {
    record(|c| add(&mut c.copy_in_payload_bytes_copied, n, &mut c.overflowed));
}

pub(crate) fn copy_out_chunk(n: usize) {
    record(|c| {
        add(&mut c.copy_out_chunks_delivered, 1, &mut c.overflowed);
        add(
            &mut c.copy_out_payload_bytes_delivered,
            n,
            &mut c.overflowed,
        );
    });
}

pub(crate) fn copy_out_copy(n: usize) {
    record(|c| add(&mut c.copy_out_payload_bytes_copied, n, &mut c.overflowed));
}

pub(crate) fn queued_packet_move() {
    record(|c| add(&mut c.tx_queue_packets_moved, 1, &mut c.overflowed));
}
