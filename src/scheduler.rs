//! 应用可选的协作调度。一次调度额度可跨越查询、行交付和重建的等待方；到达显式让出点后才会补充。

use std::{future::poll_fn, num::NonZeroUsize, task::Poll};

use crate::{Error, transport::IoOwner};

/// 查询或流水线的调度方式，也适用于逐步交付的分组和固定重放。
///
/// 每个响应帧至少计一单位，较大帧按每 KiB 向上取整。
/// 查询与有限流水线（包括批量准备和关闭）按整包计费，窗口按成员计费，动态分组还计入读取的输入项及完整编码组。额度跨同步组和显式恢复保留；
/// 借用行释放后才允许查询挂起让出。
///
/// 单次编码、输入迭代、固定组编译和同步回调不可分割，额度仅用于协作调度。各独立操作分别计量；
/// 外层循环可保留 [`BatchQuantum`]。COPY 在开始时确定调度方式，发送、接收、收集和结束共用同一额度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionScheduling {
    /// 处理就绪工作时不额外插入协作让出点。
    Uninterrupted,
    /// 工作额度耗尽后重新调度。运行时读取的额度可用 [`NonZeroUsize::new`] 校验。
    ///
    /// ```compile_fail,E0308
    /// use compio_postgres::ExecutionScheduling;
    /// let _ = ExecutionScheduling::Cooperative { max_work_per_turn: 0 };
    /// ```
    Cooperative { max_work_per_turn: NonZeroUsize },
}

/// 与已接纳协议进度一起保留的调度状态。重建等待方或恢复已中止的操作时沿用剩余额度。
#[derive(Debug)]
pub(crate) enum ExecutionQuantum {
    Uninterrupted,
    Cooperative(BatchQuantum),
}

pub(crate) fn byte_work_units(bytes: usize) -> usize {
    bytes.div_ceil(1024).max(1)
}

impl ExecutionQuantum {
    pub(crate) fn new(scheduling: ExecutionScheduling) -> Self {
        match scheduling {
            ExecutionScheduling::Uninterrupted => Self::Uninterrupted,
            ExecutionScheduling::Cooperative { max_work_per_turn } => {
                Self::Cooperative(BatchQuantum::new(max_work_per_turn))
            }
        }
    }

    #[inline]
    pub(crate) fn spend_bytes(&mut self, bytes: usize) {
        if let Self::Cooperative(quantum) = self {
            quantum.spend(byte_work_units(bytes));
        }
    }

    #[inline]
    pub(crate) fn spend_units(&mut self, work: usize) {
        if let Self::Cooperative(quantum) = self {
            quantum.spend(work);
        }
    }

    pub(crate) fn poll_yield_on_worker(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        match self {
            Self::Uninterrupted => Poll::Ready(Ok(())),
            Self::Cooperative(quantum) => quantum.poll_yield_on_worker(cx),
        }
    }

    /// 外层轮询已经校验所属 runtime 时，只执行额度检查。
    pub(crate) fn poll_yield_if_exhausted(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        match self {
            Self::Uninterrupted => Poll::Ready(()),
            Self::Cooperative(quantum) => quantum.poll_yield_if_exhausted(cx),
        }
    }

    #[inline]
    pub(crate) fn is_exhausted(&self) -> bool {
        matches!(self, Self::Cooperative(quantum) if quantum.remaining() == 0)
    }

    pub(crate) async fn yield_on_worker(&mut self) -> Result<(), Error> {
        match self {
            Self::Uninterrupted => Ok(()),
            Self::Cooperative(quantum) => quantum.yield_on_worker().await,
        }
    }
}

#[derive(Debug)]
pub struct BatchQuantum {
    quantum: usize,
    remaining: usize,
    yielded: bool,
    resume_owner: IoOwner,
}

impl BatchQuantum {
    pub fn new(quantum: NonZeroUsize) -> Self {
        let quantum = quantum.get();
        Self {
            quantum,
            remaining: quantum,
            yielded: false,
            resume_owner: IoOwner::default(),
        }
    }

    /// 使用一致单位扣减本轮已完成的行、字节或请求量。硬资源限额独立检查。
    pub fn spend(&mut self, work: usize) {
        self.remaining = self.remaining.saturating_sub(work);
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// 额度耗尽时安排下一次轮询。丢弃等待方不会清除已让出的标记；调用方应跨操作保留调度状态。
    pub async fn yield_if_exhausted(&mut self) {
        poll_fn(|cx| self.poll_yield_if_exhausted(cx)).await;
    }

    pub(crate) async fn yield_on_worker(&mut self) -> Result<(), Error> {
        poll_fn(|cx| self.poll_yield_on_worker(cx)).await
    }

    /// 连接只在实际让出时保存 worker 身份，继续交付已缓存响应前验证恢复位置。
    fn poll_yield_on_worker(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        if self.remaining != 0 {
            return Poll::Ready(Ok(()));
        }
        if self.yielded {
            self.resume_owner.check()?;
            self.resume_owner = IoOwner::default();
        } else {
            self.resume_owner = IoOwner::current();
        }
        self.poll_exhausted(cx).map(Ok)
    }

    pub(crate) fn poll_yield_if_exhausted(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if self.remaining != 0 {
            return Poll::Ready(());
        }
        self.poll_exhausted(cx)
    }

    fn poll_exhausted(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if self.yielded {
            self.remaining = self.quantum;
            self.yielded = false;
            Poll::Ready(())
        } else {
            self.yielded = true;
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::cooperative_yield();
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn a_rebuilt_waiter_does_not_restore_an_exhausted_turn() {
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut turn = BatchQuantum::new(NonZeroUsize::new(3).unwrap());
        turn.spend(2);
        assert!(pin!(turn.yield_if_exhausted()).poll(&mut cx).is_ready());
        assert_eq!(turn.remaining(), 1);
        turn.spend(2);
        assert!(pin!(turn.yield_if_exhausted()).poll(&mut cx).is_pending());
        assert_eq!(turn.remaining(), 0);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert!(pin!(turn.yield_if_exhausted()).poll(&mut cx).is_ready());
        assert_eq!(turn.remaining(), 3);
    }

    #[test]
    fn an_always_ready_loop_gives_a_competing_runtime_task_a_poll() {
        use std::{cell::Cell, rc::Rc};
        let runtime = compio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let ran = Rc::new(Cell::new(false));
            let competitor = ran.clone();
            let task = compio::runtime::spawn(async move {
                competitor.set(true);
            });
            let mut turn = BatchQuantum::new(NonZeroUsize::new(32).unwrap());
            for _ in 0..1024 {
                turn.spend(1);
                turn.yield_if_exhausted().await;
            }
            assert!(ran.get());
            task.await.unwrap();
        });
    }
}
