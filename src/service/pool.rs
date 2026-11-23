use crate::{Client, Error, ReuseState, WireTransport};
use std::{
    cell::{OnceCell, RefCell},
    fmt,
    future::{Future, poll_fn},
    mem::DropGuard,
    num::NonZeroUsize,
    ops::AsyncFnMut,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};

use compio::runtime::Runtime;

/// 连接及其会话专属状态，例如预备语句句柄。
pub struct PoolEntry<T: WireTransport, S = ()> {
    client: Client<T>,
    state: S,
    connection_id: u64,
}

impl<T: WireTransport, S> PoolEntry<T, S> {
    pub fn new(client: Client<T>, state: S) -> Self {
        let (connection_id, _) = client.pool_identity();
        Self {
            client,
            state,
            connection_id,
        }
    }
}

type RetirementFuture = Pin<Box<dyn Future<Output = (bool, Result<(), Error>)>>>;

struct RetirementClaim {
    id: MaintenanceId,
    waker: Option<Waker>,
}

struct RetainedRetirement {
    owner: Option<Waker>,
    future: RetirementFuture,
    claim: Option<RetirementClaim>,
}

enum MaintenanceState {
    Reserved,
    Uncertain,
    Retirement(RetainedRetirement),
    Polling,
}

struct MaintenanceEntry {
    id: MaintenanceId,
    state: MaintenanceState,
}

/// 跨多次池操作标识同一个预留槽或关闭操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaintenanceId(u64);

impl MaintenanceId {
    fn allocate() -> Option<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()
            .map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingMaintenance {
    pub id: MaintenanceId,
    /// 池是否保留可恢复的关闭 future。否则须由调用方确认原连接及在途 I/O 均已结束。
    pub resumable: bool,
    /// 预留守卫或关闭等待方是否仍持有处理权。
    pub claimed: bool,
}

struct Slots<T: WireTransport, S> {
    ready: Vec<Box<PoolEntry<T, S>>>,
    quarantined: Vec<Box<PoolEntry<T, S>>>,
    leased: usize,
    maintenance: Vec<MaintenanceEntry>,
    vacant: usize,
}

fn worker_matches_current(owner: Option<&Waker>) -> bool {
    Runtime::try_with_current(|current| owner.is_none_or(|owner| owner.will_wake(&current.waker())))
        .unwrap_or(false)
}

impl<T: WireTransport, S> Slots<T, S> {
    fn maintenance_mut(&mut self, id: MaintenanceId) -> Option<&mut MaintenanceState> {
        self.maintenance
            .iter_mut()
            .find(|entry| entry.id == id)
            .map(|entry| &mut entry.state)
    }

    fn remove_maintenance(
        &mut self,
        id: MaintenanceId,
        eligible: impl Fn(&MaintenanceState) -> bool,
    ) -> bool {
        let Some((index, entry)) = self
            .maintenance
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.id == id)
        else {
            return false;
        };
        if !eligible(&entry.state) {
            return false;
        }
        self.maintenance.swap_remove(index);
        true
    }

    fn refund(&mut self, id: MaintenanceId, eligible: impl Fn(&MaintenanceState) -> bool) -> bool {
        if !self.remove_maintenance(id, eligible) {
            return false;
        }
        self.vacant += 1;
        true
    }
    #[inline]
    fn place_entry(
        &mut self,
        entry: Box<PoolEntry<T, S>>,
        hygiene: SessionHygiene,
    ) -> Result<(), ReuseState> {
        let state = entry.client.reuse_state();
        if state == ReuseState::ProtocolIdle && hygiene == SessionHygiene::Verified {
            self.ready.push(entry);
            Ok(())
        } else {
            self.quarantined.push(entry);
            Err(state)
        }
    }
}

/// 固定容量的本地连接池。普通租借仅提供所属 Compio runtime 上的连接；隔离连接须在其所属 runtime 处理。
///
/// 空闲连接按 LIFO 复用。预热、租借和维护由应用驱动；构造策略决定普通空闲租约在析构时如何归还。
pub struct LocalPool<T: WireTransport, S = ()> {
    owner: OnceCell<Waker>,
    slots: RefCell<Slots<T, S>>,
    reuse: PoolReuse,
}

/// 建池时选择会话复用约定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolReuse {
    /// 借用方共享会话设置。普通租约析构时，原连接在所属 runtime 内且协议空闲即可归还。
    SharedSession,
    /// 每次归还前由调用方显式确认会话状态。
    VerifyOnRelease,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Occupancy {
    pub ready: usize,
    pub leased: usize,
    pub quarantined: usize,
    /// 关闭或替换操作仍占用的槽，包括结果尚未确认的尝试。
    pub maintenance: usize,
    pub vacant: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHygiene {
    /// 调用方已确认会话设置、身份、临时对象和预备语句适合下一租约。
    ///
    /// 池另行检查协议空闲状态。跨租户复用还须满足应用的隔离约定。
    Verified,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ReleaseOutcome {
    Returned,
    /// 此项进入隔离区，包括调用方主动隔离协议空闲的连接。
    Quarantined(ReuseState),
    /// 租借期间连接被替换，已隔离此项。
    ConnectionReplaced,
    /// 归还时当前 runtime 或连接与池的归属不符，已隔离此项。
    WrongRuntime,
}

/// 将新连接安装到预留槽的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum InstallOutcome {
    /// 连接已经可以租借。
    Installed,
    /// 连接尚未达到协议空闲，已放入隔离区。
    Quarantined(ReuseState),
    /// 预留身份已经失效，未公布新连接。
    ReservationLost,
    /// 安装时当前 runtime 或连接与池的归属不符，已放入隔离区。
    WrongRuntime,
}

#[derive(Debug)]
pub enum PrewarmFailure<E> {
    /// 调用方已确认没有存活的替代连接或在途 I/O。
    Vacant(E),
    /// 该尝试仍可能持有连接或在途 I/O。
    Uncertain(E),
}

#[derive(Debug)]
pub enum PrewarmError<E> {
    /// 此前安装的项仍可使用；失败分类决定本次尝试是否继续占用槽。
    Factory {
        installed: usize,
        failure: PrewarmFailure<E>,
        pending: Option<MaintenanceId>,
    },
    /// 工厂返回的连接仍有协议工作，进入隔离区供维护方接管。
    NotProtocolIdle { installed: usize, state: ReuseState },
    /// 当前 worker 不能为此池预热，或工厂返回的连接来自其他 worker。已创建的连接进入隔离。
    WrongRuntime {
        installed: usize,
        /// 工厂跨 runtime 恢复时，其已预留的槽仍需确认。
        pending: Option<MaintenanceId>,
    },
    /// 预留身份与预期槽不匹配。
    ReservationLost { installed: usize },
}

impl<E: fmt::Display> fmt::Display for PrewarmError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Factory {
                installed,
                failure: PrewarmFailure::Vacant(source) | PrewarmFailure::Uncertain(source),
                ..
            } => {
                write!(
                    formatter,
                    "prewarm failed after installing {installed} entries: {source}"
                )
            }
            Self::NotProtocolIdle { installed, state } => write!(
                formatter,
                "prewarm returned {state:?} after installing {installed} entries"
            ),
            Self::ReservationLost { installed } => write!(
                formatter,
                "prewarm lost its reservation after installing {installed} entries"
            ),
            Self::WrongRuntime { installed, .. } => write!(
                formatter,
                "prewarm worker mismatch after installing {installed} entries"
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PrewarmError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Factory {
                failure: PrewarmFailure::Vacant(source) | PrewarmFailure::Uncertain(source),
                ..
            } => Some(source),
            Self::NotProtocolIdle { .. }
            | Self::WrongRuntime { .. }
            | Self::ReservationLost { .. } => None,
        }
    }
}

/// 独占借用一个连接池项，直至归还或关闭。
#[must_use = "请归还租约或显式关闭连接"]
pub struct Lease<'pool, T: WireTransport, S = ()> {
    guard: super::Guarded<LeasedEntry<'pool, T, S>>,
}

struct LeasedEntry<'pool, T: WireTransport, S> {
    pool: &'pool LocalPool<T, S>,
    entry: Box<PoolEntry<T, S>>,
    origin: LeaseOrigin,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseOrigin {
    ReadyShared,
    ReadyExplicit,
    Quarantine,
}

/// 开始建连前预留一个已确认空闲的槽。丢弃守卫后，槽仍计入本次尝试。
#[must_use = "请安装连接或确认该槽为空"]
pub struct Replacement<'pool, T: WireTransport, S = ()> {
    pool: &'pool LocalPool<T, S>,
    id: MaintenanceId,
    completed: bool,
}

struct RetirementStart<'pool, T: WireTransport, S> {
    reservation: Replacement<'pool, T, S>,
    client: Client<T>,
    owner: Option<Waker>,
    replaced: bool,
}

impl<T: WireTransport, S> LocalPool<T, S> {
    #[inline]
    fn return_entry<const READY_ON_WORKER: bool>(
        &self,
        entry: Box<PoolEntry<T, S>>,
        origin: LeaseOrigin,
        hygiene: SessionHygiene,
    ) -> ReleaseOutcome {
        let mut slots = self.slots.borrow_mut();
        slots.leased -= 1;
        let (identity, owner) = entry.client.pool_identity();
        if identity != entry.connection_id {
            slots.quarantined.push(entry);
            return ReleaseOutcome::ConnectionReplaced;
        }
        // 可用区已校验原连接的归属。隔离区可以包含来自其他 worker 的连接。
        let current = READY_ON_WORKER
            || match origin {
                LeaseOrigin::ReadyShared | LeaseOrigin::ReadyExplicit => self.is_current_worker(),
                LeaseOrigin::Quarantine => self.check_or_bind_worker(owner),
            };
        if !current {
            slots.quarantined.push(entry);
            return ReleaseOutcome::WrongRuntime;
        }
        match slots.place_entry(entry, hygiene) {
            Ok(()) => ReleaseOutcome::Returned,
            Err(state) => ReleaseOutcome::Quarantined(state),
        }
    }

    #[cold]
    fn quarantine_abandoned(&self, entry: Box<PoolEntry<T, S>>) {
        let mut slots = self.slots.borrow_mut();
        slots.leased -= 1;
        slots.quarantined.push(entry);
    }

    /// 当前 runtime 能否驱动此池。尚未绑定的池由首次安装连接或启动派发器的 worker 绑定。
    #[inline]
    pub fn is_current_worker(&self) -> bool {
        worker_matches_current(self.owner.get())
    }

    pub(super) fn bind_current_worker(&self) -> bool {
        self.check_or_bind_worker(None)
    }

    /// 记录调用方已验证的 runtime。已绑定的池保持原归属。
    pub(super) fn bind_checked_worker(&self, runtime: &Runtime) {
        self.owner.get_or_init(|| runtime.waker());
    }

    fn check_or_bind_worker(&self, owner: Option<&Waker>) -> bool {
        if let Some(pool) = self.owner.get() {
            return owner.is_none_or(|owner| pool.will_wake(owner))
                && worker_matches_current(Some(pool));
        }
        Runtime::try_with_current(|current| {
            let worker = current.waker();
            owner.is_none_or(|owner| owner.will_wake(&worker)) && self.owner.set(worker).is_ok()
        })
        .unwrap_or(false)
    }

    #[inline]
    pub(super) fn has_ready(&self) -> bool {
        !self.slots.borrow().ready.is_empty()
    }

    /// 查看维护义务，包括已经由等待方接管的操作。
    pub fn pending_maintenance(&self) -> Vec<PendingMaintenance> {
        self.slots
            .borrow()
            .maintenance
            .iter()
            .map(|entry| {
                let (resumable, claimed) = match &entry.state {
                    MaintenanceState::Uncertain => (false, false),
                    MaintenanceState::Retirement(retirement) => (true, retirement.claim.is_some()),
                    MaintenanceState::Reserved => (false, true),
                    MaintenanceState::Polling => (true, true),
                };
                PendingMaintenance {
                    id: entry.id,
                    resumable,
                    claimed,
                }
            })
            .collect()
    }

    /// 已确认某未决槽的全部连接和在途操作结束后归还槽。活跃的预留或可恢复关闭须先处理。
    pub fn confirm_retired(&self, id: MaintenanceId) -> bool {
        self.slots
            .borrow_mut()
            .refund(id, |state| matches!(state, MaintenanceState::Uncertain))
    }

    /// 确认被遗忘的预留没有存活连接或 I/O 后退还槽。独占借用保证此时没有活跃的预留守卫。
    pub fn confirm_abandoned_reservation(&mut self, id: MaintenanceId) -> bool {
        self.slots
            .get_mut()
            .refund(id, |state| matches!(state, MaintenanceState::Reserved))
    }

    /// 撤销等待资格，使另一个等待方可继续同一 I/O。原等待方被唤醒后会获知其资格已撤销。
    pub fn release_retirement_waiter(&self, id: MaintenanceId) -> bool {
        let claim = self.take_retirement_claim(id, None);
        if let Some(claim) = claim {
            if let Some(waker) = claim.waker {
                waker.wake();
            }
            true
        } else {
            false
        }
    }

    fn take_retirement_claim(
        &self,
        id: MaintenanceId,
        expected: Option<MaintenanceId>,
    ) -> Option<RetirementClaim> {
        let mut slots = self.slots.borrow_mut();
        let Some(MaintenanceState::Retirement(retirement)) = slots.maintenance_mut(id) else {
            return None;
        };
        if let Some(expected) = expected {
            if retirement
                .claim
                .as_ref()
                .is_none_or(|claim| claim.id != expected)
            {
                return None;
            }
        } else if !worker_matches_current(retirement.owner.as_ref()) {
            return None;
        }
        retirement.claim.take()
    }

    /// 在所属 runtime 上继续驱动关闭操作。丢弃本次等待不会终止原关闭操作或允许安装替代连接。
    pub async fn resume_retirement(&self, id: MaintenanceId) -> Result<(), Error> {
        let claim = {
            let mut slots = self.slots.borrow_mut();
            let state = slots
                .maintenance_mut(id)
                .ok_or(Error::InvalidInput("pool maintenance identity is missing"))?;
            match state {
                MaintenanceState::Retirement(retirement) => {
                    if !worker_matches_current(retirement.owner.as_ref()) {
                        return Err(Error::InvalidInput(
                            "retirement requires its owning Compio runtime",
                        ));
                    }
                    if retirement.claim.is_some() {
                        return Err(Error::Busy);
                    }
                    let claim = MaintenanceId::allocate()
                        .ok_or(Error::Limit("pool maintenance identities exhausted"))?;
                    retirement.claim = Some(RetirementClaim {
                        id: claim,
                        waker: None,
                    });
                    claim
                }
                MaintenanceState::Polling | MaintenanceState::Reserved => return Err(Error::Busy),
                MaintenanceState::Uncertain => {
                    return Err(Error::InvalidInput(
                        "pool maintenance requires explicit confirmation",
                    ));
                }
            }
        };
        let waiter = RetirementWaiter {
            pool: self,
            id,
            claim,
        };
        poll_fn(|context| waiter.poll(context)).await
    }
}

struct RetirementWaiter<'a, T: WireTransport, S> {
    pool: &'a LocalPool<T, S>,
    id: MaintenanceId,
    claim: MaintenanceId,
}

impl<T: WireTransport, S> RetirementWaiter<'_, T, S> {
    fn poll(&self, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let retirement = {
            let mut slots = self.pool.slots.borrow_mut();
            let state = slots
                .maintenance_mut(self.id)
                .ok_or(Error::InvalidInput("pool maintenance identity is missing"))?;
            let MaintenanceState::Retirement(retirement) = state else {
                return Poll::Ready(Err(Error::Busy));
            };
            if !worker_matches_current(retirement.owner.as_ref()) {
                return Poll::Ready(Err(Error::InvalidInput(
                    "retirement requires its owning Compio runtime",
                )));
            }
            if retirement
                .claim
                .as_ref()
                .is_none_or(|claim| claim.id != self.claim)
            {
                return Poll::Ready(Err(Error::InvalidInput(
                    "the retirement waiter was released",
                )));
            }
            match std::mem::replace(state, MaintenanceState::Polling) {
                MaintenanceState::Retirement(retirement) => retirement,
                previous => {
                    *state = previous;
                    return Poll::Ready(Err(Error::Busy));
                }
            }
        };
        let mut retirement = DropGuard::new(retirement, |retirement| {
            let next = if std::thread::panicking() {
                MaintenanceState::Uncertain
            } else {
                MaintenanceState::Retirement(retirement)
            };
            if let Some(state @ MaintenanceState::Polling) =
                self.pool.slots.borrow_mut().maintenance_mut(self.id)
            {
                *state = next;
            }
        });
        if let Some(claim) = retirement.claim.as_mut()
            && claim
                .waker
                .as_ref()
                .is_none_or(|waker| !waker.will_wake(context.waker()))
        {
            claim.waker = Some(context.waker().clone());
        }
        match retirement.future.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((retired, result)) => {
                let mut slots = self.pool.slots.borrow_mut();
                if retired {
                    if !slots.refund(self.id, |state| matches!(state, MaintenanceState::Polling)) {
                        return Poll::Ready(Err(Error::Broken));
                    }
                } else {
                    *slots.maintenance_mut(self.id).ok_or(Error::Broken)? =
                        MaintenanceState::Uncertain;
                }
                drop(slots);
                drop(DropGuard::dismiss(retirement));
                Poll::Ready(result)
            }
        }
    }
}

impl<T: WireTransport, S> Drop for RetirementWaiter<'_, T, S> {
    fn drop(&mut self) {
        let _ = self.pool.take_retirement_claim(self.id, Some(self.claim));
    }
}

impl<T: WireTransport, S> LocalPool<T, S> {
    /// 建连前预留连接和维护槽的存储。容量或分配失败时返回错误并释放已预留部分。
    pub fn try_new(
        capacity: NonZeroUsize,
        reuse: PoolReuse,
    ) -> Result<Self, std::collections::TryReserveError> {
        let capacity = capacity.get();
        let mut ready = Vec::new();
        ready.try_reserve_exact(capacity)?;
        let mut quarantined = Vec::new();
        quarantined.try_reserve_exact(capacity)?;
        let mut maintenance = Vec::new();
        maintenance.try_reserve_exact(capacity)?;
        Ok(Self {
            owner: OnceCell::new(),
            reuse,
            slots: RefCell::new(Slots {
                ready,
                quarantined,
                leased: 0,
                maintenance,
                vacant: capacity,
            }),
        })
    }

    /// 在所属 worker 上填充空槽。在错误的 worker 调用时，会在预留槽或调用工厂前拒绝。工厂确认失败槽为空后即可重试。
    pub async fn prewarm<E>(
        &mut self,
        mut factory: impl AsyncFnMut() -> Result<PoolEntry<T, S>, PrewarmFailure<E>>,
    ) -> Result<usize, PrewarmError<E>> {
        if !self.is_current_worker() {
            return Err(PrewarmError::WrongRuntime {
                installed: 0,
                pending: None,
            });
        }
        let mut installed = 0;
        while let Some(slot) = self.reserve_replacement() {
            let outcome = super::await_on_worker(std::pin::pin!(factory()))
                .await
                .ok_or_else(|| PrewarmError::WrongRuntime {
                    installed,
                    pending: Some(slot.maintenance_id()),
                })?;
            let entry = match outcome {
                Ok(entry) => entry,
                Err(failure) => {
                    let pending = if matches!(failure, PrewarmFailure::Vacant(_)) {
                        slot.confirm_vacant();
                        None
                    } else {
                        Some(slot.maintenance_id())
                    };
                    return Err(PrewarmError::Factory {
                        installed,
                        failure,
                        pending,
                    });
                }
            };
            match slot.install(entry) {
                InstallOutcome::Installed => installed += 1,
                InstallOutcome::Quarantined(state) => {
                    return Err(PrewarmError::NotProtocolIdle { installed, state });
                }
                InstallOutcome::WrongRuntime => {
                    return Err(PrewarmError::WrongRuntime {
                        installed,
                        pending: None,
                    });
                }
                InstallOutcome::ReservationLost => {
                    return Err(PrewarmError::ReservationLost { installed });
                }
            }
        }
        Ok(installed)
    }

    /// 立即尝试取出连接，无需执行 I/O 或分配。所属 runtime 上无可用项时返回 `Ok(None)`；
    /// 在其他 runtime 上调用返回错误，即使池为空也是如此。
    #[inline]
    pub fn try_acquire(&self) -> Result<Option<Lease<'_, T, S>>, Error> {
        self.try_acquire_when(
            || Error::InvalidInput("checkout requires the owning Compio runtime"),
            || Ok(()),
        )
    }

    /// 检查 worker 和派发条件后取出连接。条件只读派发器状态。
    #[inline]
    pub(super) fn try_acquire_when<E>(
        &self,
        wrong_runtime: impl FnOnce() -> E,
        eligible: impl FnOnce() -> Result<(), E>,
    ) -> Result<Option<Lease<'_, T, S>>, E> {
        if !self.is_current_worker() {
            return Err(wrong_runtime());
        }
        eligible()?;
        Ok(self.pop_ready(&mut self.slots.borrow_mut()))
    }

    #[inline]
    pub(super) fn try_acquire_on_worker(&self) -> Option<(Lease<'_, T, S>, usize)> {
        let mut slots = self.slots.borrow_mut();
        let ready = slots.ready.len();
        Some((self.pop_ready(&mut slots)?, ready))
    }

    #[inline]
    fn pop_ready(&self, slots: &mut Slots<T, S>) -> Option<Lease<'_, T, S>> {
        let entry = slots.ready.pop()?;
        slots.leased += 1;
        let origin = match self.reuse {
            PoolReuse::SharedSession => LeaseOrigin::ReadyShared,
            PoolReuse::VerifyOnRelease => LeaseOrigin::ReadyExplicit,
        };
        Some(Lease::new(self, entry, origin))
    }

    /// 取出属于当前 runtime 的隔离连接，供显式恢复或关闭。
    /// 当前 runtime 无可接管的连接时返回 `Ok(None)`。未进入 Compio runtime 时返回错误。
    pub fn try_acquire_quarantined(&self) -> Result<Option<Lease<'_, T, S>>, Error> {
        Runtime::try_with_current(|current| {
            let mut slots = self.slots.borrow_mut();
            if slots.quarantined.is_empty() {
                return None;
            }
            let worker = current.waker();
            let index = slots.quarantined.iter().rposition(|entry| {
                entry
                    .client
                    .pool_identity()
                    .1
                    .or(self.owner.get())
                    .is_none_or(|owner| owner.will_wake(&worker))
            })?;
            let entry = slots.quarantined.swap_remove(index);
            slots.leased += 1;
            Some(Lease::new(self, entry, LeaseOrigin::Quarantine))
        })
        .map_err(|_| Error::InvalidInput("quarantine checkout requires a current Compio runtime"))
    }

    /// 为一次尚未开始的建连尝试预留容量。
    /// 预留只记账，可在进入 Compio runtime 之前执行；安装连接时校验所属 runtime。
    pub fn reserve_replacement(&self) -> Option<Replacement<'_, T, S>> {
        let mut slots = self.slots.borrow_mut();
        if slots.vacant == 0 {
            return None;
        }
        let id = MaintenanceId::allocate()?;
        slots.vacant -= 1;
        slots.maintenance.push(MaintenanceEntry {
            id,
            state: MaintenanceState::Reserved,
        });
        Some(Replacement {
            pool: self,
            id,
            completed: false,
        })
    }

    pub fn occupancy(&self) -> Occupancy {
        let slots = self.slots.borrow();
        Occupancy {
            ready: slots.ready.len(),
            leased: slots.leased,
            quarantined: slots.quarantined.len(),
            maintenance: slots.maintenance.len(),
            vacant: slots.vacant,
        }
    }
}

impl<'pool, T: WireTransport, S> Lease<'pool, T, S> {
    /// 同时借用原连接及其预备状态，调用期间应就地使用连接。替换连接会导致隔离，关闭替代项后也不会自动退还原连接的槽。
    #[inline]
    pub fn client_and_state(&mut self) -> (&mut Client<T>, &mut S) {
        let entry = &mut self.guard.entry;
        (&mut entry.client, &mut entry.state)
    }

    /// 调用方确认会话状态且协议空闲时归还到可用区。普通租借不会取出隔离项。归还操作不执行排空、重置或重连。
    #[inline]
    pub fn release(self, hygiene: SessionHygiene) -> ReleaseOutcome {
        self.release_inner::<false>(hygiene)
    }

    /// 此租约来自可用区，且派发器已在当前轮询验证所属 worker。
    #[inline]
    pub(super) fn release_ready_on_worker(self, hygiene: SessionHygiene) -> ReleaseOutcome {
        self.release_inner::<true>(hygiene)
    }

    #[inline]
    fn release_inner<const READY_ON_WORKER: bool>(self, hygiene: SessionHygiene) -> ReleaseOutcome {
        let LeasedEntry {
            pool,
            entry,
            origin,
        } = DropGuard::dismiss(self.guard);
        pool.return_entry::<READY_ON_WORKER>(entry, origin, hygiene)
    }

    /// 关闭连接，本地套接字确认关闭后才释放容量。
    pub fn close(self) -> impl Future<Output = Result<(), Error>>
    where
        T: 'static,
    {
        self.retire_with(|client, replaced| async move {
            let result = client.close_local().await;
            finish_retirement(replaced, result.is_ok(), result)
        })
    }

    /// 通过独立通道请求取消，并永久放弃本次借用。SQL 最终结果须另行确认。关闭失败或等待中止时槽继续计入维护义务；
    /// 丢弃等待方后可继续原关闭操作。
    /// [`Error::CancelRequest`] 表示取消通道失败但本地已关闭，[`Error::CancelRetirement`] 表示本地关闭尚未确认。
    pub fn request_cancel_and_discard(self) -> impl Future<Output = Result<(), Error>>
    where
        T: 'static,
    {
        self.retire_with(|client, replaced| async move {
            match client.into_expert().cancel_and_retire().await {
                Ok(outcome) => {
                    finish_retirement(replaced, outcome.retirement.is_ok(), outcome.into_result())
                }
                Err(error) => (false, Err(error)),
            }
        })
    }

    fn retire_with<F>(
        mut self,
        retire: impl FnOnce(Client<T>, bool) -> F,
    ) -> impl Future<Output = Result<(), Error>>
    where
        F: Future<Output = (bool, Result<(), Error>)> + 'static,
    {
        // 发起关闭即放弃普通租借。等待方从未被轮询时，原连接仍须隔离。
        self.require_explicit_release();
        async move {
            let RetirementStart {
                reservation,
                client,
                owner,
                replaced,
            } = self.take_for_retirement()?;
            let id = reservation.maintenance_id();
            let pool = reservation.pool;
            reservation.retain_retirement(owner, Box::pin(retire(client, replaced)))?;
            pool.resume_retirement(id).await
        }
    }

    fn take_for_retirement(self) -> Result<RetirementStart<'pool, T, S>, Error> {
        let entry = &self.guard.entry;
        let (id, owner) = entry.client.pool_identity();
        let owner = owner.or(self.guard.pool.owner.get()).cloned();
        if !worker_matches_current(owner.as_ref()) {
            return Err(Error::InvalidInput(
                "retirement requires its owning Compio runtime",
            ));
        }
        let replaced = id != entry.connection_id;
        let id = MaintenanceId::allocate()
            .ok_or(Error::Limit("pool maintenance identities exhausted"))?;
        let LeasedEntry { pool, entry, .. } = DropGuard::dismiss(self.guard);
        {
            let mut slots = pool.slots.borrow_mut();
            slots.leased -= 1;
            slots.maintenance.push(MaintenanceEntry {
                id,
                state: MaintenanceState::Reserved,
            });
        }
        let slot = Replacement {
            pool,
            id,
            completed: false,
        };
        Ok(RetirementStart {
            reservation: slot,
            client: entry.client,
            owner,
            replaced,
        })
    }
}

fn finish_retirement(
    replaced: bool,
    retired: bool,
    result: Result<(), Error>,
) -> (bool, Result<(), Error>) {
    if replaced {
        let original = Error::InvalidInput("the original pooled connection was replaced");
        let error = match result {
            Ok(()) => original,
            Err(cleanup) => Error::Cleanup {
                primary: Box::new(original),
                cleanup: Box::new(cleanup),
            },
        };
        (false, Err(error))
    } else {
        (retired, result)
    }
}

impl<'pool, T: WireTransport, S> Lease<'pool, T, S> {
    fn new(pool: &'pool LocalPool<T, S>, entry: Box<PoolEntry<T, S>>, origin: LeaseOrigin) -> Self {
        Self {
            guard: DropGuard::new(
                LeasedEntry {
                    pool,
                    entry,
                    origin,
                },
                |lease| {
                    if lease.origin == LeaseOrigin::ReadyShared && !std::thread::panicking() {
                        let _ = lease.pool.return_entry::<false>(
                            lease.entry,
                            lease.origin,
                            SessionHygiene::Verified,
                        );
                    } else {
                        lease.pool.quarantine_abandoned(lease.entry);
                    }
                },
            ),
        }
    }

    pub(super) fn require_explicit_release(&mut self) {
        if self.guard.origin == LeaseOrigin::ReadyShared {
            self.guard.origin = LeaseOrigin::ReadyExplicit;
        }
    }
}

impl<T: WireTransport, S> Replacement<'_, T, S> {
    pub fn maintenance_id(&self) -> MaintenanceId {
        self.id
    }

    /// 安装已预热且会话状态已就绪的连接；池会先检查协议是否空闲。
    pub fn install(mut self, entry: PoolEntry<T, S>) -> InstallOutcome {
        let mut slots = self.pool.slots.borrow_mut();
        if !slots.remove_maintenance(self.id, |state| matches!(state, MaintenanceState::Reserved)) {
            return InstallOutcome::ReservationLost;
        }
        self.completed = true;
        let entry = Box::new(entry);
        if !self
            .pool
            .check_or_bind_worker(entry.client.pool_identity().1)
        {
            slots.quarantined.push(entry);
            return InstallOutcome::WrongRuntime;
        }
        match slots.place_entry(entry, SessionHygiene::Verified) {
            Ok(()) => InstallOutcome::Installed,
            Err(state) => InstallOutcome::Quarantined(state),
        }
    }

    /// 确认没有存活的替代连接或在途 I/O 后，归还本次预留。
    pub fn confirm_vacant(mut self) {
        self.pool
            .slots
            .borrow_mut()
            .refund(self.id, |state| matches!(state, MaintenanceState::Reserved));
        self.completed = true;
    }

    fn retain_retirement(
        mut self,
        owner: Option<Waker>,
        future: RetirementFuture,
    ) -> Result<(), Error> {
        *self
            .pool
            .slots
            .borrow_mut()
            .maintenance_mut(self.id)
            .ok_or(Error::Broken)? = MaintenanceState::Retirement(RetainedRetirement {
            owner,
            future,
            claim: None,
        });
        self.completed = true;
        Ok(())
    }
}

impl<T: WireTransport, S> Drop for Replacement<'_, T, S> {
    fn drop(&mut self) {
        if !self.completed
            && let Some(state @ MaintenanceState::Reserved) =
                self.pool.slots.borrow_mut().maintenance_mut(self.id)
        {
            *state = MaintenanceState::Uncertain;
        }
    }
}
