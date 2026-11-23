# 连接池与派发

启用 `service` 可在应用所属的 Compio worker 上预热连接、复用预备语句并按容量派发工作。
持有连接的任务可直接查询，需要共享热连接时用本地池租借。自建池可使用同一套 `Client`、语句和连接复用状态。
连接忙时，应用可以自行决定限流、在当前 worker 排队，或显式使用派发器。

## 预热和归还

用 `LocalPool::try_new` 指定容量和会话策略，再用 `prewarm` 建连、准备语句，将两者放入 `PoolEntry`。
首次安装所属连接或启动派发驱动时，池绑定当前 runtime。
`try_acquire` 优先租借最近归还的空闲连接，整个租借过程不分配内存或提交 I/O。
所属 runtime 上的空池立即返回 `Ok(None)`。池绑定后，从其他 runtime 租借会返回错误。

SCRAM 建连时，口令派生在当前 worker 同步执行。对前台延迟敏感的服务可以在接纳请求前预热连接，并限制运行期间同时补建的连接数。复用已经认证的连接不再执行这一步。

| 策略 | 租约结束时的处理 |
| --- | --- |
| `PoolReuse::SharedSession` | 适用于共享数据库角色和会话设置的请求。普通租约释放时检查连接身份、所属 runtime 和协议状态，符合要求便归还。 |
| `PoolReuse::VerifyOnRelease` | 调用方检查角色、临时对象等应用状态后，以 `SessionHygiene::Verified` 明确归还。未验证的租约进入隔离。 |

两种策略都可显式隔离连接。连接被替换、事务未结束、协议有待处理工作，或租约在 panic 展开期间释放时，池会隔离该连接。
显式归还的 `ReleaseOutcome::Returned` 表示该连接已经可以再次租借。
`reset_session` 执行 `DISCARD ALL`，清理后须重新准备会话语句。估算连接数时，把等候提交和归还的时间计入平均租期。

## 直发、排队与调度

`LocalDispatcher::try_new` 接管预热池，通过 `DispatchOperation` 逐项执行直接和排队请求。
要合并积压请求，另实现 `BatchDispatchOperation` 并用 `LocalDispatcher::try_new_batched` 显式指定每批最多可以接纳多少成员。
在池所属 runtime 轮询 `run_scanned`，或通过 `spawn_scanned`、`spawn_ready` 启动本地驱动任务。
两个 `spawn` 入口在返回任务句柄时已开始接纳，可紧接着等待 `submit_queued`。手动驱动从首次轮询开始接纳。
驱动也可在池尚未接纳连接时绑定其 runtime。同一派发器一次只接受一个驱动。
保留任务句柄至停机完成。丢弃仍在运行的句柄会取消任务，退还尚未选中的请求。
启动时为当前可租借的连接预分配作业槽。可先预热池，也可在启动驱动前用派发器的 `try_replace` 填充空槽。

- `try_submit_inline` 在有空闲连接且队列为空时直接借用连接，在所属 worker 的提交者上下文中执行单个请求。选中前被拒绝时可取回原请求。已挂起的请求在其他 runtime 恢复时返回 `WrongRuntimeAfterSelection`，租约进入隔离区，SQL 可能已经执行。
- `submit_queued` 将请求排入有界 FIFO。等待槽或回复槽已满时，可以从错误中取回未选中的请求。
  若等待方在其他 runtime 恢复，未选中的请求会撤回并退还等待额度。已选中的请求由原 worker 继续执行，等待方收到 `WrongRuntimeAfterSelection`。
- `run_scanned` 和 `spawn_scanned` 使用驱动的同一个唤醒器。若有 A 个活跃作业、每轮工作预算为 Q，一轮最多扫描每个挂起作业一次，调度开销为 O(A + Q)。已轮询的作业在本轮结束后批量接回队尾，无需搬移作业或队列元素。
- `spawn_ready` 适合挂起作业多且同时就绪作业少的情况。每个执行槽保留独立的唤醒目标，合并重复唤醒，旧作业的通知不会传给复用同一槽的新作业。任意线程可通过唤醒器提交就绪通知，回调始终在连接所属 worker 执行。每次返回 Pending 的作业轮询计一单位。

队列驱动的接纳、完成和停机退回各按请求数计费，每轮合计不超过 Q。
接纳批次时用剩余额度限制成员数，轮询既有作业前也要留足整批完成的额度。
余额不足时，作业保留在队首，驱动让出 worker 后再继续。
接纳用尽一轮额度时，驱动在下一轮先推进已选作业，避免连接较多时推迟 SQL 发起。
Q 为 1 时逐项派发。希望一轮接纳并轮询 N 项短请求时，至少预留 2N 单位。
直接提交、应用回调自身的工作量和任务析构分别计算。

需要取消本地 I/O 时，在单项或单批回调内使用 Compio 的取消令牌。
令牌保留 I/O 注册直至取消或释放，生命周期应覆盖一次有界操作。
数据库取消使用独立的 PostgreSQL 协议操作。
在 Linux 上，如需让驱动使用已在当前 io_uring 注册的操作身份，请引入 `expert::linux::DispatcherExt`，显式调用 `spawn_scanned_with_personality` 或 `spawn_ready_with_personality`，并在驱动结束后再注销该身份。

| 限额 | 所限制的资源 |
| --- | --- |
| `queue` | 等待队列中的请求数和应用定义的计费字节数，开始派发即退回等待额度。 |
| `max_reply_slots` | 等待、执行中和已完成但尚未领取的回复。等待队列大小为零时无需预留回复槽。 |
| `try_new_batched` 的 `max_batch_requests` | 一次交给 `execute_batch` 的成员数。若在回调中提交一个 SQL 批次，须为它配置足够的 `BatchOptions::max_requests`。 |
| `max_work_per_turn` | 上述各驱动模式的一轮工作预算。查询和批次另有各自的协议调度额度。 |

积压按 FIFO 派给可用连接，跨连接的完成顺序由数据库决定。单项调用 `execute_one`，多项调用 `execute_batch`。
`batch.requests()` 按批次顺序借用尚在槽内的请求，并返回各自的原始槽位索引。
需要取得请求所有权时，调用 `batch.take_request(index)`。每项只能取出一次，取出后迭代会跳过该项，其余槽位索引保持原值。
`stage_reply` 暂存已确认成员的回复，回调结束且租约完成复用检查后才交付。
回复已取出或重排的请求时，仍使用其原始槽位索引。单项和批次应执行相同的业务校验。

等待者丢弃尚未选中的请求时，派发器按槽位在 O(1) 时间内撤回并归还额度。已选中的工作继续执行，放弃接收结果不会回滚 SQL。
应用可在派发回调开始 SQL 前按单调时钟拒绝超期请求。
已发出 SQL 的连接由执行方决定继续等待、恢复协议或请求取消。等待回复的任务可以放弃接收结果。
自建派发器可通过 `BoundedFifo` 使用预分配的环形等待队列，同时限制项数和字节数。

## 隔离、维护与停机

用 `try_acquire_quarantined` 或派发器的 `maintain_one` 接管隔离连接，在所属 runtime 恢复或关闭。
`try_acquire_quarantined` 在进入 Compio runtime 后，只筛选属于该 runtime 的连接。没有可接管的连接时返回 `Ok(None)`。
确认连接和在途 I/O 已释放后才退还槽位。`PrewarmFailure::Vacant` 释放预占，`Uncertain` 保留维护编号。
用 `pending_maintenance` 查看维护编号，用 `resume_retirement` 继续已保存的关闭操作，或在独立确认关闭后调用 `confirm_retired`。
`try_replace` 先预占空槽，再调用连接工厂。自行维护池时，`reserve_replacement` 可在进入 runtime 前预占容量，安装连接时再验证归属。
独立安装返回 `InstallOutcome`。`try_replace` 成功完成工厂调用后返回 `Ok(InstallOutcome)`，失败时返回 `DispatchReplaceError`。
`InstallOutcome::Installed` 表示连接可以租借。协议尚未空闲或 worker 归属不符时，连接留在隔离区。

等待维护租约、执行修复回调和轮询建连工厂都在发起操作的 worker 上继续。
跨 runtime 恢复会返回 `WrongRuntime`。
维护等待者会释放等待资格，回调仍持有的租约归入隔离区。
若 `prewarm` 或 `try_replace` 已预留连接槽，错误中的 `pending` 给出仍待确认的维护编号。
停机也保留这项义务。

取消送达与本地连接关闭分别判断。
`Error::CancelRequest` 表示取消路由失败但原连接已确认关闭。
`Error::CancelRetirement` 表示原连接是否关闭仍待确认。
正常停机先调用 `close_intake()` 停止接纳。驱动在每轮额度内按原值退回未选请求，并继续推进已选作业。
可用 `drain_unselected(limit)` 立即退回指定数量以内的未选请求，例如应用尚未安排驱动再次轮询时。
等待驱动结束后，释放其余派发器引用，用 `into_pool()` 取回连接池，再完成应用启动的维护和关闭操作。
若主动丢弃驱动，已选等待方收到 `Unresolved`，放弃的租约进入隔离区，SQL 结果须由应用确认。
