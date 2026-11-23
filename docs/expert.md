# 协议与传输

普通服务通过 `Client` 在创建连接的 Compio worker 上执行请求。
需要自行管理协议预算、借用接收缓冲区、改变同步边界或保留固定请求报文时，使用 `client.expert()` 访问同一会话。
预备语句、事务、取消句柄和接收缓冲均属于这条连接。
也可用 `expert::TcpSession`、`expert::UnixSession` 或 `expert::TlsSession` 直接建立专家会话。
连接和专家会话共用根命名空间下的配置、结果和错误类型，参数和编解码使用 `types`。
`expert::protocol` 提供原始 3.2 帧的解析与启动、取消报文编码。生成启动包时须指定字节限额。

## 选择同步边界

PostgreSQL 在一条连接上顺序处理请求。流水线可以在等待前项结果时发送后项，多个数据库后端同时执行 SQL 则需要多条连接。

| 操作 | 何时接纳与交付 |
| --- | --- |
| `query`、`one_shot` | 每项一个 Sync。借用行可以先于 Ready 返回。一次性查询替换未命名语句，结果形状错误可能在执行后才能发现。 |
| `query_simple_single` | 直接发送一条可信 SQL；列格式以服务端 RowDescription 为准。调用方负责单语句约束。 |
| `query_pipeline`、`query_pipeline_visit` | 发送前校验全部输入，每项独立 Sync。前者返回可持有的结果，后者在每项 Ready 后借出可复用的结果存储。 |
| `query_window` | 增量接纳，每项独立 Sync。在指定的输入前缀内执行。Ready 回调返回 Break 后停止接纳和回调，并排空已接纳工作。回调返回错误时使用显式的 `OnError`。 |
| `query_window_provisional_visit`、`query_window_provisional_consume` | 每项独立 Sync。回调直接借用接收数据，行和命令可以提前可见，成员结果由其 Ready 确认。 |
| `query_group_provisional_*`、`query_groups_provisional_*` | 整组共用一个 Sync，改变隐式事务和错误传播边界。此前交付的行或命令可能受后续失败影响。 |
| `prepare_pipeline`、`close_prepared_pipeline`、`close_all_statements_pipeline` | 每项独立 Sync。某项失败时后续已发送成员仍可能执行。 |

`query`、`one_shot` 和 `query_simple_single` 在会话和事务上都接收 `QueryOptions` 及 `AbandonPolicy`。
逐行读取的本地错误保留协议进度，放弃时按所选策略处置。收集或回调终端执行自己的 `OnError` 策略。

准备和关闭批次共用 `StatementPipelineLimits`。
逐包关闭仍由会话持有的语句时，`close_all_statements` 也要求显式传入限额。
该入口按包限制成员数、编码字节和诊断空间，在首个 SQL 错误后确认同包剩余结果，并跨包保留调度额度。
固定流水线和增量窗口的 Ready 回调共用 crate 根的 `ReadyBatchEvent` 及 `ReadyBatchResult`。

显式事务还须确认 COMMIT。
原始 SQL 返回的 ROLLBACK 命令标签也可能来自回滚到保存点。
Ready 为 Idle 时记录事务结束，仍处于事务中则保留事务守卫。
应用可用 `rollback_to_savepoint` 或 `rollback_and_chain` 明确表达两种操作。

## 窗口、预算与借用

`WireLimits::short_queries()` 为明文连接预留 8 KiB 初始接收区。
帧长度上限为 65,535 字节，含四字节长度、不含一字节标签。
请求上限为 64 KiB，每个请求或独立 Sync 成员最多 1,024 个控制帧。
控制帧预算不含 DataRow 和 CopyData。
查询另计结果行数和字节数。
`ClientOptions::short_queries` 的单查询限额为 256 行、256 KiB 结果及 16 KiB 元数据，每 128 个工作单位协作让出。
16 个语句槽共享 64 KiB 元数据。
明文接收区在读到合法的大帧头后才扩容，逻辑上限取 `receive_capacity` 与 `max_frame_len + 1` 中较大者。
扩容在上限内预留容量余量，延后初始化余量；逐渐变大的帧可复用已分配的存储。
常见短响应可保持较小的接收区，频繁读取大帧的连接可预设较大的 `receive_capacity`。
TLS 的跨块帧头用五字节定长存储补齐。
完整帧和位于单个明文块内的帧体可以直接借用，空帧体无需分配。
帧体跨块时才准备拼接缓冲，逻辑上限为 `max_frame_len - 4`。
搬移扩容时可能短暂同时持有两块缓冲，分配器的容量取整也单独计算。

普通批次的 `max_requests` 是整批硬上限，`max_inflight` 限制已经接纳且仍在等待确认的成员数，`max_queued_request_bytes` 限制排队发送的字节数。
已知长度下界超限时，首项发送前就会失败。
未知长度的输入在已接纳前缀完成后再探测一项。
超出的一项计入 `consumed`，不会发送。
`admitted` 统计已交给传输的成员，`confirmed` 统计收到 Ready 的成员。
要保留下一批的首项，请传入 `iter.by_ref().take(n)`，并使 `n <= max_requests`。

独立 Sync 的流水线用有界环保存按序确认的在途描述符，单成员使用内联槽。
发送缓冲分别容纳当前在途包和下一个待发包。连续包可直接交给 Compio，响应也可在连续接收缓冲内借用。
将请求和响应字节各放入一个环会让跨环尾的包变成两段，增加分片发送或拼接的处理。
持续输出场景可独立评估内核提供缓冲区和多次完成接收，比较提交数、槽位占用和跨缓冲区拼接量。

批量准备和关闭使用各自限额中的 `ExecutionScheduling`，协作额度由 `NonZeroUsize` 保证为正。
协作模式在整个批次共用工作额度，编码完成的整包和每个响应帧分别按每 KiB 向上取整计量。
放弃等待或重建等待方时，显式恢复沿用同一额度。

借用窗口的 `visit` 在交付前验证整行。
`consume` 逐字段验证，回调可能已观察到合法前缀，随后才遇到无效字段。
驱动也会校验未读字段。
提前观察的结果由应用负责，回调应尽快返回。
需要跨回调保存的数据须显式复制。

| `BatchControl` | 对剩余工作的影响 |
| --- | --- |
| `Continue` | 继续接纳和交付。 |
| `StopAdmission` | 停止接纳，继续交付并排空已接纳的成员。 |
| `Abort` | 停止回调，按所选中止策略处置连接；检查进度中的 `aborted` 和 `sql_errors`。 |

动态组窗口分别限制组数、请求数和在途组数。
在途、待发和私有预读包按实际编码量增长，每个包的容量受 `max_packet_bytes` 限制。
`max_rows` 累计本次调用的行数。
`max_member_result_bytes` 约束单个成员的结果行字节数，也约束单份数据库诊断的存储。
空组也占一个输入名额，检测超限可再读取一项。
后组可能在前组 Ready 前已接纳。
第一次向传输提交后，出错、放弃等待或回调 panic 时须丢弃连接。
需要跨组原子性时使用显式事务。

单组、动态组窗口和冻结重放失败时均返回 `GroupPipelineError`。
`source` 保留原错误，`progress` 同时记录组数和组内请求数。

| 进度字段 | 统计边界 |
| --- | --- |
| `admitted_groups`、`admitted_requests` | 整组报文已交给传输，包括仍在本地排队发送的组。 |
| `ready_groups`、`ready_requests` | 已处理通过协议状态检查的该组 ReadyForQuery。 |
| `last_ready_transaction_status` | 最后一条计入进度的 Ready 事务状态，首组确认前为 `None`。 |

读到 SQL 错误即返回，进度停在此前处理的 Ready。
例如，第一组写入在隐式事务中成功提交，第二组返回 SQL 错误时，进度可报告接纳两组、确认一组。
已接纳但未确认的组可能已经执行。重试前按业务键查明结果，或由业务提供幂等键。
显式事务内的组仍以最终 COMMIT 确认提交。

`FrozenEncodedGroup` 将固定参数、格式、成员限额和报文绑定到原连接及其语句，适用于重复执行完全相同的组。成功后可取回重放句柄。

## 结果存储与错误

`RowLease` 借用当前帧，释放后才能接收下一行。
`RowDecoder` 支持顺序解码和跳过字段。
`RowLayout::columns()` 按结果顺序迭代借用的 `ColumnRef`，`RowLayout::column(index)` 按从零开始的序号取得一列。
各列共享一块名称存储，列槽、列名和逐列格式计入布局的元数据限额。
要长期保留单行，可将 `row.view()` 与 `row.share_layout()` 交给 `OwnedRow::copy_from`。
整批持有结果时，`Grow` 按需增长，`ReserveLimit` 按限额预留，`collect_into` 复用匹配布局的存储。
固定容量的标量输出按输入迭代器的长度上界留足空位，最多使用批次的 `max_requests`。
迭代器没有长度上界时，按 `max_requests` 预留。
无行、SQL NULL 和 SQL 错误各有独立表示。

准备语句时，仍有句柄或结果引用的布局占用元数据预算。
普通 prepare 收到的实际元数据超限或列数与指定格式数不符时，会有界排空并关闭本次新建的语句。
清理也失败时，`Error::Cleanup` 保留两次错误。
清理期间放弃等待，应按 `reuse_state()` 处理连接和未交付的语句。

数据库诊断通过 `code()`、`message()` 和 `fields()` 读取，批次限额包括诊断结构和字段内容。
普通 SQL 错误需等到该成员 Ready 才计入已确认结果。
致命错误、协议损坏或传输失败时禁止复用。
显式恢复只排空已接纳的工作。
批次自动清理的累计额度由尚未收到 Ready 的已接纳成员决定，详见[错误与恢复](../README.md#错误中止与恢复)。
持有事务时可在原守卫上恢复，再根据 `transaction_status()` 继续查询或回滚。
放弃守卫后可在会话上调用 `recover_and_rollback()`。

取消通过独立连接沿原安全路由发送，送达后仍须确认原 SQL 的最终结果。
并发驱动原查询时，通过取消句柄调用 `request_cancel_and_invalidate` 禁止原连接复用，原套接字由会话持有者关闭。
持有整个连接时，可调用 `request_cancel_and_discard` 发送取消并等待原套接字释放。

COPY IN 的 `send_batch` 先校验每个 CopyData 帧，`send_owned` 在本地发送完成后返还缓冲区。
生产者可以用 `CopyDataBuffer::resize_payload` 取得有界的已初始化写入空间，直接填充待发送的载荷。
回收后需要覆盖等长载荷时，用 `payload_mut` 修改同一缓冲。
放弃已经交给传输的发送等待后，继续发送会返回 `Busy`。
用 `finish` 等待整个 COPY 完成，或用 `fail` 拒绝输入。
收到取消诊断及 Ready 后返回 `CopyAbort::Aborted`，应用可检查诊断和事务状态。
如果已经送出 CopyDone 且服务端确认完成，`fail` 返回 `AlreadyCompleted`。
COPY OUT 按协议帧交付字节。PostgreSQL 19 通常按行发送，输出还可能包含格式相关的头部或尾部，应用按实际格式解析。
`CopyInput` 和 `CopyOutput` 的 `info()` 共用同一列格式表示，相同格式的列共享一个值。
同步处理载荷可用 `visit_provisional`，在首次取得帧时直接借用暂定数据，并由终端确认命令完成和 Ready。
需要在调用方持有借用时使用 `next_chunk`，释放该借用后再读取下一帧。
需要一次取得全部载荷时，使用 `collect_ready` 并选择输出限额和错误策略。
TLS 上，`collect_ready` 按整个 CopyData 帧检查输出限额，再把明文片段直接写入结果。
`finish` 和 `finish_abandoned_copy_out` 逐块消费未读载荷。
这两个终端路径都跳过跨记录帧体的拼接。按帧借用的入口仍返回连续切片。
专家 `CopyProtocol::SimpleSingle` 要求可信的单条 COPY 语句和空参数。

从连接或事务开启 COPY IN 后，在 `CopyInput` 上选择输入方式。
`send_stream` 可以读取借用的字节块，并在协议发送缓冲中编码。
持有已编码的 `CopyDataBuffer` 时用 `send_owned_stream` 直接发送，最近完成的包可供结束帧复用。
`send_owned_stream_recycling` 在本地发送并刷新后将原包交给回调。
三种输入方式都要求指定总块数、载荷字节限额和本地失败的处置方式。
空块计入总块数，超限项可能已从输入流取出。
选择 `DrainToReady` 会发送 CopyFail 并等待 Ready，清理失败会保留原错误和清理错误。
选择 `RecoverExplicitly` 后可在同一会话或事务上调用 `fail_abandoned_copy`。
选择 `Discard` 会禁止复用。
显式事务进入失败状态后仍须回滚。

## 传输与运行时

通过 `startup_parameter` 可在启动包设置会话参数。
应用通过 `notice_handler` 同步观察服务器通知消息（NOTICE），回调须在 worker 上快速返回。
显式恢复期间会静默排空。
订阅数据库事件时，通过 `into_listener(scheduling)` 交出连接并选择调度方式。
随后用 `listen`、`unlisten` 和 `next_notification` 管理 LISTEN/NOTIFY。
协作模式下，订阅请求、响应和通知按编码字节数扣同一额度。

普通 TCP 及 TLS 入口在 Linux、Windows 和 macOS 上一致。
Unix socket 接受绝对套接字文件路径。
TCP 连接可选 `TcpNoDelay`。
TLS 要求可信 CA 和服务端名称，mTLS 还需叶证书在前的证书链及匹配的私钥。
TLS 协商、版本、会话恢复和发送限额均由 `TlsOptions` 指定。
启用会话恢复时，同一配置的克隆共享指定服务端的缓存。更换客户端身份会创建独立缓存。

Linux 专属控制位于 `compio_postgres::expert::linux`。
明文连接可显式选择 `TcpReadinessConnection` 或 `UnixReadinessConnection`。
`TcpOptionsExt::with_receive_buffer` 在 TCP 握手前请求内核接收缓冲大小，影响窗口缩放和自动调优。
内核可能限幅，并对缓冲区加倍记账。
专家 TCP 会话的 `TcpSessionExt::tcp_receive_buffer_snapshot` 返回请求值和 TCP 握手完成后的实际读回值。
系统管理模式跳过设置和读回。此选项独立于应用协议接收区，也不适用于 Unix socket。

本指南的原生传输指 Compio 完成式收发。
它把连接已有的共享 socket 描述符和缓冲区交给 Compio 的 `Send`、`Recv` 操作，由所属 runtime 提交，并在操作完成后收回缓冲。
发送缓冲可跨查询复用，借用行直接引用接收区。
Compio 为每次原生 I/O 提交分配一个操作节点，重复轮询同一操作会复用该节点。
短写或分段接收可能需要多次提交。批量提交给内核时，节点仍按操作数分配。
[Compio 驱动节点实现](https://github.com/compio-rs/compio/blob/v0.19.2/compio-driver/src/key.rs)
Linux 显式就绪式传输及 Unix 上的 TLS 适配先尝试非阻塞系统读写，遇到 WouldBlock 才通过 Compio 的 `PollFd` 等待。
挂起后先收回原就绪注册，再重试操作。
Windows TLS 在连接内复用密文缓冲，直接轮询 Compio 的完成式读写操作。
TLS 诊断计数记录直接借用的整帧或帧体字节，以及传输层实际复制的分片帧头和拼接帧体。
直接写入 COPY OUT 收集结果的字节计入 COPY OUT 载荷复制量。
选择流水线可以将部分 I/O 成本摊到多个已接纳的成员。

`SendPolicy::BeforeBufferedRead` 先推进当前发送。
`CoalesceBuffered` 可在已有完整有效响应时推迟后续待发包，减少小包发送。
更换策略或调用 `trim_send_buffer` 需要连接处于协议边界且本地发送已完成。
策略属于连接，事务结束或归池后仍然生效。

查询与 COPY 的协作调度按工作额度在检查点让出 worker。
同步回调和正在编码的单个操作仍会占用该线程。
应用负责创建 runtime、选择内核驱动和 CPU 放置，内核 I/O 的提交时机由 compio 管理。
归属检查使用 Compio 的 runtime 唤醒器和 Rust 的 `Waker::will_wake`。
只有能够确认是同一唤醒目标时，连接才允许继续驱动已绑定的 I/O。
Rust 的唤醒器比较可以在目标相同的情况下返回失败，因此未知结果一律拒绝。
停止服务时，先关闭接纳，再等待已选工作、事务处置和连接关闭，最后释放 runtime。

## 窗口发送缓存

启用 `window-cache` 特性后，通过 `client.expert().set_window_send_cache` 选择 `expert::WindowSendCache`，控制批次之间保留的发送缓冲。
独立 Sync 的窗口在待发缓冲中编码，按实际报文增长。
`max_queued_request_bytes` 是上限。
已经发送前缀后若扩容失败，按返回的批次进度处理。

| 缓存策略 | 释放时机 |
| --- | --- |
| `ReleaseOnOrdinarySend`（默认） | 切换到普通发送时释放空闲窗口缓冲。 |
| `ReleaseAfterWindow` | 窗口结束即释放。 |
| `RetainUntilTrim { max_retained_bytes }` | 在指定字节数内保留空闲缓冲，后续窗口可以复用；显式裁剪可提前释放。 |
