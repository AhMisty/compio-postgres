# Worker 查询和事务基准

在专用 PostgreSQL 19 测试数据库上运行。
默认负载在同一个 Compio runtime 上使用前台和后台两条长连接，并发短查询比较使用八条长连接。
各模式另用一条连接在计时区间外准备和清理数据。Linux 上校验实际使用的后端为 io_uring。

账户需要在测试数据库中创建 schema 的权限，并使用 SCRAM 密码认证。
设置 `CPG_DATABASE`、`CPG_USER` 和 `CPG_PASSWORD`。
使用 TCP 或 TLS 时，另设 `CPG_HOST` 和 `CPG_PORT`。明文 TCP 适用于可信测试网络。
使用 TLS 时追加 `CPG_TLS_SERVER_NAME` 和 `CPG_TLS_CA_PEM`，分别为证书的验证名称和 CA PEM 路径。
如果服务器要求客户端证书，同时提供 `CPG_TLS_CLIENT_CERT_PEM` 和 `CPG_TLS_CLIENT_KEY_PEM`。
使用 Unix 套接字时，在数据库所在主机设置绝对路径 `CPG_UNIX_PATH`。

```sh
cargo bench --locked --bench service_workload -- tcp
cargo bench --locked --bench service_workload -- tls
cargo bench --locked --bench service_workload -- unix
```

每次运行在同一事务中创建独有 schema、建表并填充数据。`items` 保存 5,000 行带主键的多列数据，`writes` 是单行计数器，两张表都写 WAL。
各模式均设置 `synchronous_commit=on`。包含事务提交测量的 `direct` 模式还会检查服务端已开启 `fsync`。
正常结束或负载返回错误后，控制连接用单独的事务删除本次创建的两张表，并以 `RESTRICT` 删除空 schema。
进程被强制终止或控制连接中断时，按 stderr 的 schema 名检查数据库。创建同名 schema 会失败。

| CSV 行 | 操作与计时边界 |
| --- | --- |
| `detail` | 预热后按主键执行 5,000 次查询，逐行解码整数、文本、布尔值和大整数。延迟包括发送至 Ready 确认。 |
| `commit` | 500 个独立短事务，每次 BEGIN、UPDATE RETURNING、COMMIT。记录事务完整完成所用时间。 |
| `batch` | 512 组流水线，每组 32 条主键查询，最多 16 条在途。每条有独立 Sync，吞吐按已确认的成员数计算。 |
| `scalar_batch` | 查询、批大小和在途上限与 `batch` 相同。标量结果确认后写入循环复用的调用方向量，计时包含按顺序核对所有值。 |
| `mixed_front` | 前台按固定 750 微秒间隔安排 2,000 次多列查询。单条前台连接顺序执行，落后时从原计划到达时刻继续计时，因此延迟包括调度和积压时间。 |
| `mixed_batch` | 同一 worker 上的独立后台任务持续运行流水线，前台结束后收完最后一批。记录后台确认吞吐。 |

CSV 中延迟单位为微秒，P50 和 P99 为该轮样本的最近秩分位数。流水线只报告吞吐。
前台请求由 worker 内的定时任务发起。要测量互联网服务向调用方交付响应的延迟，可从独立负载进程发出请求，并在该进程收到完整响应时停止计时。
比较版本时保持数据库版本、认证和 TLS 方式、CPU 配置、机器负载和网络位置一致。
多轮交错运行两个版本，分别比较前台 P99 与后台吞吐，并保留各轮结果以判断抖动。

## 统计每次查询的分配

在计数前准备语句、参数和采样数组，预热连接后只统计执行至 Ready 的区间。
对同一数据库分别测应用内存操作、直接用 Compio 发送相同报文、通过客户端执行查询。
用分配栈区分发送和接收操作节点、TLS 记录、业务结果与 runtime 的定时器，分配计数与吞吐计时分别运行。

启用 `diagnostics` 可分别统计 PostgreSQL 帧的 TLS 明文借用与拼接字节，以及 Windows 密文适配边界的复制字节。
计数发生在套接字密文适配和 PostgreSQL 解析两个边界，rustls 内部的记录存储与加解密成本另计。
派发诊断按实际调用的驱动、维护及回复唤醒器分别计数，驱动让出也可计入通用调度计数。

worker 上挂起的定时器也会被进程分配器计入。要测 I/O 本身，可让外部进程负责终止超时实验；要评估线上尾延迟，则应保留应用实际使用的截止时间。比较原生、就绪式和 TLS 路径时，固定网络端点、语句、同步边界与参数。Unix socket 应单列为同机传输。

## 核对单查询的协议与提交下界

用一条已经准备好的命名语句执行独立短查。
每次请求开始时给出本次参数，连接上没有待收发数据。
结果为单个非 NULL 的二进制 int4。
客户端必须确认本次 Ready 和本地发送完成。
统计区间从参数就绪开始，排除准备语句、建连和 TLS 握手。

在明文 TCP 上，若语句名占 N 个字节、portal 未命名，传入一个二进制 int4 参数并要求二进制结果，Bind 占 25 + N 字节，Execute 占 10 字节，Sync 占 5 字节。
对于 `SELECT $1::int4`，服务端在没有异步消息时依次返回 BindComplete、DataRow、CommandComplete 和 ReadyForQuery，共 40 字节。
命名为 `:p1` 时是 43 字节请求和 40 字节响应。

此条件下客户端至少需要一次发送和一次接收。
应用分配、内核 SQE、系统调用和实际帧字节分别观测。
操作节点的分配边界见[传输与运行时](expert.md#传输与运行时)。
是否达到该下界与实际耗时分别报告。
独立 Sync 的流水线保留每个成员的确认边界，但可将多个成员打包提交。
COPY 的 N 字节载荷若显式分成 K 个 CopyData 帧，数据阶段的报文字节为 N + 5K，启动和结束消息另计。
事务提交、TLS、拥塞和排队需要按各自工作量测量。

## 观察队列与缓冲开销

直连和池的直接租借路径在当前任务内驱动连接，无需经过派发队列。

| 位置 | 对请求成本的影响 |
| --- | --- |
| 增量流水线 | 接纳与确认严格按协议顺序进行，使用有界环形队列保存元数据。确认一个成员即回收对应槽位。当前发送包之外最多保留一个已排队发送包，多个小请求可以拼入待发包。 |
| 应用等待 FIFO | 预留 `BoundedFifo` 的环形槽，入队和出队可复用存储。 |
| 派发器 | 等待项可按索引撤回，槽内链接使任意位置撤回保持 O(1)。完成后直接写入提交时预留的回复槽。就绪驱动需接收跨线程唤醒信号，查询仍在原 worker 上执行。 |
| 原生接收区 | 单段存储可直接借用完整帧。只在跨读帧放不下时移动未读后缀或增长；短响应无需为环形边界拼接。 |

流水线的同序接纳和确认可以共用一条描述符环。
标量窗口的槽按值保存列 OID 和格式，完整行窗口持有共享布局。
两种模式各自复用多成员环并在下次使用时应用该模式的容量限额。交替使用两种模式的连接可能同时保留两块描述符存储。
派发等待项需要从中间撤回，回复则由各提交者独立领取。
直接使用对应的预留槽，避免为完成通知增加出入队，以及为已撤回项保留环上的空位。

io_uring 多次接收可以减少提交，但每次完成仍要交付一个共享缓冲槽。
评估长 COPY OUT 和深流水线时，保持单次接收区与所提供缓冲槽的大小相同，并分别记录吞吐、提交数、完成数和跨槽拼接字节。
同时核对多个连接共享缓冲池时的耗尽与恢复成本，以及退出等待后仍持有的接收操作。

## 比较 worker 本地连接池和派发器

启用 `service` 后，可在相同查询和并发度下比较五种提交方式。
每轮在一个 worker 上预热八条连接及各自的预备语句，并发执行八次多列主键查询。
首批预热后测量 256 批，共 2,048 次。采样数组在计时前分配。每次查询核对四个字段，并等待 Ready，池和派发模式还计入租约归还。
控制连接单独维护一次性测试数据。

```sh
cargo bench --locked --features service --bench service_workload -- tcp connections
cargo bench --locked --features service --bench service_workload -- tcp pool
cargo bench --locked --features service --bench service_workload -- tcp inline
cargo bench --locked --features service --bench service_workload -- tcp scan
cargo bench --locked --features service --bench service_workload -- tcp ready
```

`connections` 为每条并发查询提供专属热连接，`pool` 在提交方直接租借连接。
`inline` 从派发器直接借用连接，在提交方完成查询，无需配置等待槽或回复槽。
`scan` 和 `ready` 将请求放入同样大小的有界队列，分别使用扫描驱动和按唤醒派发的驱动。
两种驱动均逐项执行同一条语句，每轮预留十六单位，足以接纳八项并开始首次轮询。
延迟从提交计至调用方取回结果，包括排队和派发。
批次之间等待上一批全部完成。
将上述命令中的 `tcp` 换为 `tls` 或 `unix`，可比较加密连接或同机 Unix 套接字。
该负载衡量热连接上的固定并发短查。
稀疏唤醒或长 SQL 占多数的服务需要按实际请求分布另行测量。

建表、测量和清理分别设置 120 秒等待上限。测量超时仍尝试清理，建表或清理未获确认时可依据 stderr 中的 schema 名核对。

## 比较编译配置

本仓的 bench 继承 release 配置，在 Cargo 默认的 `opt-level = 3` 上使用 thin LTO 和单代码生成单元。
优化器可以跨 crate 内联具体的编解码和传输实现。
保留默认的 panic 展开策略，以维持连接和租约遇到 panic 时的清理行为。
最终二进制由应用工作区根清单决定编译配置。要在应用构建中采用同样的设置，需要在该清单中配置。

```toml
[profile.release]
lto = "thin"
codegen-units = 1
```

对比 Cargo 默认优化与本仓配置时，用独立生成目录保存基线产物，再交错运行两种配置。
分别比较单查、批量、混合负载前台 P99 和后台吞吐。

```sh
cargo bench --locked --target-dir target/bench-default \
    --config 'profile.release.lto=false' --config 'profile.release.codegen-units=16' \
    --bench service_workload -- tcp
```

比较跨 crate 的 Thin LTO 与 Fat LTO 时，固定特性、代码生成单元数和测试负载。
分别构建两个程序，再交错运行以比较吞吐和尾延迟。

```sh
cargo bench --locked --features service --target-dir target/bench-thin \
    --config 'profile.bench.lto="thin"' --config 'profile.bench.codegen-units=1' \
    --bench service_workload --no-run
cargo bench --locked --features service --target-dir target/bench-fat \
    --config 'profile.bench.lto="fat"' --config 'profile.bench.codegen-units=1' \
    --bench service_workload --no-run
```

单一 CPU 型号且构建机与部署机使用相同指令集时，可单独测量本机指令集优化。
分发到多种 CPU 的产物应按部署覆盖范围选择指令集。

```sh
RUSTFLAGS='-C target-cpu=native' cargo bench --locked --bench service_workload -- tcp
```

[Cargo 编译配置](https://doc.rust-lang.org/cargo/reference/profiles.html)
