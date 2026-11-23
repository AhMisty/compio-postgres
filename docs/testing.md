# 构建、示例和集成测试

在仓库根目录使用 `rust-toolchain.toml` 指定的稳定版 Rust。
构建需要目标平台的链接工具链。默认 TLS 特性通过 `ring` 编译原生密码学代码，也需要目标平台可用的 C 编译器。
下文的 Bash、OpenSSL、Docker 和 PostgreSQL 命令用于各自的验证夹具。

库、示例和基准均禁止不安全 Rust。
Clippy 检查库、示例和基准中显式的 `unwrap`、`expect`、`panic!` 和 `unreachable!`。
生产库同时启用 `indexing_slicing`。运行时槽位使用受检访问，定长编码中由私有构造器保证的边界就地说明。
全部目标禁止 `todo!`、`unimplemented!`、直接按字节下标切分 UTF-8 字符串，以及可能因时间顺序错误而 panic 的时间减法。
测试可以用断言定位夹具和协议错误。

## 本地检查

这些命令无需 PostgreSQL 实例。
常规测试在本机回环地址或本地 Unix 套接字上启动限时对端。
GitHub Actions 在 Linux、Windows 和 macOS 上检查全功能及最小功能构建。
Windows 和 macOS 单独运行本地 TLS 握手与分片测试，Linux 在真库夹具中运行同一组用例。
Linux 另外验证默认功能、独立启用本地连接池和派发器的构建，以及 API 文档。
Linux 真库检查覆盖 io_uring、TCP、Unix socket、TLS 1.2/1.3、SCRAM 通道绑定和客户端证书。

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features service
cargo rustdoc --locked --all-features --lib -- -D warnings
```

使用默认 Cargo 生成目录时，打开 `target/doc/compio_postgres/index.html` 阅读本地 API 文档。

Linux CI 串行运行测试用例，降低并行建 runtime 对内核锁定内存额度的占用。各用例内部的并发与在途请求配置不变。
如果 Linux 上创建 Compio runtime 返回 `ENOMEM`，可用与 CI 相同的设置复跑。

```sh
RUST_TEST_THREADS=1 cargo test --locked --all-features
```

运行进程级分配计数的库测试时，单独执行忽略用例。

```sh
cargo test --locked --all-features --lib --test limit_contract -- --ignored --test-threads=1
```

在准备发布的源码树中打包，Cargo 会解包并重新编译发行产物。

```sh
cargo package --locked
```

Cargo 默认把发行包写到 `target/package/`。
需要清理时，先确认 `target/` 属于本仓库、没有其他任务使用，且其中的发行包和其他生成物都可删除。
在仓库根目录清理这个指定的生成目录。

```sh
cargo clean --target-dir target
```

## 本地 TLS 夹具

使用 Bash 和 OpenSSL 或兼容 CLI 的 LibreSSL，Windows 使用 Git Bash。
脚本在临时目录生成 CA、服务端证书及私钥，用本地回环对端验证缺失的 PostgreSQL ALPN、跨 TLS 记录的帧和 COPY OUT 载荷处理。
该模式无需 PostgreSQL 或 Docker，退出后清理夹具。

```sh
bash scripts/test-postgres.sh --tls-only
```

## 数据库和认证

使用独立 PostgreSQL 19 实例及允许创建测试对象的数据库角色。
真实 SQL 用例会创建临时表。
部分跨连接测试还需要创建普通数据库对象。
冻结重放验证要求该角色能够在当前 schema 创建序列，并查询同一角色的后端状态和阻塞关系。
使用 SCRAM 密码，允许该角色通过所测试的 TCP 及 Unix socket 路由登录。
Linux 上的冻结重放与 io_uring 专项要求内核向测试进程开放 io_uring。

| 环境变量 | 含义 |
| --- | --- |
| `CPG_HOST`、`CPG_PORT` | 可解析的 TCP 主机和端口。 |
| `CPG_DATABASE`、`CPG_USER`、`CPG_PASSWORD` | 测试数据库、登录角色及其 SCRAM 密码。 |
| `CPG_UNIX_PATH` | Unix 上 PostgreSQL 套接字的绝对文件路径，例如 `/var/run/postgresql/.s.PGSQL.5432`。 |
| `CPG_TLS_SERVER_NAME`、`CPG_TLS_CA_PEM` | 证书验证名称及用于签发服务端证书的 CA PEM 文件。 |
| `CPG_TLS_SERVER_CERT_PEM`、`CPG_TLS_SERVER_KEY_PEM` | 本地 TLS 测试对端使用的服务端证书链和配套私钥。 |
| `CPG_TLS_CLIENT_CERT_PEM`、`CPG_TLS_CLIENT_KEY_PEM` | 测试双向 TLS 使用的客户端证书链和配套私钥。 |

完整 TLS 矩阵需要 PostgreSQL 启用 SSL，允许 TLS 1.2 和 1.3，使用 SCRAM-SHA-256。
测试同时覆盖 SSLRequest、直接 TLS 和通道绑定。
服务端证书需包含验证名称。
服务端与客户端证书应具有相应的 serverAuth 和 clientAuth 用途，证书链按叶证书在前排列。
仓库随附的公开证书只用于解析单测，真实握手使用上述夹具证书。
双向 TLS 需要将服务端的 `ssl_ca_file` 指向签发客户端证书的可信 CA。
该用例通过数据库连接查询 `pg_stat_ssl`，核对服务端收到的客户端证书序列号。
私钥应保存在源码树之外。

### 运行隔离夹具

Linux 上可复用 CI 的入口。需要本机 Docker Engine、OpenSSL 和允许 io_uring 的内核。
脚本使用官方 `postgres:19.0` 镜像，在回环地址分配端口，并生成本轮专用的套接字和证书。
镜像按默认入口初始化数据库，脚本随后用 PostgreSQL 的配置文件和 `pg_ctl reload` 启用 TLS。
真库测试在要求 TLS 的回环连接成功后开始。
所有真库用例和进程级分配测试串行运行，退出时回收容器和夹具目录。

```sh
bash scripts/test-postgres.sh
```

Linux 主机已安装 PostgreSQL 19 时，也可把其 `bin` 目录加入 `PATH`，以普通用户启动隔离实例。
选择测试主机上空闲的回环端口。
脚本生成并回收数据库、套接字和证书，使用与容器入口相同的测试命令。

```sh
bash scripts/test-postgres.sh --native 55432
```

### 使用已有测试实例

示例在同一 worker 建连，然后执行单值查询、批量收集和逐项观察。
选择 TLS 时，在上表的 TCP 和 SCRAM 参数之外，提供服务端名称和可信 CA 路径。
服务器要求双向 TLS 时再提供客户端证书链和私钥。

```sh
cargo run --locked --example api -- tls
```

在可信测试网络上可显式选择明文 TCP。

```sh
cargo run --locked --example api -- tcp
```

Unix 上设置 `CPG_UNIX_PATH` 和数据库登录参数后，可直接使用本机套接字。

```sh
cargo run --locked --example api -- unix
```

只验证基础真实数据库用例时，使用以下命令。

```sh
cargo test --locked --test live_pg -- --ignored --test-threads=1
```

配置了相应平台上的全部数据库和证书夹具后，运行所有标记为忽略的专项。单线程运行使进程级分配诊断能单独计数。

```sh
cargo test --locked --all-features -- --ignored --test-threads=1
```

数据库连通性、行内容、Ready 和 COMMIT 是正确性检查。比较应用吞吐、调度影响或前台尾延迟时，使用[基准指南](bench.md)中的固定工作负载。
