# Chaos RNG — Go / Windows 移植版

原项目为 Python「多熵源真随机数生成器」，本目录是 **Go 1.22 / 仅 Windows** 的完整移植。
所有采集/密码学逻辑覆盖原 10 个模块，**零第三方依赖**（全部走 Go 标准库 + Windows SDK）。

## 本轮更新：OneBot 完整支持 v11 + WS，并去掉消息缓存

- **主动 HTTP 拉取为主通道**：用 OneBot v11 的 `get_group_list` / `get_friend_list` 自动发现会话，
  `get_group_msg_history` / `get_friend_msg_history` 拉取"最近消息"。逐条哈希后**立即丢弃原文**，
  进程内**零消息缓存**（明文存活仅微秒级），比旧版的哈希环形缓冲更贴合原版"只留哈希不存原文"。
- **正向 WebSocket 为可选实时/降级通道**：自实现完整 RFC6455 客户端 —— wss(TLS) 握手、分片(fin/continuation)
  重组、客户端**掩码帧**（RFC6455 要求）、ping→pong、close 握手；收到即哈希即丢弃。
- **完整 v11 接口封装**：`get_login_info`、`get_group_list`、`get_friend_list`、
  `get_group_msg_history`、`get_friend_msg_history` 等，统一 `{action, params}` 请求 +
  `{status, retcode, data}` 响应解析，鉴权 `Authorization: Bearer <token>`。
- **反关联**：每次混池前缀一个进程级随机 `selfTag`，避免跨实例把同一消息对齐成可关联指纹。

### OneBot 开启方式

```
chaos_rng.exe --onebot --onebot-http http://127.0.0.1:5700 --onebot-token <token>
chaos_rng.exe --onebot --onebot-ws-enable --onebot-ws ws://127.0.0.1:6700   # 额外启用 WS 实时事件
```
参数含义见 `config.example.yaml`。默认 `enable=false`，需本地跑一个 OneBot 实现（Lagrange / NapCat / go-cqhttp 等）。

> 注意：`get_group_msg_history` / `get_friend_msg_history` 是部分 v11 实现的扩展接口。
> 若某实现返回不支持，会自动跳过该会话并继续走 WS 事件流，不影响整体运行。

## 为什么 Go 比 C++ 更顺

| 维度 | C++/MinGW 版 | Go 版 |
|---|---|---|
| SHA-256 / AES | 手写实现 + 过 NIST 向量 | 直接用标准库 `crypto/sha256`、`crypto/aes` |
| 异步抓取 | WinHTTP 同步封装 | 原生 `net/http` + goroutine，天然并发 |
| WebSocket(OneBot) | WinHTTP WebSocket | 自实现完整 RFC6455（TLS、分片、掩码、ping/pong） |
| Windows API | LoadLibrary + 函数指针 | `syscall.NewLazyDLL` 运行时动态加载，类型安全 |
| 部署 | 单 exe 但需 MinGW 运行时 | 单静态 exe（CGO_ENABLED=0），拷走即跑 |

## 文件结构（对应原 Python 模块）

| Go 文件 | 对应 | 说明 |
|---|---|---|
| `main.go` | main.py | 配置 + 全熵源调度 + 纠偏/搅拌 + 种子输出 + 提权入口 |
| `entropy_pool.go` | chaos_rng_core.py | HashStir(sha256/sha512)、ChaosEntropyPool、SeedGenerator、冯·诺依曼纠偏、AES-256-ECB |
| `winapi.go` | — | 共享 Win32 动态加载：RtlGenRandom、安全时间戳、SecureZero 等价 |
| `entropy_proc.go` | (进程熵) | Toolhelp32 快照 + GetProcessTimes CPU 差分（替代 psutil） |
| `entropy_sensors.go` | system/hardware/entropy_collectors | 系统抖动、内存、磁盘、**ACPI 温度(绕过 WMI/PDH)**、输入抖动 |
| `weather.go` | weather | wttr.in 34 省市温度并发抓取（替代 aiohttp） |
| `content.go` | content_entropy.py | 多平台热榜内容熵，SHA256，速率限制 |
| `packet.go` | packet_collector.py | **Npcap wpcap.dll 动态加载**，回退 SIO_RCVALL；AES→SHA256 混池 |
| `tpm.go` | tpm_entropy.py | tbs.dll 动态加载 TPM2_GetRandom + 时钟抖动 |
| `onebot.go` | onebot_client.py | **完整 v11 HTTP 拉取 + RFC6455 WS，零消息缓存** |
| `permissions.go` | permissions.py | TokenElevation 检测 + ShellExecuteExW(runas) UAC 提权 |

## 编译（Go 1.22+，仅 Windows）

在本目录执行：`go build -o chaos_rng.exe .`
或直接运行 `build.bat`。

- 无需 CGO、无需 MinGW、无需任何第三方库。
- 交叉编译（Linux/mac 产出 Windows exe）：
  `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o chaos_rng.exe .`

## 与 Python 原版的差异（诚实边界）

1. **哈希算法**：Python 用 sha256/sha3_256/blake2b；Go 保持零第三方依赖，收敛为 sha256/sha512（强摘要，行为等价）。
2. **温度熵**：读 ACPI ThermalZone 寄存器（绕过 WMI/PDH，无驱动），是热区温度而非逐核 CPU 温度；拿不到自动降级。
3. **抓包**：装了 Npcap 且管理员时走 wpcap.dll（无需 SDK）；否则回退 SIO_RCVALL 本机可见流量。
4. **内容熵**：热榜接口随平台改版可能失效，失败自动跳过。
5. **OneBot**：本轮升级为 v11 HTTP 主动拉取（零缓存）+ 完整 WS 客户端；默认关闭，需本地 OneBot 服务。
6. **安全清零**：Go 有 GC/移动栈，`secureZero` 尽力清零，弱于 C 的 `SecureZeroMemory`。
7. **隐私**：消息/内容/抓包只混哈希、不存原文；抓包先 AES 加密再哈希；OneBot 已去掉环形缓冲，明文存活期更短。
