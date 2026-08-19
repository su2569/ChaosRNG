# Chaos RNG

不建议直接用于生产环境

## 简介

Chaos RNG 是一个独立运行的混沌随机数生成程序，通过采集**14种不同维度的熵源**，构建高安全性的随机数种子池。

不同于伪随机数生成器（PRNG），Chaos RNG 从**真实的物理世界**采集不可预测的噪声数据，经密码学哈希搅拌后生成近乎完美的随机数。

## 核心特性

- 🔥 **14+ 独立熵源** — 从硬件、网络、系统、用户交互等多维度采集
- 🛡️ **密码学安全** — 所有熵数据经 SHA-256/BLAKE2b 哈希搅拌
- 🎛️ **模块化设计** — 每个熵源独立可开关，自动检测可用性
- 🌐 **TCP 服务** — 提供 `0.0.0.0:18888` 种子获取接口
- 💬 **OneBot V11** — 可作为 QQ/微信机器人的随机数服务后端
- 🔑 **自动提权** — Windows UAC / Linux sudo / macOS osascript

## 熵源列表

| 熵源 | 原理 | 模式 |
|------|------|------|
| 🔧 进程抖动 | 系统进程 CPU/IO 变化 | 自动 |
| 🌤️ 天气数据 | 全国34省实时温度 | 网络 |
| 🕸️ 网络抓包 | TCP/UDP payload AES-256→SHA256 | 需root |
| 💬 OneBot消息 | QQ/微信群聊内容哈希 | WS客户端 |
| 🎙️ 音频底噪 | 麦克风ADC最低有效位(LSB) | 硬件 |
| 📷 CMOS暗电流 | 摄像头镜头盖下的像素噪声 | 硬件 |
| 🖱️ 输入中断 | 鼠标/键盘纳秒级时间间隔 | 硬件 |
| 💾 磁盘IO | 读写操作微秒级抖动 | 硬件 |
| 🧠 内存读取 | 本进程/全系统内存内容 | 可选模式 |
| 📊 磁盘统计 | 实时读写量变化率 | 系统 |
| 🌡️ 硬件温度 | CPU/GPU/主板温度波动 | 硬件 |
| 🔒 TPM芯片 | 硬件RNG + PCR寄存器 | 硬件 |
| ⚙️ 系统事件 | 调度/会话/日志/中断 | 系统 |
| 📰 内容平台 | 微博/知乎/B站/GitHub等热榜 | 网络缓冲 |

## 处理流程

```
原始熵数据
    ↓
[冯·诺依曼纠偏] (可选)
    01→0, 10→1, 00/11丢弃
    ↓
[HashWhirlpool 搅拌]
    SHA-256 / SHA3-256 / BLAKE2b
    ↓
[ChaosEntropyPool 累积]
    持续混入，SHA-256 状态机
    ↓
[SeedGenerator 合成]
    os.urandom ⊕ pool_hash ⊕ time_hash
    ↓
256-bit 种子输出
```

## 快速开始

### 安装依赖

```bash
# 核心依赖
pip install pyyaml psutil aiohttp websockets

# 扩展熵源（按需安装）
pip install cryptography scapy          # 抓包
pip install sounddevice opencv-python   # 音频/摄像头
pip install pynput                      # 输入设备
pip install pywin32 wmi                 # Windows温度
```

### 运行

```bash
# 完整功能（自动请求管理员权限）
sudo python main.py

# 不请求提权（缺少抓包等特权功能）
python main.py --no-elevate

# 后台运行（无交互控制台）
python main.py --no-shell

# 指定配置
python main.py -c my_config.yaml
```

### 交互命令

```
chaos> seed      # 获取 256-bit 种子
chaos> lucky     # 获取 1-100 幸运数字
chaos> status    # 查看完整状态
chaos> caps      # 查看功能开关
chaos> content   # 手动触发内容采集
chaos> quit      # 退出
```

### TCP 接口

```bash
# 获取种子（二进制）
echo "GET_SEED" | nc localhost 18888

# 获取种子（十六进制）
echo "GET_HEX" | nc localhost 18888

# 查看状态
echo "STATUS" | nc localhost 18888
```

## 配置文件

编辑 `config.yaml` 控制各功能开关：

```yaml
entropy_sources:
  memory:
    enabled: true
    mode: "self"      # "self"=安全(仅本进程), "all"=全系统(需root)
  content:
    enabled: true
    platforms:
      weibo: true
      github: true
```

## 安全说明

- **内存模式**: `self` 模式仅读取本进程内存，不会被反外挂/安全软件误判；`all` 模式需要 root 且可能被标记
- **抓包**: 使用 scapy 或原始 socket，需要管理员/root 权限
- **输入监听**: pynput 全局监听可能需要额外权限配置
- **所有内容哈希**: 原始数据经 SHA-256 哈希后混入，不存储任何原始内容

## 系统支持

| 系统 | 支持程度 |
|------|---------|
| Linux | ⭐⭐⭐ 完整支持 |
| Windows | ⭐⭐⭐ 完整支持 |
| macOS | ⭐⭐☆ 部分支持（抓包受限）|

## 协议与许可

本项目采用 **MIT 协议** 开源，详见 [LICENSE](LICENSE) 文件。

作者: **su2569**

## 免责声明

本程序仅用于学习研究密码学、随机数生成和系统安全。使用网络抓包、内存读取等功能时，请确保遵守当地法律法规，仅在您拥有合法权限的系统上运行。
