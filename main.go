//go:build windows || linux

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// 配置：对应 Python 原版 entropy_sources 开关 + OneBot v11 连接参数 + TCP 服务。
type Config struct {
	Sources struct {
		Process  bool
		System   bool
		Memory   bool
		Disk     bool
		Temp     bool
		Input    bool
		Weather  bool
		Content  bool
		Packet   bool
		TPM      bool
		OneBot   bool
		EventLog bool
	}

	// 事件日志采集参数
	EventLog EventLogConfig
	// OneBot v11
	OneBotHTTP     string
	OneBotWS       string
	OneBotToken    string
	OneBotPollSec  int
	OneBotHistory  int
	OneBotEnableWS bool

	// TCP 种子服务
	TCPHost string
	TCPPort int

	SampleCount   int
	Rounds        int
	UseVonNeumann bool
	HashAlgo      string

	// TCP 服务（可通过 config.json 的 server 节覆盖）
	StreamMaxConcurrent int
	StreamMaxDuration   int // 秒
	PushRatePerSec      float64
	PushRateBurst       int

	// 天气/内容熵源独立抓取间隔（秒）
	WeatherIntervalSec int
	ContentIntervalSec int
}

func defaultConfig() *Config {
	c := &Config{
		SampleCount:    12,
		Rounds:         3,
		HashAlgo:       "sha256",
		OneBotHTTP:     "http://127.0.0.1:5700",
		OneBotWS:       "ws://127.0.0.1:6700",
		OneBotPollSec:  3,
		OneBotHistory:  50,
		OneBotEnableWS: false,
		TCPHost:        "0.0.0.0",
		TCPPort:        18888,

		StreamMaxConcurrent: 8,
		StreamMaxDuration:   60,
		PushRatePerSec:      2.0,
		PushRateBurst:       4,

		WeatherIntervalSec: 300, // 5 分钟
		ContentIntervalSec: 300, // 5 分钟
	}
	s := &c.Sources
	s.Process, s.System, s.Memory, s.Disk = true, true, true, true
	s.Temp, s.Input, s.Weather, s.Content = true, true, true, true
	s.Packet, s.TPM, s.OneBot, s.EventLog = true, true, false, false

	// EventLog 默认关闭（需用户明确启用，避免意外读取 Security 日志）
	c.EventLog = EventLogConfig{
		Enable:      false,
		IntervalSec: 15,
		MaxEvents:   20,
	}
	return c
}

func main() {
	// Windows 控制台切到 UTF-8 代码页，正确显示中文/emoji
	if runtime.GOOS == "windows" {
		cmdCP := exec.Command("cmd", "/c", "chcp", "65001")
		cmdCP.Stdout = nil
		cmdCP.Stderr = nil
		_ = cmdCP.Run()
	}

	var (
		noElevate = flag.Bool("no-elevate", false, "不自动提权")
		noShell   = flag.Bool("no-shell", false, "无交互控制台")
		serve     = flag.Bool("serve", false, "长驻服务模式（启动 TCP 种子服务器）")
		rounds    = flag.Int("rounds", -1, "采集轮数（非 serve 模式），-1 用配置默认")

		obEnable = flag.Bool("onebot", false, "启用 OneBot v11 熵源")
		obHTTP   = flag.String("onebot-http", "", "OneBot v11 HTTP 地址")
		obWS     = flag.String("onebot-ws", "", "OneBot 正向 WS 地址")
		obToken  = flag.String("onebot-token", "", "OneBot access_token（同时用作 STATUS 口令）")
		obWSOn   = flag.Bool("onebot-ws-enable", false, "额外启用 OneBot WS 实时事件流")

		tcpHost = flag.String("tcp-host", "", "TCP 监听地址（空则用配置/默认）")
		tcpPort = flag.Int("tcp-port", 0, "TCP 端口（0 则用配置/默认）")
		cfgPath = flag.String("config", "config.json", "配置文件路径（JSON）")

		poolMode = flag.Bool("pool", false, "池模式：仅接受外部推送、搅拌、输出熵，不启动本地采集器")
		xmsFlag  = flag.String("Xms", "20M", "初始预留内存（20M/1G/512K/1024(纯数字=MB)/1048576B(纯字节)）")
		xmxFlag  = flag.String("Xmx", "", "最大内存上限（格式同 -Xms；空则取 min(16G, 空闲内存+SWAP)）")

		logLevelFlag = flag.String("log-level", "info", "日志级别：debug/info/warn/error")
		logFileFlag  = flag.String("log-file", "", "日志文件路径（空则仅输出到控制台）")
		noColorFlag  = flag.Bool("no-color", false, "禁用 ANSI 彩色日志")

		logMaxSizeFlag     = flag.Int64("log-max-size", 10<<20, "日志文件最大字节数（默认 10MB）")
		logBackupCountFlag = flag.Int("log-backup-count", 5, "日志轮转保留的备份数（默认 5）")

		csprngFlag = flag.String("csprng", "system",
			"CSPRNG 后端：system(crypto/rand) / hmac(HMAC-SHA256) / ctr(AES-256-CTR) / mixed(HMAC⊕CTR) / none(物理熵)")
		seedFileFlag = flag.String("seed-file", "",
			"初始种子文件（hex 或二进制，>=32 字节）；hmac/ctr 未指定时用物理熵播种")
	)
	flag.Parse()

	// ---- 初始化日志 ----
	enableVT()
	if err := InitLogger(*logLevelFlag, *logFileFlag, *noColorFlag,
		*logMaxSizeFlag, *logBackupCountFlag); err != nil {
		fmt.Fprintf(os.Stderr, "[log] 初始化失败: %v\n", err)
		os.Exit(1)
	}
	defer CloseLogger()

	// ---- 先确定使用哪个配置文件：CWD → exe 目录 → 显式 flag ----
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfg := defaultConfig()
	resolvedPath, cfgSource := resolveConfigPath(*cfgPath, set["config"])
	if n, err := loadConfigJSON(resolvedPath, cfg); err != nil {
		LogWarn("config", "读取 %s 失败：%v（使用默认值）", resolvedPath, err)
	} else {
		LogInfo("config", "已加载 %s（%d 项，来源=%s）", resolvedPath, n, cfgSource)
	}

	// ---- 显式 flag 覆盖配置文件 ----
	if set["rounds"] && *rounds > 0 {
		cfg.Rounds = *rounds
	}
	if set["onebot"] {
		cfg.Sources.OneBot = *obEnable
	}
	if set["onebot-http"] && *obHTTP != "" {
		cfg.OneBotHTTP = *obHTTP
	}
	if set["onebot-ws"] && *obWS != "" {
		cfg.OneBotWS = *obWS
	}
	if set["onebot-token"] && *obToken != "" {
		cfg.OneBotToken = *obToken
	}
	if set["onebot-ws-enable"] {
		cfg.OneBotEnableWS = *obWSOn
	}
	if set["tcp-host"] && *tcpHost != "" {
		cfg.TCPHost = *tcpHost
	}
	if set["tcp-port"] && *tcpPort > 0 {
		cfg.TCPPort = *tcpPort
	}

	// ---- 内存限制 ----
	var xmsBytes, xmxBytes int64
	if s := *xmsFlag; s != "" {
		v, perr := ParseMemSize(s)
		if perr != nil {
			LogError("mem", "-Xms 解析失败：%v", perr)
			os.Exit(1)
		}
		xmsBytes = v
	}
	if s := *xmxFlag; s != "" {
		v, perr := ParseMemSize(s)
		if perr != nil {
			LogError("mem", "-Xmx 解析失败：%v", perr)
			os.Exit(1)
		}
		xmxBytes = v
	}
	appliedXms, _, perr := ApplyMemoryLimits(xmsBytes, xmxBytes)
	if perr != nil {
		LogError("mem", "%v", perr)
		os.Exit(1)
	}

	// ---- 权限管理 ----
	pm := NewPermissionManager()
	if !*noElevate && !pm.HasElevatedFlag() && !pm.IsAdmin() {
		LogWarn("perm", "当前非管理员，尝试 UAC 提权重启（抓包/温度需要更高权限）...")
		if pm.Elevate() {
			LogInfo("perm", "已请求提权，本实例退出，请在弹窗中确认。")
			return
		}
		LogWarn("perm", "提权被拒绝，继续以普通权限运行（部分熵源可能降级）。")
	}
	LogInfo("perm", "管理员=%v 提权参数=%v", pm.IsAdmin(), pm.HasElevatedFlag())

	// ---- 用 cfg 覆盖全局限流参数（在 TCP 服务启动前） ----
	globalPushLimiter = newPushLimiter(cfg.PushRatePerSec, cfg.PushRateBurst)

	// ---- 熵池 + 搅拌器 ----
	stirrer := NewHashStir(cfg.HashAlgo)
	pool := NewChaosEntropyPool(stirrer)
	pool.MixBytes(osRandom(64)) // 基础熵：保证即使所有外部源失败也有可用池

	// ---- 初始化 CSPRNG 后端 ----
	if *seedFileFlag != "" && (*csprngFlag == "" || *csprngFlag == "system") {
		LogWarn("csprng", "-seed-file 对 system 后端无效（system 直连 crypto/rand，无需种子）")
	}
	drbg, derr := NewDRBG(*csprngFlag, *seedFileFlag)
	if derr != nil {
		LogError("csprng", "初始化失败: %v", derr)
		os.Exit(1)
	}
	pool.drbg = drbg
	LogInfo("csprng", "后端: %s", drbg.Name())
	if *csprngFlag == "hmac" || *csprngFlag == "ctr" {
		if *seedFileFlag != "" {
			LogInfo("csprng", "种子来源: 用户文件 %s", *seedFileFlag)
		} else {
			LogInfo("csprng", "种子来源: 物理熵（clock/cpu/memory jitter）")
		}
	}

	// -Xms 预留：持有缓冲区保持内存占用；程序退出时通过 defer 清零。
	// 旧实现 secureZero 后即失去引用，GC 可随时回收，不构成真正预留。
	var reservedMemory []byte
	if appliedXms > 0 {
		const maxPrealloc = int64(64) << 20
		n := appliedXms
		if n > maxPrealloc {
			n = maxPrealloc
		}
		reservedMemory = osRandom(int(n))
		pool.MixBytesFiltered(reservedMemory)
		defer func() { secureZero(reservedMemory) }()
	}

	// ---- 实例化各熵源（池模式下全部跳过） ----
	var (
		procCol    *ProcessSnapshotCollector
		sysCol     *SystemEntropyCollector
		memCol     *MemoryEntropyCollector
		diskCol    *DiskEntropyCollector
		tempCol    *TemperatureCollector
		inputCol   *InputEntropyCollector
		wpCol      *WeatherEntropyCollector
		contentCol *ContentEntropyCollector
		pktCol     *PacketCollector
		tpmCol     *TPMEntropyCollector
		eventCol   *EventLogCollector
	)
	// 优雅关闭用：eventlog 采集器的停止函数（可能为空函数）
	stopEventCol := func() {}

	caps := map[string]bool{
		"push":      true,
		"mix":       true,
		"pool_mode": *poolMode,
		"onebot":    false,
	}

	if !*poolMode {
		procCol = NewProcessSnapshotCollector(pool)
		sysCol = NewSystemEntropyCollector(pool)
		memCol = NewMemoryEntropyCollector(pool)
		diskCol = NewDiskEntropyCollector(pool)
		tempCol = NewTemperatureCollector(pool)
		inputCol = NewInputEntropyCollector(pool)
		wpCol = NewWeatherEntropyCollector(pool, cfg.WeatherIntervalSec)
		contentCol = NewContentEntropyCollector(pool, cfg.ContentIntervalSec)
		pktCol = NewPacketCollector(pool)
		// 启动时探测：不可用则直接禁用，不进入采集循环
		if !pktCol.Probe() {
			LogWarn("packet", "启动探测失败（SIO_RCVALL 被拦截或未安装 Npcap），已禁用抓包熵源。建议安装 Npcap：https://npcap.com")
		}
		tpmCol = NewTPMEntropyCollector(pool)
		if tpmCol.Available() {
			defer tpmCol.Close()
		}
		// 双开关：entropy_sources.eventlog 或 eventlog.enable 任一为 true 就启动
		if cfg.Sources.EventLog || cfg.EventLog.Enable {
			if cfg.Sources.EventLog && !cfg.EventLog.Enable {
				LogDebug("config", "entropy_sources.eventlog=true 但 eventlog.enable=false，自动启用")
			}
			eventCfg := cfg.EventLog
			eventCfg.Enable = true // 强制同步，避免 collectPlatform 里 if !c.cfg.Enable 拦截
			cand := NewEventLogCollector(pool, eventCfg)
			// 启动时探测：不可用则直接禁用，不启动后台 goroutine
			if cand.Probe() {
				eventCol = cand
				stopEventCol = eventCol.Start()
				caps["eventlog"] = true
				LogInfo("eventlog", "事件日志采集已启动（间隔 %ds，每次 %d 条）",
					cfg.EventLog.IntervalSec, cfg.EventLog.MaxEvents)
			} else {
				caps["eventlog"] = false
				LogWarn("eventlog", "启动探测失败（wevtutil 和 PowerShell 均不可用或权限不足），已禁用事件日志熵源")
			}
		}

		caps["process"] = cfg.Sources.Process
		caps["system"] = cfg.Sources.System
		caps["memory"] = cfg.Sources.Memory
		caps["disk"] = cfg.Sources.Disk
		caps["temp"] = cfg.Sources.Temp
		caps["input"] = cfg.Sources.Input
		caps["weather"] = cfg.Sources.Weather
		caps["content"] = cfg.Sources.Content
		caps["packet"] = cfg.Sources.Packet && !pktCol.Disabled()
		caps["tpm"] = tpmCol.Available()
	}

	// ---- OneBot ----
	var obCol *OneBotClient
	if !*poolMode && cfg.Sources.OneBot {
		obCol = NewOneBot(pool, OneBotConfig{
			Enable:      true,
			HTTPURL:     cfg.OneBotHTTP,
			WSURL:       cfg.OneBotWS,
			Token:       cfg.OneBotToken,
			PollSec:     cfg.OneBotPollSec,
			HistorySize: cfg.OneBotHistory,
			EnableWS:    cfg.OneBotEnableWS,
		})
		if uid, nick, err := obCol.GetLoginInfo(); err == nil {
			LogInfo("onebot", "已连接 %s(%d)，HTTP 拉取已启动", nick, uid)
		} else {
			LogWarn("onebot", "HTTP 未就绪(%v)，将以轮询/事件持续重试", err)
		}
		obCol.Start()
		defer obCol.Stop()
		caps["onebot"] = true
	}

	// ---- 冻结 caps 快照，之后不再改写 ----
	capsSnapshot := make(map[string]bool, len(caps))
	for k, v := range caps {
		capsSnapshot[k] = v
	}

	if *poolMode {
		fmt.Println("Chaos RNG (Go / Windows) 启动，池模式（仅接受 PUSH_SEED / MIX 推送）")
	} else {
		fmt.Println("Chaos RNG (Go / Windows) 启动，全熵源调度：")
		fmt.Printf("  进程/系统/内存/磁盘/温度/输入/天气/内容/抓包/TPM/OneBot = %v %v %v %v %v %v %v %v %v %v %v\n",
			capsSnapshot["process"], capsSnapshot["system"], capsSnapshot["memory"], capsSnapshot["disk"],
			capsSnapshot["temp"], capsSnapshot["input"], capsSnapshot["weather"], capsSnapshot["content"],
			capsSnapshot["packet"], capsSnapshot["tpm"], capsSnapshot["onebot"])
	}

	// ---- 采集一次（池模式下空操作） ----
	var collectOnce func(verbose bool)
	if *poolMode {
		collectOnce = func(verbose bool) {}
	} else {
		collectOnce = func(verbose bool) {
			if cfg.Sources.Process {
				procCol.Collect()
				time.Sleep(150 * time.Millisecond)
				procCol.Collect()
			}
			if cfg.Sources.System {
				sysCol.Collect()
			}
			if cfg.Sources.Memory {
				memCol.Collect()
			}
			if cfg.Sources.Disk {
				diskCol.Collect()
			}
			if cfg.Sources.Temp {
				tempCol.Collect()
				if t := tempCol.LastTenthsC(); t > 0 && verbose {
					LogDebug("temp", "实测热区 %.1f C", float64(t)/10.0)
				}
			}
			if cfg.Sources.Input {
				inputCol.Collect()
			}
			if cfg.Sources.TPM && tpmCol.Available() {
				tpmCol.Collect()
			}
			if cfg.Sources.Weather {
				n := wpCol.FetchOnce(cfg.SampleCount)
				if verbose {
					LogDebug("weather", "成功抓取 %d 个城市温度", n)
				}
			}
			if cfg.Sources.Content {
				n := contentCol.FetchAll()
				if verbose {
					LogDebug("content", "成功抓取 %d 个平台热榜", n)
				}
			}
			if cfg.Sources.Packet {
				n := pktCol.Collect(64)
				if verbose {
					LogDebug("packet", "后端=%s 处理 %d 帧", pcapBackend(pktCol), n)
				}
			}
			if obCol != nil && verbose {
				h, w := obCol.Stats()
				LogDebug("onebot", "HTTP混入=%d WS事件混入=%d（零缓存）", h, w)
			}

			if eventCol != nil && verbose {
				accepted, unique := eventCol.Stats()
				attempted := eventCol.TotalAttempted()
				LogDebug("eventlog", "尝试 %d 条（接受 %d，唯一 %d）", attempted, accepted, unique)
			}
		}
	}

	// ---- 停止通知 ----
	stopped := make(chan struct{})
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(func() { close(stopped) }) }

	// ============ 长驻服务模式 / 池模式 ============
	if *serve || *poolMode {
		if !*poolMode {
			go func() {
				collectOnce(true)
				ticker := time.NewTicker(15 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-stopped:
						return
					case <-ticker.C:
						collectOnce(false)
					}
				}
			}()
		}

		srv := NewTCPServer(pool, stirrer, cfg, capsSnapshot, obCol, cfg.TCPHost, cfg.TCPPort)
		srv.eventCol = eventCol
		srv.pktCol = pktCol
		if err := srv.Start(); err != nil {
			LogError("tcp", "启动失败: %v", err)
			os.Exit(1)
		}
		defer srv.Stop()

		// 信号处理：Ctrl+C / SIGTERM 优雅关闭
		// 顺序：停止采集循环 → 停止 TCP → 停止 OneBot → 停止 eventlog → 打"完成"
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			LogWarn("main", "收到信号 %v，开始优雅关闭...", sig)
			stopFn() // 关闭 stopped channel 通知采集循环退出
			srv.Stop()
			if obCol != nil {
				obCol.Stop()
			}
			stopEventCol() // 停 eventlog goroutine（会等子进程退出）
			LogInfo("main", "优雅关闭完成")
		}()

		if !*noShell {
			interactiveShell(pool, srv, obCol, wpCol, contentCol, capsSnapshot, stopFn)
		} else {
			<-stopped
		}
		return
	}

	// ============ 一次性输出种子模式 ============
	for r := 0; r < cfg.Rounds; r++ {
		collectOnce(true)
	}

	seed := GenerateSeed(pool)
	out := seed
	if cfg.UseVonNeumann {
		vn := VonNeumann(seed)
		if len(vn) > 0 {
			out = vn
			secureZero(seed)
		}
	}
	fmt.Printf("\n熵池事件数=%d 已搅拌字节=%d\n", pool.EventCount(), stirrer.TotalStirred())
	fmt.Printf("最终种子(%d 字节, hex):\n%x\n", len(out), out)
	secureZero(out)
}

func pcapBackend(c *PacketCollector) string {
	if c.UsingNpcap() {
		return "Npcap(wpcap)"
	}
	return "SIO_RCVALL(raw)"
}
