//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// 配置：对应 Python 原版 entropy_sources 开关 + OneBot v11 连接参数 + TCP 服务。
type Config struct {
	Sources struct {
		Process bool
		System  bool
		Memory  bool
		Disk    bool
		Temp    bool
		Input   bool
		Weather bool
		Content bool
		Packet  bool
		TPM     bool
		OneBot  bool
	}
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
	}
	s := &c.Sources
	s.Process, s.System, s.Memory, s.Disk = true, true, true, true
	s.Temp, s.Input, s.Weather, s.Content = true, true, true, true
	s.Packet, s.TPM, s.OneBot = true, true, false
	return c
}

func main() {
	// Win10 控制台切到 UTF-8 代码页，正确显示中文/emoji
	cmdCP := exec.Command("cmd", "/c", "chcp", "65001")
	cmdCP.Stdout = nil
	cmdCP.Stderr = nil
	_ = cmdCP.Run()

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
	)
	flag.Parse()

	// ---- 先读 JSON 配置，再让显式传入的 flag 覆盖 ----
	cfg := defaultConfig()
	if n, err := loadConfigJSON(*cfgPath, cfg); err != nil {
		fmt.Printf("[config] 读取 %s 失败：%v（使用默认值）\n", *cfgPath, err)
	} else {
		fmt.Printf("[config] 已加载 %s（%d 项）\n", *cfgPath, n)
	}

	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

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

	// ---- 权限管理 ----
	pm := NewPermissionManager()
	if !*noElevate && !pm.HasElevatedFlag() && !pm.IsAdmin() {
		fmt.Println("[权限] 当前非管理员，尝试 UAC 提权重启（抓包/温度需要更高权限）...")
		if pm.Elevate() {
			fmt.Println("[权限] 已请求提权，本实例退出，请在弹窗中确认。")
			return
		}
		fmt.Println("[权限] 提权被拒绝，继续以普通权限运行（部分熵源可能降级）。")
	}
	fmt.Printf("[权限] 管理员=%v 提权参数=%v\n", pm.IsAdmin(), pm.HasElevatedFlag())

	// ---- 熵池 + 搅拌器 ----
	stirrer := NewHashStir(cfg.HashAlgo)
	pool := NewChaosEntropyPool(stirrer)
	pool.MixBytes(osRandom(64)) // 基础熵：保证即使所有外部源失败也有可用池

	// ---- 实例化各熵源 ----
	procCol := NewProcessSnapshotCollector(pool)
	sysCol := NewSystemEntropyCollector(pool)
	memCol := NewMemoryEntropyCollector(pool)
	diskCol := NewDiskEntropyCollector(pool)
	tempCol := NewTemperatureCollector(pool)
	inputCol := NewInputEntropyCollector(pool)
	wpCol := NewWeatherEntropyCollector(pool)
	contentCol := NewContentEntropyCollector(pool)
	pktCol := NewPacketCollector(pool)
	tpmCol := NewTPMEntropyCollector(pool)
	if tpmCol.Available() {
		defer tpmCol.Close()
	}

	caps := map[string]bool{
		"process": cfg.Sources.Process,
		"system":  cfg.Sources.System,
		"memory":  cfg.Sources.Memory,
		"disk":    cfg.Sources.Disk,
		"temp":    cfg.Sources.Temp,
		"input":   cfg.Sources.Input,
		"weather": cfg.Sources.Weather,
		"content": cfg.Sources.Content,
		"packet":  cfg.Sources.Packet,
		"tpm":     tpmCol.Available(),
		"onebot":  false,
	}

	// ---- OneBot ----
	var obCol *OneBotClient
	if cfg.Sources.OneBot {
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
			fmt.Printf("[OneBot] 已连接 %s(%d)，HTTP 拉取已启动\n", nick, uid)
		} else {
			fmt.Printf("[OneBot] HTTP 未就绪(%v)，将以轮询/事件持续重试\n", err)
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

	fmt.Println("Chaos RNG (Go / Windows) 启动，全熵源调度：")
	fmt.Printf("  进程/系统/内存/磁盘/温度/输入/天气/内容/抓包/TPM/OneBot = %v %v %v %v %v %v %v %v %v %v %v\n",
		capsSnapshot["process"], capsSnapshot["system"], capsSnapshot["memory"], capsSnapshot["disk"],
		capsSnapshot["temp"], capsSnapshot["input"], capsSnapshot["weather"], capsSnapshot["content"],
		capsSnapshot["packet"], capsSnapshot["tpm"], capsSnapshot["onebot"])

	// ---- 采集一次 ----
	collectOnce := func(verbose bool) {
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
				fmt.Printf("  [温度] 实测热区 %.1f C\n", float64(t)/10.0)
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
				fmt.Printf("  [天气] 成功抓取 %d 个城市温度\n", n)
			}
		}
		if cfg.Sources.Content {
			n := contentCol.FetchAll()
			if verbose {
				fmt.Printf("  [内容] 成功抓取 %d 个平台热榜\n", n)
			}
		}
		if cfg.Sources.Packet {
			n := pktCol.Collect(64)
			if verbose {
				fmt.Printf("  [抓包] 后端=%s 处理 %d 帧\n", pcapBackend(pktCol), n)
			}
		}
		if obCol != nil && verbose {
			h, w := obCol.Stats()
			fmt.Printf("  [OneBot] HTTP混入=%d WS事件混入=%d（零缓存）\n", h, w)
		}
	}

	// ---- 停止通知 ----
	stopped := make(chan struct{})
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(func() { close(stopped) }) }

	// ============ 长驻服务模式 ============
	if *serve {
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

		srv := NewTCPServer(pool, stirrer, cfg, capsSnapshot, obCol, cfg.TCPHost, cfg.TCPPort)
		if err := srv.Start(); err != nil {
			fmt.Printf("[TCP] 启动失败: %v\n", err)
			os.Exit(1)
		}
		defer srv.Stop()

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