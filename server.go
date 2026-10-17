//go:build windows || linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TCPServer 协议（v3）：
//
//	GET_SEED                 -> [4B len][32B seed]                任何人
//	GET_HEX                  -> 64 hex + \n                       任何人
//	GET_SEEDS <n>            -> n*[4B len][32B seed]              n≤1024
//	RGBA [size]              -> [4B size][4B total][RGBA 流]       一次性，16≤size≤8192
//	RGBA_STREAM [size] [fps] -> 持续推送，每帧 [4B size][4B total][RGBA]
//	                           最长 60 秒；发 STOP/QUIT 或断开即终止
//	                           16≤size≤512；1≤fps≤60；并发上限 8
//	PUSH_SEED <hex>          -> JSON（评分+限流+有损压缩）
//	MIX <hex>                -> JSON（纯度筛选后混池）
//	PING                     -> PONG\n
//	STOP                     -> 中断当前 RGBA_STREAM
//	CAPS                     -> JSON 能力
//	STATUS <key>             -> JSON 状态（仅回环）
//	HELP [cmd]               -> 帮助
type TCPServer struct {
	pool     *ChaosEntropyPool
	stirrer  *HashStir
	cfg      *Config
	caps     map[string]bool
	obClient *OneBotClient

	host string
	port int

	startTime     time.Time
	seedsServed   int64
	seedsPushed   int64
	pushAccepts   int64
	pushRejects   int64
	rgbaServed    int64
	cmdsTotal     int64
	activeStreams int64

	ln   net.Listener
	done chan struct{}

	// 可选：由 main.go 注入，用于 STATUS 暴露实时状态
	eventCol *EventLogCollector
	pktCol   *PacketCollector
}

const (
	streamMaxDuration   = 60 * time.Second
	streamMaxSize       = 512
	streamMaxFPS        = 60
	streamMaxConcurrent = 8
)

func NewTCPServer(pool *ChaosEntropyPool, stirrer *HashStir, cfg *Config,
	caps map[string]bool, ob *OneBotClient, host string, port int) *TCPServer {
	frozen := make(map[string]bool, len(caps))
	for k, v := range caps {
		frozen[k] = v
	}
	return &TCPServer{
		pool:      pool,
		stirrer:   stirrer,
		cfg:       cfg,
		caps:      frozen,
		obClient:  ob,
		host:      host,
		port:      port,
		startTime: time.Now(),
		done:      make(chan struct{}),
	}
}

func (s *TCPServer) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.host, s.port))
	if err != nil {
		for p := s.port + 1; p < s.port+10; p++ {
			ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.host, p))
			if err == nil {
				s.port = p
				break
			}
		}
		if err != nil {
			return err
		}
	}
	s.ln = ln
	LogInfo("tcp", "监听 %s:%d（HELP 查看命令列表）", s.host, s.port)
	go s.acceptLoop()
	return nil
}

func (s *TCPServer) Stop() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	if s.ln != nil {
		s.ln.Close()
	}
}

func (s *TCPServer) Port() int { return s.port }

func (s *TCPServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		go s.handleConn(c)
	}
}

func isLoopbackAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// cmdInfo 用于 HELP 表格
type cmdInfo struct {
	Name string
	Args string
	Desc string
}

var allCmds = []cmdInfo{
	{"GET_SEED", "", "获取 32B 二进制种子（[4B len][seed]）"},
	{"GET_HEX", "", "获取 64 字符 hex 种子"},
	{"GET_SEEDS", "<n>", "批量种子，n≤1024，每帧 [4B len][32B]"},
	{"RGBA", "[size]", "一次性 RGBA 字节流，16≤size≤8192"},
	{"RGBA_STREAM", "[size] [fps]", "实时 RGBA 流，最长 60s，STOP 中断；size≤512 fps≤60"},
	{"PUSH_SEED", "<hex>", "推送 32B 种子（评分+限流+有损压缩）"},
	{"MIX", "<hex>", "推送任意长度字节（≤4KB），纯度筛选后混池"},
	{"PING", "", "心跳，返回 PONG"},
	{"STOP", "", "中断当前 RGBA_STREAM（QUIT 亦可）"},
	{"CAPS", "", "能力 JSON"},
	{"STATUS", "<key>", "状态 JSON（仅回环）"},
	{"HELP", "[cmd]", "显示帮助；HELP <cmd> 查看单条详情"},
}

func (s *TCPServer) handleConn(c net.Conn) {
	defer c.Close()
	addr := c.RemoteAddr().String()
	s.pool.MixEvent("pull:" + addr)

	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	perConn := newPushLimiter(s.cfg.PushRatePerSec, s.cfg.PushRateBurst)

	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		raw := strings.TrimSpace(line)
		cmd := strings.ToUpper(raw)
		atomic.AddInt64(&s.cmdsTotal, 1)

		switch {
		// ---------- 精确匹配优先 ----------
		case cmd == "GET_SEED":
			seed := GenerateSeed(s.pool)
			var lb [4]byte
			binary.BigEndian.PutUint32(lb[:], uint32(len(seed)))
			w.Write(lb[:])
			w.Write(seed)
			w.Flush()
			secureZero(seed)
			atomic.AddInt64(&s.seedsServed, 1)

		case cmd == "GET_HEX":
			seed := GenerateSeed(s.pool)
			w.WriteString(hex.EncodeToString(seed) + "\n")
			w.Flush()
			secureZero(seed)
			atomic.AddInt64(&s.seedsServed, 1)

		case cmd == "PING":
			w.WriteString("PONG\n")
			w.Flush()

		case cmd == "CAPS":
			b, _ := json.Marshal(s.caps)
			w.Write(b)
			w.WriteByte('\n')
			w.Flush()

		// ---------- RGBA_STREAM：必须放在 RGBA 之前 ----------
		case strings.HasPrefix(cmd, "RGBA_STREAM ") || cmd == "RGBA_STREAM":
			s.handleRGBAStream(c, r, w, raw)

		// ---------- 一次性 RGBA ----------
		case strings.HasPrefix(cmd, "RGBA ") || cmd == "RGBA":
			size := 4096
			parts := strings.SplitN(raw, " ", 2)
			if len(parts) > 1 {
				if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					size = v
				}
			}
			if size < 16 {
				size = 16
			}
			if size > 8192 {
				size = 8192
			}
			total := size * size * 4

			var hdr [8]byte
			binary.BigEndian.PutUint32(hdr[0:4], uint32(size))
			binary.BigEndian.PutUint32(hdr[4:8], uint32(total))
			if _, err := w.Write(hdr[:]); err != nil {
				return
			}

			const chunkBytes = 1 << 20
			written := 0
			for written < total {
				remain := total - written
				n := chunkBytes
				if n > remain {
					n = remain
				}
				seeds := (n + 31) / 32
				data := GenerateSeeds(s.pool, seeds)
				if len(data) < n {
					break
				}
				if _, err := w.Write(data[:n]); err != nil {
					secureZero(data)
					return
				}
				secureZero(data)
				written += n
			}
			w.Flush()
			atomic.AddInt64(&s.rgbaServed, 1)
			atomic.AddInt64(&s.seedsServed, int64((total+31)/32))

		// ---------- GET_SEEDS ----------
		case strings.HasPrefix(cmd, "GET_SEEDS"):
			n := 16
			parts := strings.SplitN(raw, " ", 2)
			if len(parts) > 1 {
				if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && v >= 1 && v <= 1024 {
					n = v
				}
			}
			seeds := GenerateSeeds(s.pool, n)
			var lb [4]byte
			for i := 0; i < n; i++ {
				binary.BigEndian.PutUint32(lb[:], 32)
				w.Write(lb[:])
				w.Write(seeds[i*32 : (i+1)*32])
			}
			w.Flush()
			secureZero(seeds)
			atomic.AddInt64(&s.seedsServed, int64(n))

		// ---------- PUSH_SEED ----------
		case strings.HasPrefix(cmd, "PUSH_SEED ") || cmd == "PUSH_SEED":
			hexArg := ""
			if len(raw) > len("PUSH_SEED ") {
				hexArg = strings.TrimSpace(raw[len("PUSH_SEED "):])
			}
			res := pushHexSeed(s.pool, perConn, hexArg)
			atomic.AddInt64(&s.seedsPushed, 1)
			if res.OK {
				atomic.AddInt64(&s.pushAccepts, 1)
			} else {
				atomic.AddInt64(&s.pushRejects, 1)
			}
			b, _ := json.Marshal(res)
			w.Write(b)
			w.WriteByte('\n')
			w.Flush()

		// ---------- MIX ----------
		case strings.HasPrefix(cmd, "MIX ") || cmd == "MIX":
			hexArg := ""
			if len(raw) > len("MIX ") {
				hexArg = strings.TrimSpace(raw[len("MIX "):])
			}
			if hexArg == "" {
				w.WriteString("{\"ok\":false,\"reason\":\"empty\"}\n")
				w.Flush()
				continue
			}
			data, derr := hex.DecodeString(hexArg)
			if derr != nil || len(data) == 0 {
				w.WriteString("{\"ok\":false,\"reason\":\"bad_hex\"}\n")
				w.Flush()
				continue
			}
			if len(data) > 4096 {
				data = data[:4096]
			}
			rejectBelow, highEnough := purityThresholds(len(data))
			purity := ComputePurity(data)
			if purity < rejectBelow {
				secureZero(data)
				w.WriteString(fmt.Sprintf("{\"ok\":false,\"reason\":\"low_purity\",\"purity\":%.1f}\n", purity))
				w.Flush()
				continue
			}
			var compressed []byte
			toMix := data
			if purity < highEnough {
				compressed = CondenseEntropy(data)
				if len(compressed) == 0 {
					secureZero(data)
					w.WriteString(fmt.Sprintf("{\"ok\":false,\"reason\":\"condense_failed\",\"purity\":%.1f}\n", purity))
					w.Flush()
					continue
				}
				toMix = compressed
			}
			s.pool.MixBytes(toMix)
			if compressed != nil {
				secureZero(compressed)
			}
			secureZero(data)
			w.WriteString(fmt.Sprintf("{\"ok\":true,\"purity\":%.1f}\n", purity))
			w.Flush()
			atomic.AddInt64(&s.seedsPushed, 1)
			atomic.AddInt64(&s.pushAccepts, 1)

		// ---------- STATUS ----------
		case strings.HasPrefix(cmd, "STATUS"):
			if !isLoopbackAddr(c.RemoteAddr()) {
				w.WriteString("FORBIDDEN: STATUS only from loopback (127.0.0.1 / ::1)\n")
				w.Flush()
				continue
			}
			parts := strings.SplitN(cmd, " ", 2)
			key := ""
			if len(parts) > 1 {
				key = strings.TrimSpace(parts[1])
			}
			if !s.checkStatusKey(key) {
				w.WriteString("FORBIDDEN: STATUS requires key\n")
				w.Flush()
				continue
			}
			b, _ := json.Marshal(s.status())
			w.Write(b)
			w.WriteByte('\n')
			w.Flush()

		// ---------- HELP ----------
		case cmd == "HELP" || strings.HasPrefix(cmd, "HELP "):
			parts := strings.SplitN(raw, " ", 2)
			arg := ""
			if len(parts) > 1 {
				arg = strings.TrimSpace(parts[1])
			}
			s.handleHelp(w, arg)

		// ---------- STOP / QUIT（无 stream 时提示）----------
		case cmd == "STOP" || cmd == "QUIT":
			w.WriteString("{\"ok\":false,\"reason\":\"no_stream\"}\n")
			w.Flush()

		default:
			w.WriteString("ERROR: unknown command. Send HELP to list all commands.\n")
			w.Flush()
		}
	}
}

// handleHelp 输出命令列表或单条详情。
func (s *TCPServer) handleHelp(w *bufio.Writer, arg string) {
	if arg == "" {
		w.WriteString("Chaos RNG TCP Commands (v3)\n")
		w.WriteString("--------------------------------------------------------------\n")
		for _, c := range allCmds {
			fmt.Fprintf(w, "  %-12s %-16s %s\n", c.Name, c.Args, c.Desc)
		}
		w.WriteString("--------------------------------------------------------------\n")
		w.WriteString("提示：HELP <cmd> 查看单条详情；RGBA_STREAM 期间只响应 STOP。\n")
		w.Flush()
		return
	}
	up := strings.ToUpper(arg)
	for _, c := range allCmds {
		if c.Name == up {
			fmt.Fprintf(w, "%s %s\n  %s\n", c.Name, c.Args, c.Desc)
			w.Flush()
			return
		}
	}
	w.WriteString("未知命令：" + arg + "，发送 HELP 查看列表。\n")
	w.Flush()
}

// handleRGBAStream 推送实时 RGBA 帧，最长 streamMaxDuration，
// 期间只响应 STOP / QUIT，或客户端断开。返回时恢复 5 分钟读超时。
//
// 字节格式（每帧独立、与一次性 RGBA 同构）：
//
//	[4B size BE][4B total BE][total 字节 RGBA]
//
// 客户端可逐帧解析，无需在连接建立时缓存尺寸。
func (s *TCPServer) handleRGBAStream(c net.Conn, r *bufio.Reader, w *bufio.Writer, raw string) {
	maxConcurrent := int64(s.cfg.StreamMaxConcurrent)
	if maxConcurrent <= 0 {
		maxConcurrent = 8
	}
	if atomic.LoadInt64(&s.activeStreams) >= maxConcurrent {
		w.WriteString("{\"ok\":false,\"reason\":\"too_many_streams\"}\n")
		w.Flush()
		return
	}

	// 解析 size [fps]
	size := 256
	fps := 20
	parts := strings.Fields(raw)
	if len(parts) > 1 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			size = v
		}
	}
	if len(parts) > 2 {
		if v, err := strconv.Atoi(parts[2]); err == nil {
			fps = v
		}
	}
	if size < 16 {
		size = 16
	}
	if size > streamMaxSize {
		size = streamMaxSize
	}
	if fps < 1 {
		fps = 1
	}
	if fps > streamMaxFPS {
		fps = streamMaxFPS
	}
	total := size * size * 4

	atomic.AddInt64(&s.activeStreams, 1)
	defer atomic.AddInt64(&s.activeStreams, -1)
	defer c.SetWriteDeadline(time.Time{}) // 退出时清空写超时，避免影响后续命令
	LogInfo("tcp", "RGBA_STREAM 开始 size=%d fps=%d 客户=%s", size, fps, c.RemoteAddr().String())

	// 每帧复用的 8B 头
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(size))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(total))

	maxDuration := time.Duration(s.cfg.StreamMaxDuration) * time.Second
	if maxDuration <= 0 {
		maxDuration = streamMaxDuration
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()

	// writer 退出原因：
	//   "timeout"     – 60s 到期
	//   "io_error"    – Write/Flush 失败（多为客户端断开）
	//   "canceled"    – 主 goroutine 调 cancel()（STOP/QUIT/读错误）
	// 主 goroutine 据此决定日志与响应文案。
	exitReason := make(chan string, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second / time.Duration(fps))
		defer ticker.Stop()
		seedsPerFrame := (total + 31) / 32
		for {
			select {
			case <-ctx.Done():
				select {
				case exitReason <- "timeout":
				default:
				}
				return
			case <-ticker.C:
				// 单帧 5 秒写超时，避免客户端读端停滞时 wg.Wait() 永久阻塞
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				data := GenerateSeeds(s.pool, seedsPerFrame)
				// 每帧发头 + 数据，客户端可逐帧解析
				if _, err := w.Write(hdr[:]); err != nil {
					secureZero(data)
					select {
					case exitReason <- "io_error":
					default:
					}
					return
				}
				if _, err := w.Write(data[:total]); err != nil {
					secureZero(data)
					select {
					case exitReason <- "io_error":
					default:
					}
					return
				}
				secureZero(data)
				if err := w.Flush(); err != nil {
					select {
					case exitReason <- "io_error":
					default:
					}
					return
				}
				atomic.AddInt64(&s.seedsServed, int64(seedsPerFrame))
			}
		}
	}()

	// 主 goroutine：轮询客户端输入识别 STOP，同时监听 writer 退出
	for {
		select {
		case reason := <-exitReason:
			wg.Wait()
			c.SetReadDeadline(time.Now().Add(5 * time.Minute))
			// io_error 时客户端已断开，write 会失败，忽略即可
			if reason == "timeout" {
				w.WriteString("{\"ok\":true,\"reason\":\"timeout\"}\n")
				w.Flush()
				LogInfo("tcp", "RGBA_STREAM 超时结束 客户=%s", c.RemoteAddr().String())
			} else if reason == "io_error" {
				LogWarn("tcp", "RGBA_STREAM 写入失败（客户端可能已断开）客户=%s", c.RemoteAddr().String())
			}
			return
		default:
		}

		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		line, err := r.ReadString('\n')
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			cancel()
			wg.Wait()
			LogWarn("tcp", "RGBA_STREAM 客户端断开 客户=%s", c.RemoteAddr().String())
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		if cmd == "STOP" || cmd == "QUIT" {
			cancel()
			wg.Wait()
			reason := "stopped"
			if cmd == "QUIT" {
				reason = "quit"
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Minute))
			w.WriteString("{\"ok\":true,\"reason\":\"" + reason + "\"}\n")
			w.Flush()
			LogInfo("tcp", "RGBA_STREAM %s 客户=%s", reason, c.RemoteAddr().String())
			return
		}
		// 其它命令忽略
	}
}

func (s *TCPServer) checkStatusKey(key string) bool {
	expected := s.cfg.OneBotToken
	if expected == "" {
		expected = "114514"
	}
	hKey := sha256.Sum256([]byte(key))
	hExp := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(hKey[:], hExp[:]) == 1
}

func (s *TCPServer) status() map[string]interface{} {
	uptime := int(time.Since(s.startTime).Seconds())
	digest := s.pool.Digest()
	modules := map[string]interface{}{}
	if s.obClient != nil {
		h, w := s.obClient.Stats()
		modules["onebot"] = map[string]interface{}{
			"http_mixed": h,
			"ws_mixed":   w,
		}
	}
	if s.pool.drbg != nil {
		tb, rt := s.pool.drbg.Stats()
		modules["csprng"] = map[string]interface{}{
			"backend":     s.pool.drbg.Name(),
			"total_bytes": tb,
			"ratchets":    rt,
		}
	}
	if s.eventCol != nil {
		accepted, unique := s.eventCol.Stats()
		attempted := s.eventCol.TotalAttempted()
		modules["eventlog"] = map[string]interface{}{
			"enabled":   !s.eventCol.Disabled(),
			"attempted": attempted,
			"accepted":  accepted,
			"unique":    unique,
			"disabled":  s.eventCol.Disabled(),
		}
	} else {
		modules["eventlog"] = map[string]interface{}{
			"enabled": false,
			"reason":  "pool_mode_or_disabled",
		}
	}
	if s.pktCol != nil {
		modules["packet"] = map[string]interface{}{
			"enabled":  !s.pktCol.Disabled(),
			"disabled": s.pktCol.Disabled(),
			"backend":  pcapBackend(s.pktCol),
		}
	} else {
		modules["packet"] = map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"entropy_pool": map[string]interface{}{
			"hash_prefix":    fmt.Sprintf("%x...", digest[:8]),
			"event_count":    s.pool.EventCount(),
			"stirred_bytes":  s.stirrer.TotalStirred(),
			"uptime_sec":     uptime,
			"hash_algorithm": s.stirrer.Algorithm(),
		},
		"capabilities": s.caps,
		"modules":      modules,
		"stats": map[string]interface{}{
			"seeds_served":   atomic.LoadInt64(&s.seedsServed),
			"seeds_pushed":   atomic.LoadInt64(&s.seedsPushed),
			"push_accepts":   atomic.LoadInt64(&s.pushAccepts),
			"push_rejects":   atomic.LoadInt64(&s.pushRejects),
			"rgba_served":    atomic.LoadInt64(&s.rgbaServed),
			"commands":       atomic.LoadInt64(&s.cmdsTotal),
			"active_streams": atomic.LoadInt64(&s.activeStreams),
		},
	}
}
