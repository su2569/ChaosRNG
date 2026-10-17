//go:build windows

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// TCPServer 协议（v2）：
//   GET_SEED            -> [4B 长度][32 字节种子]           任何人
//   GET_HEX             -> 64 hex + \n                      任何人
//   GET_SEEDS <n>       -> n*[4B 长度][32 字节种子]         任何人（n ≤ 1024）
//   RGBA [size]         -> [4B size][4B total][RGBA 字节流]  任何人（16 ≤ size ≤ 8192）
//   PING                -> PONG\n                            任何人
//   STATUS <key>        -> JSON 状态 + \n                    仅回环 + key
//   CAPS                -> JSON 能力 + \n                    任何人
//   PUSH_SEED <hex>     -> JSON 结果 + \n                    任何人（有评分/限流）
type TCPServer struct {
	pool     *ChaosEntropyPool
	stirrer  *HashStir
	cfg      *Config
	caps     map[string]bool
	obClient *OneBotClient

	host string
	port int

	startTime   time.Time
	seedsServed int64
	seedsPushed int64
	pushAccepts int64
	pushRejects int64
	rgbaServed  int64
	cmdsTotal   int64

	ln   net.Listener
	done chan struct{}
}

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
	fmt.Printf("[TCP] 监听 %s:%d\n", s.host, s.port)
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

func (s *TCPServer) handleConn(c net.Conn) {
	defer c.Close()
	addr := c.RemoteAddr().String()
	s.pool.MixEvent("pull:" + addr)

	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)

	perConn := newPushLimiter(pushRatePerSec, pushRateBurst)

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
		// ---------- GET_SEED ----------
		case cmd == "GET_SEED":
			seed := GenerateSeed(s.pool)
			var lb [4]byte
			binary.BigEndian.PutUint32(lb[:], uint32(len(seed)))
			w.Write(lb[:])
			w.Write(seed)
			w.Flush()
			secureZero(seed)
			atomic.AddInt64(&s.seedsServed, 1)

		// ---------- GET_HEX ----------
		case cmd == "GET_HEX":
			seed := GenerateSeed(s.pool)
			w.WriteString(hex.EncodeToString(seed) + "\n")
			w.Flush()
			secureZero(seed)
			atomic.AddInt64(&s.seedsServed, 1)

		// ---------- GET_SEEDS <n> ----------
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

		// ---------- RGBA [size] ----------
		case strings.HasPrefix(cmd, "RGBA"):
			size := 4096
			parts := strings.SplitN(raw, " ", 2)
			if len(parts) > 1 {
				if v, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					size = v
				}
			}
			// 安全钳制
			if size < 16 {
				size = 16
			}
			if size > 8192 {
				size = 8192
			}
			total := size * size * 4

			// 响应头: [4B size][4B total]
			var hdr [8]byte
			binary.BigEndian.PutUint32(hdr[0:4], uint32(size))
			binary.BigEndian.PutUint32(hdr[4:8], uint32(total))
			if _, err := w.Write(hdr[:]); err != nil {
				return
			}

			// 流式分块生成（每块 1 MB）
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

		// ---------- PING ----------
		case cmd == "PING":
			w.WriteString("PONG\n")
			w.Flush()

		// ---------- PUSH_SEED <hex> ----------
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

		// ---------- STATUS <key> ----------
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

		// ---------- CAPS ----------
		case cmd == "CAPS":
			b, _ := json.Marshal(s.caps)
			w.Write(b)
			w.WriteByte('\n')
			w.Flush()

		// ---------- MIX <hex> ----------
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
			purity := ComputePurity(data)
			if purity < purityRejectBelow {
				secureZero(data)
				w.WriteString(fmt.Sprintf("{\"ok\":false,\"reason\":\"low_purity\",\"purity\":%.1f}\n", purity))
				w.Flush()
				continue
			}
			// 纯度已在外部算好，直接按阈值决定用 raw 还是 condense，
			// 绕过 MixBytesFiltered 内部重复计算。
			var compressed []byte
			toMix := data
			if purity < purityHighEnough {
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

		default:
			w.WriteString("ERROR: GET_SEED GET_HEX GET_SEEDS <n> RGBA [size] PING STATUS <key> CAPS PUSH_SEED <hex> MIX <hex>\n")
			w.Flush()
		}
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
			"seeds_served":  atomic.LoadInt64(&s.seedsServed),
			"seeds_pushed":  atomic.LoadInt64(&s.seedsPushed),
			"push_accepts":  atomic.LoadInt64(&s.pushAccepts),
			"push_rejects":  atomic.LoadInt64(&s.pushRejects),
			"rgba_served":   atomic.LoadInt64(&s.rgbaServed),
			"commands":      atomic.LoadInt64(&s.cmdsTotal),
		},
	}
}