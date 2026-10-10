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
	"strings"
	"sync/atomic"
	"time"
)

// TCPServer 提供 TCP 种子服务，协议兼容 Python 原版：
//   GET_SEED          -> [4B 长度][原始种子]            任何来源可访问
//   GET_HEX           -> hex 种子 + \n                   任何来源可访问
//   PING              -> PONG\n                          任何来源可访问
//   STATUS <key>      -> JSON 状态 + \n                  仅回环 + key 校验
//   CAPS              -> 能力 JSON + \n                  任何来源可访问
//   PUSH_SEED <hex>   -> JSON 结果 + \n                  任何来源可访问（有评分/限流）
//
// STATUS 双重门槛：来源必须 127.0.0.1/::1，且口令匹配（未配置 token 时回退 "114514"）。
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

// isLoopbackAddr 判断连接是否来自本机回环（127.0.0.0/8 或 ::1）。
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

	// 每个连接一份独立限流器；全局限流器在 seedscore.go
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

		case strings.HasPrefix(cmd, "PUSH_SEED ") || cmd == "PUSH_SEED":
			// 从原始行（保留大小写，hex 无碍）中截取参数
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

		case cmd == "CAPS":
			b, _ := json.Marshal(s.caps)
			w.Write(b)
			w.WriteByte('\n')
			w.Flush()

		default:
			w.WriteString("ERROR: GET_SEED GET_HEX PING STATUS <key> CAPS PUSH_SEED <hex>\n")
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
			"commands":      atomic.LoadInt64(&s.cmdsTotal),
		},
	}
}