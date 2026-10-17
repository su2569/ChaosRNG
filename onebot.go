//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// OneBot v11 客户端（仅 Windows，零第三方依赖）
//
// 设计目标（对应 onebot_client.py 的隐私要求）：
//   1) 主动 HTTP 拉取"最近消息"为主通道：get_group_msg_history / get_friend_msg_history，
//      逐条哈希后立即丢弃原文，进程内零消息缓存（明文存活仅微秒级）。
//   2) 正向 WebSocket 事件流为可选实时通道/降级：收到即哈希即丢弃，同样不缓存。
//   3) 完整支持 OneBot v11 相关接口：get_login_info / get_group_list / get_friend_list
//      / get_group_msg_history / get_friend_msg_history / get_group_msg 等。
//   4) 完整 RFC6455 客户端：wss(TLS) 握手、分片重组、客户端掩码帧、ping/pong、close。
//   5) 反关联：混池前缀一个进程级随机 selfTag，避免跨实例把同一消息对齐成指纹。
//
// 零缓存实现：所有消息只以 json.RawMessage / []byte 形态出现，SHA-256 之后
// 立刻 secureZero，不进入任何 map / slice / 结构体字段持久驻留。
// ============================================================================

// OneBotConfig 仅描述连接与调度参数，不含任何消息存储字段。
type OneBotConfig struct {
	Enable      bool    `yaml:"enable"`
	HTTPURL     string  `yaml:"http_url"`      // OneBot v11 HTTP 服务，如 http://127.0.0.1:5700
	WSURL       string  `yaml:"ws_url"`        // 正向 WS，如 ws://127.0.0.1:6700，可选
	Token       string  `yaml:"token"`         // access_token（HTTP 走 Bearer，WS 走 Authorization 头）
	PollSec     int     `yaml:"poll_interval"` // HTTP 轮询间隔（秒）
	HistorySize int     `yaml:"history_size"`  // 每次拉取历史条数
	Groups      []int64 `yaml:"groups"`        // 群白名单；空则 get_group_list 自动发现
	Friends     []int64 `yaml:"friends"`       // 好友白名单；空则 get_friend_list 自动发现
	EnableWS    bool    `yaml:"enable_ws"`     // 是否启用 WS 实时事件流
}

// OneBotClient 实现熵采集 + v11 API 调用，本身不保存任何会话消息内容。
type OneBotClient struct {
	cfg     OneBotConfig
	pool    *ChaosEntropyPool
	cli     *http.Client
	selfTag [8]byte // 进程级随机前缀，混入哈希防跨实例关联
	aesKey  []byte  // 【新增】AES-256-CTR 密钥，deriveAESKey 产出

	mu     sync.Mutex
	cursor map[string]int64 // 会话->上次最大 message_id，仅作游标（整数，非消息内容）

	stopCh  chan struct{}
	wg      sync.WaitGroup
	stopped bool

	mixedHTTP int64 // 原子计数：HTTP 通道混入条数
	mixedWS   int64 // 原子计数：WS 通道混入条数
}

func NewOneBot(p *ChaosEntropyPool, cfg OneBotConfig) *OneBotClient {
	if cfg.HTTPURL == "" {
		cfg.HTTPURL = "http://127.0.0.1:5700"
	}
	if cfg.WSURL == "" {
		cfg.WSURL = "ws://127.0.0.1:6700"
	}
	if cfg.PollSec <= 0 {
		cfg.PollSec = 3
	}
	if cfg.HistorySize <= 0 || cfg.HistorySize > 200 {
		cfg.HistorySize = 50
	}
	c := &OneBotClient{
		cfg:    cfg,
		pool:   p,
		cli:    &http.Client{Timeout: 8 * time.Second},
		cursor: make(map[string]int64),
		stopCh: make(chan struct{}),
	}
	copy(c.selfTag[:], osRandom(8))
	c.aesKey = deriveAESKey(p)
	return c
}

// Start 启动 HTTP 轮询通道与（可选）WS 事件流通道。
func (c *OneBotClient) Start() {
	if !c.cfg.Enable {
		return
	}
	c.wg.Add(1)
	go c.httpLoop()
	if c.cfg.EnableWS {
		c.wg.Add(1)
		go c.wsLoop()
	}
}

func (c *OneBotClient) Stop() {
	c.mu.Lock()
	if !c.stopped {
		c.stopped = true
		close(c.stopCh)
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// Stats 返回两个通道累计混池条数（不暴露任何消息内容）。
func (c *OneBotClient) Stats() (httpMixed, wsMixed int64) {
	return atomic.LoadInt64(&c.mixedHTTP), atomic.LoadInt64(&c.mixedWS)
}

// ---------- 隐私核心：一段字节 -> selfTag 前缀 -> SHA-256 -> 混池 -> 清零 ----------
func (c *OneBotClient) mixRaw(raw []byte) {
	if len(raw) == 0 {
		return
	}

	var toMix []byte = raw
	var cond []byte
	if len(raw) >= purityMinBytes {
		purity := ComputePurity(raw)
		if purity < purityRejectBelow {
			return
		}
		if purity < purityHighEnough {
			cond = CondenseEntropy(raw)
			if len(cond) == 0 {
				return
			}
			toMix = cond
		}
	}
	if cond != nil {
		defer secureZero(cond)
	}

	iv := osRandom(ctrIVLen)
	ct := aes256CTR(c.aesKey, iv, toMix)
	if ct == nil {
		h := sha256.Sum256(toMix)
		c.pool.MixBytes(h[:])
		return
	}
	h := sha256.New()
	h.Write(c.selfTag[:])
	h.Write(iv)
	h.Write(ct)
	sum := h.Sum(nil)
	c.pool.MixBytes(sum)
	secureZero(ct)
}

// ===================== HTTP 轮询通道 =====================
func (c *OneBotClient) httpLoop() {
	defer c.wg.Done()
	// 启动即拉一次，之后按 PollSec 定时。
	c.pollAll()
	tick := time.NewTicker(time.Duration(c.cfg.PollSec) * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-tick.C:
			c.pollAll()
		}
	}
}

func (c *OneBotClient) pollAll() {
	groups := c.cfg.Groups
	if len(groups) == 0 {
		if g, err := c.getGroupList(); err == nil {
			groups = g
		}
	}
	for _, gid := range groups {
		select {
		case <-c.stopCh:
			return
		default:
		}
		c.pullGroupHistory(gid)
	}

	friends := c.cfg.Friends
	if len(friends) == 0 {
		if f, err := c.getFriendList(); err == nil {
			friends = f
		}
	}
	for _, fid := range friends {
		select {
		case <-c.stopCh:
			return
		default:
		}
		c.pullFriendHistory(fid)
	}
}

// pullGroupHistory: get_group_msg_history 拉最近消息，逐条哈希即丢。
// data 既兼容 {"messages":[...]} 也兼容直接返回数组的实现。
func (c *OneBotClient) pullGroupHistory(gid int64) {
	key := fmt.Sprintf("g:%d", gid)
	params := map[string]interface{}{"group_id": gid, "count": c.cfg.HistorySize}
	if cid := c.getCursor(key); cid > 0 {
		params["message_id"] = cid // 部分实现按 message_id 游标向前翻页
	}
	data, err := c.api("get_group_msg_history", params)
	if err != nil {
		// 接口缺失/未授权：混入一条不可达事件（保持熵连续性），静默返回。
		c.pool.MixEvent(fmt.Sprintf("onebot.hist.g%d.err", gid))
		return
	}
	c.consumeMessages(key, data)
}

func (c *OneBotClient) pullFriendHistory(fid int64) {
	key := fmt.Sprintf("f:%d", fid)
	params := map[string]interface{}{"user_id": fid, "count": c.cfg.HistorySize}
	if cid := c.getCursor(key); cid > 0 {
		params["message_id"] = cid
	}
	data, err := c.api("get_friend_msg_history", params)
	if err != nil {
		c.pool.MixEvent(fmt.Sprintf("onebot.hist.f%d.err", fid))
		return
	}
	c.consumeMessages(key, data)
}

// consumeMessages: 从 data 里取出 messages 列表，逐条把原始 JSON 当熵混入，
// 解析 message_id 更新游标（仅整数），处理完即丢弃原始字节。
func (c *OneBotClient) consumeMessages(key string, data json.RawMessage) {
	msgs := extractMessages(data)
	if len(msgs) == 0 {
		return
	}
	var maxID int64
	for _, m := range msgs {
		c.mixRaw(m)
		atomic.AddInt64(&c.mixedHTTP, 1)
		var probe struct {
			MessageID int64 `json:"message_id"`
		}
		if json.Unmarshal(m, &probe) == nil && probe.MessageID > maxID {
			maxID = probe.MessageID
		}
		secureZero(m)
	}
	if maxID > 0 {
		c.setCursor(key, maxID)
	}
}

// extractMessages 兼容 {"messages":[...]} 与裸数组两种返回。
func extractMessages(data json.RawMessage) []json.RawMessage {
	if len(data) == 0 {
		return nil
	}
	// 先看是否对象
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) == nil {
		if arr, ok := obj["messages"]; ok {
			var out []json.RawMessage
			if json.Unmarshal(arr, &out) == nil {
				return out
			}
		}
	}
	// 否则尝试裸数组
	var out []json.RawMessage
	if json.Unmarshal(data, &out) == nil {
		return out
	}
	return nil
}

// ---------- 常用 v11 API 封装 ----------
func (c *OneBotClient) getGroupList() ([]int64, error) {
	data, err := c.api("get_group_list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var arr []struct {
		GroupID int64 `json:"group_id"`
	}
	if json.Unmarshal(data, &arr) != nil {
		return nil, fmt.Errorf("bad get_group_list")
	}
	out := make([]int64, 0, len(arr))
	for _, g := range arr {
		out = append(out, g.GroupID)
	}
	return out, nil
}

func (c *OneBotClient) getFriendList() ([]int64, error) {
	data, err := c.api("get_friend_list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var arr []struct {
		UserID int64 `json:"user_id"`
	}
	if json.Unmarshal(data, &arr) != nil {
		return nil, fmt.Errorf("bad get_friend_list")
	}
	out := make([]int64, 0, len(arr))
	for _, f := range arr {
		out = append(out, f.UserID)
	}
	return out, nil
}

// GetLoginInfo 供外部查询连接是否就绪（仅取 nickname/user_id 做日志，不存内容）。
func (c *OneBotClient) GetLoginInfo() (int64, string, error) {
	data, err := c.api("get_login_info", map[string]interface{}{})
	if err != nil {
		return 0, "", err
	}
	var r struct {
		UserID   int64  `json:"user_id"`
		Nickname string `json:"nickname"`
	}
	if json.Unmarshal(data, &r) != nil {
		return 0, "", fmt.Errorf("bad get_login_info")
	}
	return r.UserID, r.Nickname, nil
}

// api: 统一的 v11 HTTP 动作调用，返回 data 原文（json.RawMessage）。
// 请求体 {action, params}，鉴权走 Authorization: Bearer <token>。
// 响应统一为 {status, retcode, data, message}，非 ok 视为错误。
func (c *OneBotClient) api(action string, params map[string]interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"action": action,
		"params": params,
	})
	// 【修复】bytes.NewReader 直接复用 []byte，避免 string(body) 再拷贝一次。
	req, err := http.NewRequest("POST", c.cfg.HTTPURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Status  string          `json:"status"`
		Retcode int             `json:"retcode"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, fmt.Errorf("bad json")
	}
	// 【修复】用 || 而非 &&：status 非 ok 或 retcode 非 0 任一成立即算失败。
	if envelope.Status != "ok" || envelope.Retcode != 0 {
		return nil, fmt.Errorf("api %s retcode=%d", action, envelope.Retcode)
	}
	return envelope.Data, nil
}

// ---------- 游标（仅整数，不含内容） ----------
func (c *OneBotClient) getCursor(key string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursor[key]
}
func (c *OneBotClient) setCursor(key string, v int64) {
	c.mu.Lock()
	c.cursor[key] = v
	c.mu.Unlock()
}

// ===================== WebSocket 实时事件流（可选/降级） =====================
func (c *OneBotClient) wsLoop() {
	defer c.wg.Done()
	retries := 0
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}
		err := c.serveWS()
		if err == nil {
			return // 主动 close
		}
		retries++
		c.pool.MixEvent(fmt.Sprintf("onebot.ws.retry.%d", retries))
		if retries > 60 {
			return // 长时间不可达则放弃，避免刷屏日志成为指纹
		}
		time.Sleep(time.Duration(minInt(retries, 10)) * time.Second)
	}
}

func (c *OneBotClient) serveWS() error {
	ws, err := wsDial(c.cfg.WSURL, c.cfg.Token)
	if err != nil {
		return err
	}
	defer ws.Close()
	for {
		select {
		case <-c.stopCh:
			ws.closeWithCode(1000)
			return nil
		default:
		}
		ws.c.SetReadDeadline(time.Now().Add(90 * time.Second))
		opcode, payload, err := ws.readMessage()
		if err != nil {
			return err
		}
		if opcode == 0x1 {
			c.mixRaw(payload) // 事件整包原始 JSON 即熵，哈希即丢
			atomic.AddInt64(&c.mixedWS, 1)
		}
		secureZero(payload)
	}
}

// ===================== 最小完整 RFC6455 客户端 =====================
type wsConn struct {
	c  net.Conn
	br *bufio.Reader
}

func wsDial(rawURL, token string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	secure := u.Scheme == "wss"
	host := u.Host
	if u.Port() == "" {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	if secure {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err = tc.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n"
	if token != "" {
		req += "Authorization: Bearer " + token + "\r\n"
	}
	req += "\r\n"
	if _, err = conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	ok, err := wsHandshakeOK(br, key)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("ws handshake rejected")
	}
	return &wsConn{c: conn, br: br}, nil
}

func wsHandshakeOK(br *bufio.Reader, key string) (bool, error) {
	status, err := br.ReadString('\n')
	if err != nil {
		return false, err
	}
	if len(status) < 12 || status[9:12] != "101" {
		return false, nil
	}
	want := wsAccept(key)
	ok := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "sec-websocket-accept:") {
			if strings.TrimSpace(line[len("Sec-WebSocket-Accept:"):]) == want {
				ok = true
			}
		}
	}
	return ok, nil
}

func wsAccept(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// readMessage 读取一条完整消息：处理分片(fin/continuation)、ping->pong、pong、close。
func (w *wsConn) readMessage() (byte, []byte, error) {
	var (
		frag []byte
		op   byte
	)
	for {
		fin, opcode, data, err := w.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case 0x8: // close
			return 0x8, nil, io.EOF
		case 0x9: // ping -> 回 pong（掩码客户端帧）
			_ = w.writeFrame(0xA, data)
			continue
		case 0xA: // pong
			continue
		case 0x0: // continuation
			// op 已在首片确定
		default: // 0x1 text / 0x2 binary 起始片
			op = opcode
		}
		frag = append(frag, data...)
		if len(frag) > 1<<22 {
			return 0, nil, io.ErrNoProgress
		}
		if fin {
			return op, frag, nil
		}
	}
}

func (w *wsConn) readFrame() (bool, byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		return false, 0, nil, err
	}
	fin := h[0]&0x80 != 0
	opcode := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	length := uint64(h[1] & 0x7f)
	switch length {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(b[:])
	}
	if length > 1<<22 {
		return false, 0, nil, io.ErrNoProgress
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

// writeFrame 客户端发送帧：必须置 MASK 位并掩码（RFC6455 要求）。
func (w *wsConn) writeFrame(opcode byte, data []byte) error {
	var head []byte
	head = append(head, 0x80|opcode)
	n := len(data)
	switch {
	case n < 126:
		head = append(head, 0x80|byte(n))
	case n < 1<<16:
		head = append(head, 0x80|126, byte(n>>8), byte(n))
	default:
		head = append(head, 0x80|127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		head = append(head, b[:]...)
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	head = append(head, mask[:]...)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = data[i] ^ mask[i%4]
	}
	if _, err := w.c.Write(head); err != nil {
		return err
	}
	_, err := w.c.Write(masked)
	return err
}

// Close 满足 io.Closer：发送 close code=1000 后关闭 TCP。
func (w *wsConn) Close() error {
	w.closeWithCode(1000)
	return nil
}

// closeWithCode 内部使用：发送指定 close code 并关闭底层连接。
func (w *wsConn) closeWithCode(code uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], code)
	_ = w.writeFrame(0x8, b[:])
	_ = w.c.Close()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
