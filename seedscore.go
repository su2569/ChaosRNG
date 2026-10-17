//go:build windows || linux

package main

import (
	"encoding/hex"
	"math"
	"math/bits"
	"sync"
	"time"
)

// ============================================================================
// SeedScore —— 客户端推送种子的质量评分 + 去重 + 限流
//
// 目标：拒绝低熵 / 重复 / 模式化的种子，只让"看起来真随机"的混入池。
//
// 五个评分维度（0~100，越高越好）：
//   1. Monobit          0/1 位数均衡度         权重 35%
//   2. Shannon 熵       字节分布熵             权重 25%
//   3. Runs             0/1 交替段数均衡度     权重 15%
//   4. Unique bytes     32 字节里唯一值个数    权重 10%
//   5. XOR 差分熵       相邻字节 XOR 后的熵    权重 15%
//
// #5 专门用来抓递增序列 / 重复模式：这类种子在 #1~#4 上可能得分很高，
// 但相邻字节 XOR 后必然退化成常量，熵接近 0。
//
// 阈值策略：
//   score < pushScoreMin(30)              -> 拒绝
//   pushScoreMin ≤ score < pushScoreHigh  -> 先有损压缩(CondenseEntropy)再混入
//   score ≥ pushScoreHigh(90)             -> 直接混入
// ============================================================================

const (
	pushSeedBytes  = 32
	pushSeedHexLen = 64
	pushScoreMin   = 30.0 // 极低熵拒绝线（不压缩，直接拒绝）
	// pushScoreHigh 已改为动态阈值（purityThresholds），见 pushHexSeed 第 5 步
	pushRatePerSec = 2.0 // 默认值，可被 config.json 的 server.push_rate_per_sec 覆盖
	pushRateBurst  = 4   // 默认值，可被 config.json 的 server.push_rate_burst 覆盖
	pushRecentCap  = 64
	pushMinHamming = 40
)

// SeedScore 持有最近接受的种子，用于 Hamming 去重。
type SeedScore struct {
	mu        sync.Mutex
	recent    [pushRecentCap][pushSeedBytes]byte
	recentIdx int
	recentLen int
}

func NewSeedScore() *SeedScore { return &SeedScore{} }

// Score 评估单个 32 字节种子。返回 (总分 0~100, 是否通过 Hamming 去重)。
// Hamming 检查为 false 时，调用方应拒绝（reason="too_similar"）。
func (s *SeedScore) Score(seed []byte) (float64, bool) {
	if len(seed) != pushSeedBytes {
		return 0, false
	}

	// --- 1. Monobit ---
	ones := 0
	for _, b := range seed {
		ones += bits.OnesCount8(b)
	}
	dev := float64(ones) - 128.0
	if dev < 0 {
		dev = -dev
	}
	monobitScore := 100.0 - dev*(100.0/32.0)
	if monobitScore < 0 {
		monobitScore = 0
	}

	// --- 2. Shannon 熵 ---
	var freq [256]int
	for _, b := range seed {
		freq[b]++
	}
	var H float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(pushSeedBytes)
		H -= p * math.Log2(p)
	}
	shannonScore := H / 5.0 * 100.0
	if shannonScore > 100 {
		shannonScore = 100
	}

	// --- 3. Runs ---
	runs := 1
	prev := (seed[0] >> 7) & 1
	for _, b := range seed {
		for k := 7; k >= 0; k-- {
			bit := (b >> uint(k)) & 1
			if bit != prev {
				runs++
				prev = bit
			}
		}
	}
	runsDev := float64(runs) - 128.0
	if runsDev < 0 {
		runsDev = -runsDev
	}
	runsScore := 100.0 - runsDev*(100.0/64.0)
	if runsScore < 0 {
		runsScore = 0
	}

	// --- 4. Unique bytes ---
	uniq := 0
	for _, c := range freq {
		if c > 0 {
			uniq++
		}
	}
	uniqScore := float64(uniq) / 28.0 * 100.0
	if uniqScore > 100 {
		uniqScore = 100
	}

	// --- 5. XOR 差分熵 ---
	diff := make([]byte, 0, pushSeedBytes-1)
	for i := 0; i < pushSeedBytes-1; i++ {
		diff = append(diff, seed[i]^seed[i+1])
	}
	var dfreq [256]int
	for _, b := range diff {
		dfreq[b]++
	}
	var DH float64
	for _, c := range dfreq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(diff))
		DH -= p * math.Log2(p)
	}
	diffScore := DH / 4.9 * 100.0
	if diffScore > 100 {
		diffScore = 100
	}

	total := 0.35*monobitScore + 0.25*shannonScore +
		0.15*runsScore + 0.10*uniqScore + 0.15*diffScore

	return total, s.checkHamming(seed)
}

// checkHamming 与最近 pushRecentCap 个已接受种子比对。
// 与任意一个的距离 < pushMinHamming 就返回 false。
func (s *SeedScore) checkHamming(seed []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < s.recentLen; i++ {
		idx := (s.recentIdx - 1 - i + pushRecentCap) % pushRecentCap
		if hamming(seed, s.recent[idx][:]) < pushMinHamming {
			return false
		}
	}
	return true
}

// Record 把已接受的种子记入环形缓冲。
func (s *SeedScore) Record(seed []byte) {
	if len(seed) != pushSeedBytes {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copy(s.recent[s.recentIdx][:], seed)
	s.recentIdx = (s.recentIdx + 1) % pushRecentCap
	if s.recentLen < pushRecentCap {
		s.recentLen++
	}
}

func hamming(a, b []byte) int {
	d := 0
	for i := range a {
		d += bits.OnesCount8(a[i] ^ b[i])
	}
	return d
}

// ============================================================================
// pushLimiter —— 令牌桶限流（每连接一份 + 全局一份）
// ============================================================================

type pushLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func newPushLimiter(perSec float64, burst int) *pushLimiter {
	return &pushLimiter{
		tokens:   float64(burst),
		capacity: float64(burst),
		rate:     perSec,
		last:     time.Now(),
	}
}

// Allow 尝试消耗一个令牌。成功返回 (true, 0)；失败返回 (false, 建议等待毫秒)。
func (l *pushLimiter) Allow() (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapsed * l.rate
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	if l.tokens >= 1 {
		l.tokens -= 1
		return true, 0
	}
	need := (1 - l.tokens) / l.rate
	return false, int(need*1000) + 1
}

// ============================================================================
// PUSH_SEED 处理流程
// ============================================================================

var (
	globalPushLimiter = newPushLimiter(pushRatePerSec, pushRateBurst)
	globalSeedScore   = NewSeedScore()
)

type pushResult struct {
	OK      bool    `json:"ok"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason"`
	RetryMS int     `json:"retry_ms,omitempty"`
	Mixed   bool    `json:"mixed"`
}

// pushHexSeed 处理一条 `PUSH_SEED <hex>` 请求。
// 顺序：格式 → 评分 → 阈值 → 去重 → 全局限流 → 每连接限流 → 混池。
// 便宜检查在前，避免无效请求消耗限流配额。
//
// 混池策略：
//
//	score ≥ pushScoreHigh(90)  → 直接 MixBytes(raw)
//	score <  pushScoreHigh(90) → 先 CondenseEntropy(raw) 有损压缩，再 MixBytes(cond)
func pushHexSeed(pool *ChaosEntropyPool, perConn *pushLimiter, hexStr string) pushResult {
	// 1. 格式校验
	if len(hexStr) != pushSeedHexLen {
		return pushResult{Reason: "bad_length"}
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil || len(raw) != pushSeedBytes {
		return pushResult{Reason: "bad_hex"}
	}
	defer secureZero(raw)

	// 2. 评分
	score, passHamming := globalSeedScore.Score(raw)
	if score < pushScoreMin {
		return pushResult{Score: score, Reason: "low_entropy"}
	}
	if !passHamming {
		return pushResult{Score: score, Reason: "too_similar"}
	}

	// 3. 全局限流（先查全局，避免单客户端消耗所有配额）
	if ok, retry := globalPushLimiter.Allow(); !ok {
		return pushResult{Score: score, Reason: "rate_global", RetryMS: retry}
	}
	// 4. 每连接限流
	if perConn != nil {
		if ok, retry := perConn.Allow(); !ok {
			return pushResult{Score: score, Reason: "rate_conn", RetryMS: retry}
		}
	}

	// 5. 通过：记录 + 混池
	// 用动态阈值（与 MixBytesFiltered 一致），避免固定 90 过度压缩 32 字节种子
	globalSeedScore.Record(raw)
	_, highEnough := purityThresholds(len(raw))
	if score < highEnough {
		cond := CondenseEntropy(raw)
		if len(cond) > 0 {
			pool.MixBytes(cond)
			secureZero(cond)
		} else {
			pool.MixBytes(raw)
		}
	} else {
		pool.MixBytes(raw)
	}
	return pushResult{OK: true, Score: score, Reason: "accepted", Mixed: true}
}
