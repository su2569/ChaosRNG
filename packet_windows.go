//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// 抓包熵：优先 Npcap wpcap.dll（运行时动态加载，无需 SDK/lib），
// 回退 SIO_RCVALL 原始套接字。
// 载荷走 AES-256-CTR(随机IV) -> SHA256 -> 混池。
type PacketCollector struct {
	pool      *ChaosEntropyPool
	usedNpcap bool
	mu        sync.Mutex
	iface     string
	aesKey    []byte // AES-256-CTR 密钥，deriveAESKey 产出

	// 连续失败 ≥ 3 次时自动禁用
	// 用 int32 + atomic 避免 Collect/Probe（加锁）与 Disabled（无锁）数据竞争
	disabled            int32
	consecutiveFailures int32
}

func NewPacketCollector(p *ChaosEntropyPool) *PacketCollector {
	return &PacketCollector{
		pool:   p,
		aesKey: deriveAESKey(p),
	}
}

func (c *PacketCollector) UsingNpcap() bool { return c.usedNpcap }

var (
	modws232      = syscall.NewLazyDLL("ws2_32.dll")
	procWSAIoctl  = modws232.NewProc("WSAIoctl")
	procClosesock = modws232.NewProc("closesocket")
)

// ---------------- Npcap 动态加载 ----------------
type pcapHandles struct {
	openLive    *syscall.LazyProc
	close_      *syscall.LazyProc
	nextEx      *syscall.LazyProc
	lookupdev   *syscall.LazyProc
	findAllDevs *syscall.LazyProc
	freeAllDevs *syscall.LazyProc
	loaded      bool
}

var npc = func() *pcapHandles {
	if _, err := syscall.LoadLibrary("wpcap.dll"); err != nil {
		return &pcapHandles{}
	}
	m := syscall.NewLazyDLL("wpcap.dll")
	return &pcapHandles{
		openLive:    m.NewProc("pcap_open_live"),
		close_:      m.NewProc("pcap_close"),
		nextEx:      m.NewProc("pcap_next_ex"),
		lookupdev:   m.NewProc("pcap_lookupdev"),   // 旧 API，兼容性保留
		findAllDevs: m.NewProc("pcap_findalldevs"), // Npcap 1.x 推荐
		freeAllDevs: m.NewProc("pcap_freealldevs"),
		loaded:      true,
	}
}()

// pcapFirstDevName 优先用 pcap_findalldevs（Npcap 1.x 推荐），
// fallback 到 pcap_lookupdev（旧 API 兼容）。
func (c *PacketCollector) pcapFirstDevName() string {
	// 1. pcap_findalldevs
	if npc.findAllDevs.Find() == nil && npc.freeAllDevs.Find() == nil {
		var alldevs uintptr
		var errBuf [256]byte
		r, _, _ := npc.findAllDevs.Call(
			uintptr(unsafe.Pointer(&alldevs)),
			uintptr(unsafe.Pointer(&errBuf[0])))
		if r == 0 && alldevs != 0 {
			defer npc.freeAllDevs.Call(alldevs)
			// pcap_if 布局（64 位）：next(8) name(8) desc(8) addresses(8) flags(4)
			// 32 位：next(4) name(4) desc(4) addresses(4) flags(4)
			ptrSize := int(unsafe.Sizeof(uintptr(0)))
			nameOff := uintptr(ptrSize)      // next 之后
			flagsOff := uintptr(ptrSize * 4) // next+name+desc+addresses 之后
			cur := alldevs
			for cur != 0 {
				namePtr := *(*uintptr)(unsafe.Pointer(cur + nameOff))
				var flags uint32
				if ptrSize == 8 {
					flags = *(*uint32)(unsafe.Pointer(cur + flagsOff))
				} else {
					flags = *(*uint32)(unsafe.Pointer(cur + flagsOff))
				}
				// PCAP_IF_LOOPBACK = 0x1，跳过 loopback
				if namePtr != 0 && (flags&0x1) == 0 {
					name := cString(namePtr)
					if len(name) > 0 {
						return string(name)
					}
				}
				cur = *(*uintptr)(unsafe.Pointer(cur))
			}
		}
	}

	// 2. fallback: pcap_lookupdev（旧 API）
	if npc.lookupdev.Find() == nil {
		var errBuf [256]byte
		devRet, _, _ := npc.lookupdev.Call(uintptr(unsafe.Pointer(&errBuf[0])))
		if devRet != 0 {
			if name := cString(devRet); len(name) > 0 {
				return string(name)
			}
		}
	}

	return ""
}

// 【修复】Windows 上 pcap 内部使用的 struct timeval 是 {long tv_sec; long tv_usec;}，
// 64 位下 long=4 → 8 字节；而 Go 的 syscall.Timeval 在 64 位下是 {int64,int64}=16 字节。
// 直接使用 unsafe.Sizeof(syscall.Timeval{}) 会导致 caplen 读到垃圾。
const pcapWinTimevalSize = 8

func (c *PacketCollector) collectViaNpcap(count int) int {
	if !npc.loaded {
		return 0
	}
	if npc.openLive.Find() != nil ||
		npc.close_.Find() != nil ||
		npc.nextEx.Find() != nil ||
		npc.lookupdev.Find() != nil {
		return 0
	}
	devName := c.pcapFirstDevName()
	if devName == "" {
		return 0
	}
	var errBuf [256]byte
	nameBytes := []byte(devName)
	nameBytes = append(nameBytes, 0)
	h, _, _ := npc.openLive.Call(
		uintptr(unsafe.Pointer(&nameBytes[0])),
		65535, 1, 200, uintptr(unsafe.Pointer(&errBuf[0])))
	if h == 0 {
		return 0
	}
	defer npc.close_.Call(h)

	n := 0
	deadline := time.Now().Add(2 * time.Second)
	for n < count && time.Now().Before(deadline) {
		var hdrPtr, dataPtr uintptr
		r, _, _ := npc.nextEx.Call(h,
			uintptr(unsafe.Pointer(&hdrPtr)),
			uintptr(unsafe.Pointer(&dataPtr)))
		if r != 1 {
			continue
		}
		// 【修复】使用 Windows pcap 的 timeval 大小，而非 Go syscall.Timeval
		caplen := binary.LittleEndian.Uint32(
			ptrBytes(hdrPtr+uintptr(pcapWinTimevalSize), 4))
		if caplen == 0 || caplen > 65535 {
			continue
		}
		frame := ptrBytes(dataPtr, int(caplen))
		payload := extractIPv4Payload(frame)
		c.mixEncrypted(payload)
		n++
	}
	return n
}

// ---------------- SIO_RCVALL 回退（保持不变） ----------------
// collectViaRawSocket 用 SIO_RCVALL 原始套接字采集帧。
//
// Windows SIO_RCVALL 要求：
//  1. socket 必须先 bind 到具体网卡 IP
//  2. 需要管理员权限
//  3. 防火墙/杀软可能拦截（WFP 过滤）
//
// 遍历所有非 loopback 的 IPv4 网卡，逐个尝试 bind + WSAIoctl，
// 成功的那个就用它收帧。
func (c *PacketCollector) collectViaRawSocket(count int) int {
	ifs, err := net.Interfaces()
	if err != nil {
		LogDebug("packet", "SIO_RCVALL: net.Interfaces 失败: %v", err)
		return 0
	}

	// 收集所有候选网卡 IP（跳过 loopback / 虚拟网卡优先策略见下）
	type candidate struct {
		ip   net.IP
		ifi  net.Interface
		prio int // 越小越优先
	}
	var candidates []candidate

	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 {
			continue // 网卡未启用
		}

		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue
			}
			// 优先级：物理网卡 > 虚拟网卡；已连接 > 未连接
			prio := 50
			name := strings.ToLower(ifi.Name)
			isVirtual := strings.Contains(name, "vmware") ||
				strings.Contains(name, "virtualbox") ||
				strings.Contains(name, "vethernet") ||
				strings.Contains(name, "hyper-v") ||
				strings.Contains(name, "wsl") ||
				strings.Contains(name, "loopback") ||
				strings.Contains(name, "tap") ||
				strings.Contains(name, "tun")
			if isVirtual {
				prio = 100
			} else {
				prio = 10
			}
			// APIPA (169.254.x.x) 通常意味着未连接
			if ip4[0] == 169 && ip4[1] == 254 {
				prio += 200
			}
			candidates = append(candidates, candidate{ip: ip4, ifi: ifi, prio: prio})
		}
	}

	if len(candidates) == 0 {
		LogDebug("packet", "SIO_RCVALL: 无可用 IPv4 网卡（需要非 loopback 已连接网卡）")
		return 0
	}

	// 按优先级排序
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].prio < candidates[i].prio {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// 逐个尝试
	for _, cand := range candidates {
		n := c.tryRawSocket(cand.ip, count)
		if n > 0 {
			LogDebug("packet", "SIO_RCVALL: %s (%s) 成功，处理 %d 帧",
				cand.ip.String(), cand.ifi.Name, n)
			return n
		}
	}
	LogDebug("packet", "SIO_RCVALL: 所有 %d 个网卡均失败", len(candidates))
	return 0
}

// tryRawSocket 在指定 IP 上尝试 SIO_RCVALL。
// 返回处理的帧数（0 表示失败或无帧）。
func (c *PacketCollector) tryRawSocket(ip net.IP, count int) int {
	LogDebug("packet", "SIO_RCVALL: 尝试 %s", ip.String())

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(syscall.IPPROTO_IP))
	if err != nil {
		LogDebug("packet", "SIO_RCVALL: socket() 失败: %v", err)
		return 0
	}
	defer procClosesock.Call(uintptr(fd))

	// 关键修复 1: bind 到目标 IP
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], ip.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		LogDebug("packet", "SIO_RCVALL: bind(%s) 失败: %v（可能需要管理员权限）", ip.String(), err)
		return 0
	}

	if procWSAIoctl.Find() != nil {
		LogDebug("packet", "SIO_RCVALL: WSAIoctl 不可用")
		return 0
	}

	// 关键修复 2: WSAIoctl(SIO_RCVALL) 在 bind 之后
	// 输入必须是 RCVALL_ON (DWORD=1)，不是 IP 地址。
	// IP 地址只用于 bind，WSAIoctl 的"输入缓冲区"是开关值。
	var rcvallOn uint32 = 1
	const sioRCVALL = uintptr(0x98000001)
	var bytesReturned uint32

	r1, _, errno := procWSAIoctl.Call(
		uintptr(fd), sioRCVALL,
		uintptr(unsafe.Pointer(&rcvallOn)), 4, // 输入：RCVALL_ON
		0, 0,
		uintptr(unsafe.Pointer(&bytesReturned)),
		0, 0)
	if r1 != 0 {
		LogDebug("packet", "SIO_RCVALL: WSAIoctl 失败: errno=%d（需要管理员 + 关闭杀软网络防护）", errno)
		return 0
	}

	// 收帧超时 1 秒，避免 recvfrom 永久阻塞
	_ = syscall.SetsockoptTimeval(fd, 0xffff, 0x1006, &syscall.Timeval{Sec: 1})

	buf := make([]byte, 65535)
	deadline := time.Now().Add(2 * time.Second)
	n := 0
	timeouts := 0
	for n < count && time.Now().Before(deadline) {
		nb, _, e := syscall.Recvfrom(fd, buf, 0)
		if e != nil || nb <= 0 {
			timeouts++
			if timeouts > 5 && n == 0 {
				// 连续超时且一帧没收到，说明这个网卡没流量
				break
			}
			continue
		}
		pkt := make([]byte, nb)
		copy(pkt, buf[:nb])
		c.mixEncrypted(pkt)
		secureZero(pkt)
		n++
	}
	return n
}

func (c *PacketCollector) Collect(count int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.LoadInt32(&c.disabled) != 0 {
		return 0
	}
	// 优先 Npcap
	if n := c.collectViaNpcap(count); n > 0 {
		c.usedNpcap = true
		atomic.StoreInt32(&c.consecutiveFailures, 0)
		return n
	}
	// 回退 SIO_RCVALL
	n := c.collectViaRawSocket(count)
	if n > 0 {
		atomic.StoreInt32(&c.consecutiveFailures, 0)
		return n
	}
	// 失败：累计，达到 3 次自动禁用
	atomic.AddInt32(&c.consecutiveFailures, 1)
	if atomic.LoadInt32(&c.consecutiveFailures) >= 3 {
		atomic.StoreInt32(&c.disabled, 1)
		LogWarn("packet",
			"连续 %d 次抓包失败，已自动禁用抓包熵源。建议安装 Npcap：https://npcap.com",
			c.consecutiveFailures)
	}
	return 0
}

// mixEncrypted: 随机 IV + AES-256-CTR -> SHA256(IV||CT) -> 混池。
func (c *PacketCollector) mixEncrypted(payload []byte) {
	if len(payload) == 0 {
		return
	}

	var toMix []byte = payload
	var cond []byte
	if len(payload) >= purityMinBytes {
		purity := ComputePurity(payload)
		if purity < purityRejectBelow {
			return
		}
		if purity < purityHighEnough {
			cond = CondenseEntropy(payload)
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
		return
	}
	h := sha256.New()
	h.Write(iv)
	h.Write(ct)
	sum := h.Sum(nil)
	c.pool.MixBytes(sum)
	secureZero(ct)
}

// extractIPv4Payload（保持不变）
func extractIPv4Payload(frame []byte) []byte {
	if len(frame) < 14 {
		return frame
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	off := 14
	if etherType == 0x8100 {
		if len(frame) < 18 {
			return frame
		}
		etherType = binary.BigEndian.Uint16(frame[16:18])
		off = 18
	}
	if etherType != 0x0800 {
		return frame
	}
	if len(frame) <= off {
		return frame
	}
	ip := frame[off:]
	if len(ip) < 20 {
		return ip
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return ip
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	end := ihl
	if total > 0 && total <= len(ip) {
		end = total
	}
	return ip[ihl:end]
}

func cString(ptr uintptr) []byte {
	if ptr == 0 {
		return nil
	}
	out := make([]byte, 0, 64)
	for i := uintptr(0); i < 512; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + i))
		if b == 0 {
			break
		}
		out = append(out, b)
	}
	return out
}

func ptrBytes(ptr uintptr, n int) []byte {
	if n <= 0 || ptr == 0 {
		return nil
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
	}
	return b
}

// Probe 启动时探测抓包可用性。
// 返回 true 表示可用；false 表示不可用（自动设 disabled = true）。
//
// 探测方式：试抓 1 帧，成功（或 Npcap 加载成功但无流量）即可用。
// 注意：试抓 0 帧也算可用——可能只是当前网卡没流量，
//
//	真正不可用是 SIO_RCVALL 报错（WSAIoctl 失败）。
func (c *PacketCollector) Probe() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.LoadInt32(&c.disabled) != 0 {
		return false
	}

	// 1. 试 Npcap（如果已安装）
	if npc.loaded {
		if c.probeNpcap() {
			c.usedNpcap = true
			return true
		}
	}

	// 2. 试 SIO_RCVALL
	if c.probeRawSocket() {
		return true
	}

	atomic.StoreInt32(&c.disabled, 1)
	return false
}

// probeNpcap 检查 wpcap.dll 是否可加载 + open_live 成功 + 试抓 1 帧。
//
// 仅 open_live 成功不代表真可用（网卡无流量、权限不足等）。
// 试抓 1 帧才能确认，与 SIO_RCVALL 的 canRcvall 一致。
func (c *PacketCollector) probeNpcap() bool {
	if !npc.loaded {
		return false
	}
	if npc.openLive.Find() != nil || npc.close_.Find() != nil ||
		npc.nextEx.Find() != nil {
		return false
	}
	devName := c.pcapFirstDevName()
	if devName == "" {
		return false
	}
	var errBuf [256]byte
	nameBytes := []byte(devName)
	nameBytes = append(nameBytes, 0)
	h, _, _ := npc.openLive.Call(
		uintptr(unsafe.Pointer(&nameBytes[0])),
		65535, 1, 100, uintptr(unsafe.Pointer(&errBuf[0])))
	if h == 0 {
		return false
	}
	defer npc.close_.Call(h)

	// 试抓 1 帧（最多 500ms）
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		var hdrPtr, dataPtr uintptr
		r, _, _ := npc.nextEx.Call(h,
			uintptr(unsafe.Pointer(&hdrPtr)),
			uintptr(unsafe.Pointer(&dataPtr)))
		if r == 1 {
			caplen := binary.LittleEndian.Uint32(
				ptrBytes(hdrPtr+uintptr(pcapWinTimevalSize), 4))
			if caplen > 0 && caplen <= 65535 {
				LogDebug("packet", "启动探测：Npcap open_live + 试抓 %d 字节成功", caplen)
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	LogDebug("packet", "启动探测：Npcap open_live 成功但 500ms 内未收到帧（网卡可能无流量）")
	return false
}

// probeRawSocket 检查 SIO_RCVALL 是否可用（试开启，不实际收帧）。
func (c *PacketCollector) probeRawSocket() bool {
	ifs, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil {
				continue
			}
			if c.canRcvall(ip) {
				return true
			}
		}
	}
	return false
}

// canRcvall 试 bind + WSAIoctl，成功即可用。
// canRcvall 试 bind + WSAIoctl + 试抓 1 帧，都成功才算可用。
//
// 关键：Windows 上 WSAIoctl(SIO_RCVALL) 可能返回 0（成功），
// 但 WFP/防火墙深度拦截，recvfrom 收不到任何帧。
// 必须试抓 1 帧才能确认真正可用。
func (c *PacketCollector) canRcvall(ip net.IP) bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(syscall.IPPROTO_IP))
	if err != nil {
		return false
	}
	defer procClosesock.Call(uintptr(fd))

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], ip.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		LogDebug("packet", "启动探测：bind(%s) 失败: %v", ip.String(), err)
		return false
	}

	if procWSAIoctl.Find() != nil {
		return false
	}

	var rcvallOn uint32 = 1
	var bytesReturned uint32
	const sioRCVALL = uintptr(0x98000001)

	r1, _, errno := procWSAIoctl.Call(
		uintptr(fd), sioRCVALL,
		uintptr(unsafe.Pointer(&rcvallOn)), 4,
		0, 0,
		uintptr(unsafe.Pointer(&bytesReturned)),
		0, 0)
	if r1 != 0 {
		LogDebug("packet", "启动探测：WSAIoctl(%s) 失败 errno=%d", ip.String(), errno)
		return false
	}

	// WSAIoctl 成功，但必须试抓 1 帧才算真可用
	// 200ms 超时避免启动卡太久；有流量的话本地回环 200ms 足够抓到
	_ = syscall.SetsockoptTimeval(fd, 0xffff, 0x1006, &syscall.Timeval{Usec: 200000})

	buf := make([]byte, 1500)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		nb, _, e := syscall.Recvfrom(fd, buf, 0)
		if e == nil && nb > 0 {
			LogDebug("packet", "启动探测：SIO_RCVALL(%s) 成功，试抓 %d 字节", ip.String(), nb)
			return true
		}
		// 超时继续等，直到 500ms 总超时
	}

	LogDebug("packet", "启动探测：SIO_RCVALL(%s) WSAIoctl 成功但 500ms 内未收到帧（WFP 拦截或网卡无流量）", ip.String())
	return false
}

// Disabled 返回是否因连续失败被自动禁用或启动探测失败。
// 用 atomic 无锁读，不阻塞 Collect。
func (c *PacketCollector) Disabled() bool {
	return atomic.LoadInt32(&c.disabled) != 0
}
