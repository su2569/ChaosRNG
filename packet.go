//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
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
	openLive  *syscall.LazyProc
	close_    *syscall.LazyProc
	nextEx    *syscall.LazyProc
	lookupdev *syscall.LazyProc
	loaded    bool
}

var npc = func() *pcapHandles {
	if _, err := syscall.LoadLibrary("wpcap.dll"); err != nil {
		return &pcapHandles{}
	}
	m := syscall.NewLazyDLL("wpcap.dll")
	return &pcapHandles{
		openLive:  m.NewProc("pcap_open_live"),
		close_:    m.NewProc("pcap_close"),
		nextEx:    m.NewProc("pcap_next_ex"),
		lookupdev: m.NewProc("pcap_lookupdev"),
		loaded:    true,
	}
}()

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
	var errBuf [256]byte
	devRet, _, _ := npc.lookupdev.Call(uintptr(unsafe.Pointer(&errBuf[0])))
	if devRet == 0 {
		return 0
	}
	nameBytes := cString(devRet)
	if len(nameBytes) == 0 {
		return 0
	}
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
func (c *PacketCollector) collectViaRawSocket(count int) int {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0
	}
	var ip net.IP
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				ip = ipn.IP.To4()
				break
			}
		}
		if ip != nil {
			break
		}
	}
	if ip == nil {
		return 0
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(syscall.IPPROTO_IP))
	if err != nil {
		return 0
	}
	defer procClosesock.Call(uintptr(fd))

	if procWSAIoctl.Find() != nil {
		return 0
	}

	var inaddr [4]byte
	copy(inaddr[:], ip)
	var bytesReturned uint32
	const sioRCVALL = uintptr(0x98000001)

	r1, _, _ := procWSAIoctl.Call(
		uintptr(fd), sioRCVALL,
		uintptr(unsafe.Pointer(&inaddr[0])), 4,
		0, 0,
		uintptr(unsafe.Pointer(&bytesReturned)),
		0, 0)
	if r1 != 0 {
		return 0
	}

	_ = syscall.SetsockoptTimeval(fd, 0xffff, 0x1006, &syscall.Timeval{Sec: 1})

	n := 0
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 65535)
	for n < count && time.Now().Before(deadline) {
		nb, _, e := syscall.Recvfrom(fd, buf, 0)
		if e != nil || nb <= 0 {
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
	if n := c.collectViaNpcap(count); n > 0 {
		c.usedNpcap = true
		return n
	}
	return c.collectViaRawSocket(count)
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