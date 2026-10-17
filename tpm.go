//go:build windows

package main

import (
	"encoding/binary"
	"syscall"
	"time"
	"unsafe"
)

type TPMEntropyCollector struct {
	pool     *ChaosEntropyPool
	ctx      uintptr
	ctxReady bool
	avail    bool
}

var (
	mtbs          = syscall.NewLazyDLL("tbs.dll")
	procCtxCreate = mtbs.NewProc("Tbsi_Context_Create")
	procSubmit    = mtbs.NewProc("Tbsip_Submit_Command")
	procCloseCtx  = mtbs.NewProc("Tbsip_Context_Close")
	procGetInfo   = mtbs.NewProc("Tbsi_Get_Info")
)

func NewTPMEntropyCollector(p *ChaosEntropyPool) *TPMEntropyCollector {
	c := &TPMEntropyCollector{pool: p}
	if procCtxCreate.Find() == nil && procSubmit.Find() == nil {
		// 【修复】TBS_CONTEXT_PARAMS2 是 version(4) + 位域(4) 共 8 字节。
		// 位 0 = includeTpm12，位 1 = includeTpm20。
		var params struct {
			version uint32
			flags   uint32
		}
		params.version = 2
		params.flags = 0x3 // includeTpm12 | includeTpm20

		var ctx uintptr
		r, _, _ := procCtxCreate.Call(
			uintptr(unsafe.Pointer(&params)),
			uintptr(unsafe.Pointer(&ctx)))
		if r == 0 { // TBS_SUCCESS
			c.ctx = ctx
			c.ctxReady = true
			c.avail = true
		}
	}
	return c
}

func (c *TPMEntropyCollector) Available() bool { return c.avail }

// getRandom: TPM2_GetRandom 请求 n 字节（<=32）。
//
// 【修复】TPM2 响应布局：
//   tag(2) | responseSize(4) | responseCode(4) | size(2) | buffer[got]
//   偏移： 0       2               6               10        12
// 旧实现把 responseCode 读在 resp[10:14]，size 读在 [14:16]，
// 使得任何 GetRandom 都返回非零 code，硬件熵永远拿不到。
func (c *TPMEntropyCollector) getRandom(n int) ([]byte, bool) {
	if !c.ctxReady || n > 32 {
		return nil, false
	}
	cmd := make([]byte, 12)
	binary.BigEndian.PutUint16(cmd[0:2], 0x8001)      // TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint32(cmd[2:6], 12)          // commandSize
	binary.BigEndian.PutUint32(cmd[6:10], 0x0000017B) // TPM_CC_GetRandom
	binary.BigEndian.PutUint16(cmd[10:12], uint16(n)) // bytesRequested

	resp := make([]byte, 1024)
	respLen := uint32(len(resp))
	r, _, _ := procSubmit.Call(c.ctx, 3, 0,
		uintptr(unsafe.Pointer(&cmd[0])), uintptr(len(cmd)),
		uintptr(unsafe.Pointer(&resp[0])), uintptr(unsafe.Pointer(&respLen)))
	if r != 0 {
		secureZero(cmd)
		secureZero(resp)
		return nil, false
	}
	if respLen < 12 {
		secureZero(cmd)
		secureZero(resp)
		return nil, false
	}
	code := binary.BigEndian.Uint32(resp[6:10])
	if code != 0 {
		secureZero(cmd)
		secureZero(resp)
		return nil, false
	}
	got := int(binary.BigEndian.Uint16(resp[10:12]))
	if got <= 0 || 12+got > int(respLen) {
		secureZero(cmd)
		secureZero(resp)
		return nil, false
	}
	out := make([]byte, got)
	copy(out, resp[12:12+got])
	secureZero(cmd)
	secureZero(resp)
	return out, true
}

func (c *TPMEntropyCollector) Collect() {
	if randBytes, ok := c.getRandom(32); ok {
		c.pool.MixBytesFiltered(randBytes)
		secureZero(randBytes)
	}
	var b [16]byte
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(ns >> uint(8*i))
	}
	var cnt int64
	if procQueryPerformanceCounter.Find() == nil {
		procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&cnt)))
	}
	for i := 0; i < 8; i++ {
		b[8+i] = byte(cnt >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}

func (c *TPMEntropyCollector) Close() {
	if c.ctxReady && procCloseCtx.Find() == nil {
		procCloseCtx.Call(c.ctx)
		c.ctxReady = false
	}
}