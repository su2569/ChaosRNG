//go:build windows

package main

import (
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// ================= 系统运行抖动熵 =================
type SystemEntropyCollector struct {
	pool     *ChaosEntropyPool
	lastTick uint64
}

func NewSystemEntropyCollector(p *ChaosEntropyPool) *SystemEntropyCollector {
	return &SystemEntropyCollector{pool: p}
}

func (c *SystemEntropyCollector) Collect() {
	tick, _, _ := procGetTickCount64.Call()
	var gc runtime.MemStats
	runtime.ReadMemStats(&gc)
	var buf [40]byte
	buf[0] = byte(tick)
	buf[1] = byte(tick >> 8)
	buf[2] = byte(tick >> 16)
	buf[3] = byte(tick >> 24)
	buf[4] = byte(gc.NumGC)
	buf[5] = byte(gc.NumGC >> 8)
	buf[6] = byte(runtime.NumGoroutine())
	buf[7] = byte(gc.PauseTotalNs)
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		buf[8+i] = byte(ns >> uint(8*i))
	}
	var idle, kern, user syscall.Filetime
	if procGetSystemTimes.Find() == nil {
		procGetSystemTimes.Call(
			uintptr(unsafe.Pointer(&idle)),
			uintptr(unsafe.Pointer(&kern)),
			uintptr(unsafe.Pointer(&user)))
		buf[20] = byte(idle.LowDateTime ^ kern.LowDateTime ^ user.LowDateTime)
		buf[21] = byte(idle.HighDateTime ^ kern.HighDateTime ^ user.HighDateTime)
	}
	type memEx struct {
		dwLength     uint32
		dwMemoryLoad uint32
		ullTotalPhys uint64
		ullAvailPhys uint64
		_            [40]byte
	}
	var m memEx
	m.dwLength = uint32(unsafe.Sizeof(m))
	if procGlobalMemoryStatusEx.Find() == nil {
		procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
		buf[22] = byte(m.dwMemoryLoad)
		buf[23] = byte(m.ullAvailPhys)
		buf[24] = byte(m.ullAvailPhys >> 8)
	}
	c.pool.MixBytesFiltered(buf[:])
	c.lastTick = uint64(tick)
}

// ================= 内存熵 =================
type MemoryEntropyCollector struct{ pool *ChaosEntropyPool }

func NewMemoryEntropyCollector(p *ChaosEntropyPool) *MemoryEntropyCollector {
	return &MemoryEntropyCollector{pool: p}
}

func (c *MemoryEntropyCollector) Collect() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var b [32]byte
	local := make([]byte, 64)
	addr := uintptr(unsafe.Pointer(&local[0]))
	for i := 0; i < 8; i++ {
		b[i] = byte(addr >> uint(8*i))
	}
	for i := 0; i < 8; i++ {
		b[8+i] = byte(ms.NextGC >> uint(8*i))
	}
	for i := 0; i < 8; i++ {
		b[16+i] = byte(ms.TotalAlloc >> uint(8*i))
	}
	for i := 0; i < 4; i++ {
		b[24+i] = byte(ms.HeapAlloc >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
	secureZero(local)
}

// ================= 磁盘统计熵 =================
type DiskEntropyCollector struct{ pool *ChaosEntropyPool }

func NewDiskEntropyCollector(p *ChaosEntropyPool) *DiskEntropyCollector {
	return &DiskEntropyCollector{pool: p}
}

// 【修复】把 GetLogicalDrives / GetDiskFreeSpaceExW 提升为包级 LazyProc，
// 避免每次 Collect 重新构造。
var (
	procGetLogicalDrives    = modkernel32.NewProc("GetLogicalDrives")
	procGetDiskFreeSpaceExW = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetAsyncKeyState    = moduser32.NewProc("GetAsyncKeyState")
	procGetSystemPowerStatus = modkernel32.NewProc("GetSystemPowerStatus")
)

func (c *DiskEntropyCollector) Collect() {
	drivesRet, _, _ := procGetLogicalDrives.Call()
	drives := uint32(drivesRet)
	root, _ := syscall.UTF16PtrFromString("C:\\")
	// 三个输出参数各取一份：avail（调用者配额内可用）、total（盘总容量）、
	// totalFree（盘总空闲）。旧实现把 &freeBytes 同时传给 avail 和 totalFree，
	// avail 的结果被 totalFree 覆盖丢弃；此处修正并把 avail 也混入池。
	var freeAvailBytes, totalBytes, freeTotalBytes int64
	if procGetDiskFreeSpaceExW.Find() == nil {
		procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(root)),
			uintptr(unsafe.Pointer(&freeAvailBytes)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&freeTotalBytes)))
	}
	var b [24]byte
	for i := 0; i < 4; i++ {
		b[i] = byte(drives >> uint(8*i))
	}
	// freeAvailBytes 融进 drives 的高位，保持 b 布局（24 字节）不变
	b[0] ^= byte(freeAvailBytes)
	b[1] ^= byte(freeAvailBytes >> 8)
	b[2] ^= byte(freeAvailBytes >> 16)
	b[3] ^= byte(freeAvailBytes >> 24)
	for i := 0; i < 8; i++ {
		b[4+i] = byte(freeTotalBytes >> uint(8*i))
	}
	for i := 0; i < 8; i++ {
		b[12+i] = byte(totalBytes >> uint(8*i))
	}
	ns := time.Now().UnixNano()
	for i := 0; i < 4; i++ {
		b[20+i] = byte(ns >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}

// ================= 温度熵 =================
type TemperatureCollector struct {
	pool     *ChaosEntropyPool
	lastTent int32
}

func NewTemperatureCollector(p *ChaosEntropyPool) *TemperatureCollector {
	return &TemperatureCollector{pool: p}
}

func (c *TemperatureCollector) LastTenthsC() int32 { return c.lastTent }

func (c *TemperatureCollector) Collect() {
	if t, ok := readAcpiThermal(); ok {
		c.lastTent = t
		var b [8]byte
		for i := 0; i < 4; i++ {
			b[i] = byte(t >> uint(8*i))
		}
		ns := time.Now().UnixNano()
		for i := 0; i < 4; i++ {
			b[4+i] = byte(ns >> uint(8*i))
		}
		c.pool.MixBytesFiltered(b[:])
		return
	}
	var sysPow struct {
		ACLineStatus       byte
		BatteryFlag        byte
		BatteryLifePercent byte
		SystemStatusFlag   byte
		_                  uint32
	}
	if procGetSystemPowerStatus.Find() == nil {
		procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&sysPow)))
	}
	var b [16]byte
	b[0] = sysPow.ACLineStatus
	b[1] = sysPow.BatteryFlag
	b[2] = sysPow.BatteryLifePercent
	var cnt int64
	if procQueryPerformanceCounter.Find() == nil {
		procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&cnt)))
	}
	for i := 0; i < 8; i++ {
		b[4+i] = byte(cnt >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}

// ---------- ACPI 读取实现 ----------
var (
	modsetupapi                         = syscall.NewLazyDLL("setupapi.dll")
	procSetupDiGetClassDevs             = modsetupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInterfaces     = modsetupapi.NewProc("SetupDiEnumDeviceInterfacesW")
	procSetupDiGetDeviceInterfaceDetail = modsetupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	procSetupDiDestroyDeviceInfoList    = modsetupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procDeviceIoControl                 = modkernel32.NewProc("DeviceIoControl")
	procCreateFileW                     = modkernel32.NewProc("CreateFileW")
	procCloseHandle                     = modkernel32.NewProc("CloseHandle")
)

// GUID_DEVCLASS_ACPI = {4d36e97d-e325-11ce-bfc1-08002be10318}
var guidACPI = syscall.GUID{
	Data1: 0x4d36e97d, Data2: 0xe325, Data3: 0x11ce,
	Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
}

const (
	// IOCTL_ACPI_THERMAL_READ_TEMPERATURE =
	//     CTL_CODE(FILE_DEVICE_ACPI=0x32, 0x02, METHOD_BUFFERED=0, FILE_READ_DATA=0x01)
	//   = (0x32 << 16) | (0x01 << 14) | (0x02 << 2) | 0
	//   = 0x00324008
	//
	// 旧值 0x00220000|0x80000000 = 0x80220000 是错误的：
	//   - 0x0022 是 FILE_DEVICE_UNKNOWN，不是 FILE_DEVICE_ACPI(0x32)
	//   - 0x80000000 是 GENERIC_READ，不是 CTL_CODE 的 Access 位段
	//   - DeviceIoControl 必然返回 ERROR_INVALID_FUNCTION，温度永远拿不到。
	ioctlAcpiThermalReadTemp = 0x00324008

	// CreateFileW 的 dwDesiredAccess 必须是 GENERIC_READ，
	// 因为 IOCTL 的 access 是 FILE_READ_DATA，IO manager 会检查句柄权限。
	// 旧值 fileAnyAccess = 0 打开后无读权限，DeviceIoControl 会被拒绝。
	fileGenericRead    = 0x80000000
	fileShareReadWrite = 0x00000007
	openExisting       = 3
)

// 【修复】SP_DEVICE_INTERFACE_DATA 的 Reserved 是单个 ULONG_PTR（8 字节），
// 不是 [4]uintptr（32 字节）。旧版结构体 56 字节，cbSize 设 56，
// SetupDiEnumDeviceInterfaces 会以 ERROR_INVALID_USER_BUFFER 拒绝。
type spDeviceInterfaceData struct {
	cbSize         uint32
	InterfaceClass syscall.GUID
	Flags          uint32
	Reserved       uintptr
}

func readAcpiThermal() (int32, bool) {
	if procSetupDiGetClassDevs.Find() != nil ||
		procSetupDiDestroyDeviceInfoList.Find() != nil ||
		procSetupDiEnumDeviceInterfaces.Find() != nil ||
		procSetupDiGetDeviceInterfaceDetail.Find() != nil ||
		procCreateFileW.Find() != nil ||
		procDeviceIoControl.Find() != nil ||
		procCloseHandle.Find() != nil {
		return 0, false
	}
	hdev, _, _ := procSetupDiGetClassDevs.Call(
		uintptr(unsafe.Pointer(&guidACPI)), 0, 0,
		uintptr(0x00000002|0x00000010))
	if hdev == uintptr(0xffffffffffffffff) || hdev == 0 {
		return 0, false
	}
	defer procSetupDiDestroyDeviceInfoList.Call(hdev)

	var ifd spDeviceInterfaceData
	ifd.cbSize = uint32(unsafe.Sizeof(ifd))
	for i := uint32(0); i < 16; i++ {
		r, _, _ := procSetupDiEnumDeviceInterfaces.Call(hdev, 0,
			uintptr(unsafe.Pointer(&guidACPI)), uintptr(i),
			uintptr(unsafe.Pointer(&ifd)))
		if r == 0 {
			break
		}
		var reqLen uint32
		procSetupDiGetDeviceInterfaceDetail.Call(hdev, uintptr(unsafe.Pointer(&ifd)), 0, 0,
			uintptr(unsafe.Pointer(&reqLen)), 0)
		if reqLen == 0 {
			continue
		}
		buf := make([]byte, reqLen)

		// 【修复】DETAIL_DATA.cbSize 必须是结构体头部大小：
		//   64 位 = 4(字节 cbSize) + 4(对齐填充) = 8
		//   32 位 = 4 + 2(WCHAR 对齐)         = 6
		// 旧代码写入 reqLen 直接被 API 拒绝。
		pathOff := uintptr(8)
		if unsafe.Sizeof(uintptr(0)) == 4 {
			*(*uint32)(unsafe.Pointer(&buf[0])) = 6
			pathOff = 4
		} else {
			*(*uint32)(unsafe.Pointer(&buf[0])) = 8
		}
		r2, _, _ := procSetupDiGetDeviceInterfaceDetail.Call(hdev, uintptr(unsafe.Pointer(&ifd)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(reqLen),
			uintptr(unsafe.Pointer(&reqLen)), 0)
		if r2 == 0 {
			continue
		}
		pathPtr := unsafe.Pointer(&buf[pathOff])
		h, _, _ := procCreateFileW.Call(uintptr(pathPtr), fileGenericRead,
			uintptr(fileShareReadWrite), 0, openExisting, 0, 0)
		if h == uintptr(0xffffffffffffffff) {
			continue
		}
		var outBuf [4]byte
		var bytesRet uint32
		r3, _, _ := procDeviceIoControl.Call(h, ioctlAcpiThermalReadTemp,
			0, 0, uintptr(unsafe.Pointer(&outBuf[0])), 4,
			uintptr(unsafe.Pointer(&bytesRet)), 0)
		procCloseHandle.Call(h)
		if r3 != 0 && bytesRet >= 4 {
			tenths := int32(outBuf[0]) | int32(outBuf[1])<<8 | int32(outBuf[2])<<16 | int32(outBuf[3])<<24
			tenths -= 2732
			if tenths > 0 && tenths < 2000 {
				return tenths, true
			}
		}
	}
	return 0, false
}

// ================= 输入抖动熵 =================
type InputEntropyCollector struct{ pool *ChaosEntropyPool }

func NewInputEntropyCollector(p *ChaosEntropyPool) *InputEntropyCollector {
	return &InputEntropyCollector{pool: p}
}

func (c *InputEntropyCollector) Collect() {
	// 【修复】使用包级 procGetAsyncKeyState，不再每次 Collect 重建。
	var b [24]byte
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(ns >> uint(8*i))
	}
	keys := []uintptr{0x01, 0x02, 0x04, 0x41, 0x20, 0x0D}
	if procGetAsyncKeyState.Find() == nil {
		for j, k := range keys {
			r, _, _ := procGetAsyncKeyState.Call(k)
			b[8+j] = byte(r)
		}
	}
	var cnt int64
	if procQueryPerformanceCounter.Find() == nil {
		procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&cnt)))
	}
	for i := 0; i < 8; i++ {
		b[16+i] = byte(cnt >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}