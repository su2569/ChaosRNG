//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// 权限管理：检测是否管理员，必要时 UAC 提权重启（--elevated 防无限循环）。
type PermissionManager struct {
	elevatedArg string
}

func NewPermissionManager() *PermissionManager { return &PermissionManager{elevatedArg: "--elevated"} }

var (
	procOpenProcessToken    = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modadvapi32.NewProc("GetTokenInformation")
	modshell32              = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteEx      = modshell32.NewProc("ShellExecuteExW")
	procGetCurrentProcess   = modkernel32.NewProc("GetCurrentProcess")
)

const tokenElevation = 20

// IsAdmin: 查询当前进程令牌的 TokenElevation。
func (pm *PermissionManager) IsAdmin() bool {
	var token syscall.Handle
	hProc, _, _ := procGetCurrentProcess.Call()
	r, _, _ := procOpenProcessToken.Call(hProc, 0x0008, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer syscall.CloseHandle(token)
	var elevation uint32
	var retLen uint32
	r2, _, _ := procGetTokenInformation.Call(uintptr(token), tokenElevation,
		uintptr(unsafe.Pointer(&elevation)), uintptr(4),
		uintptr(unsafe.Pointer(&retLen)))
	if r2 == 0 {
		return false
	}
	return elevation != 0
}

type seiExecInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         syscall.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     syscall.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hKeyClass    syscall.Handle
	dwHotKey     uint32
	hProcess     uintptr
}

// Elevate: 以 runas 动词重启自身（触发 UAC）。
func (pm *PermissionManager) Elevate() bool {
	args := os.Args[1:]
	hasElev := false
	for _, a := range args {
		if a == pm.elevatedArg {
			hasElev = true
		}
	}
	if !hasElev {
		args = append(args, pm.elevatedArg)
	}
	params := strings.Join(quoteArgs(args), " ")

	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(os.Args[0])
	p, _ := syscall.UTF16PtrFromString(params)

	var sei seiExecInfo
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	sei.fMask = 0x00000040
	sei.lpVerb = verb
	sei.lpFile = file
	sei.lpParameters = p
	sei.nShow = 1
	r, _, _ := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		return false
	}
	if sei.hProcess != 0 {
		syscall.CloseHandle(syscall.Handle(sei.hProcess))
	}
	return true
}

// HasElevatedFlag: 命令行是否带 --elevated。
func (pm *PermissionManager) HasElevatedFlag() bool {
	for _, a := range os.Args[1:] {
		if a == pm.elevatedArg {
			return true
		}
	}
	return false
}

func quoteArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.ContainsAny(a, " \t\"") {
			out = append(out, "\""+strings.ReplaceAll(a, "\"", "\\\"")+"\"")
		} else {
			out = append(out, a)
		}
	}
	return out
}
