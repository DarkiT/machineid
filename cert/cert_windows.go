//go:build windows
// +build windows

package cert

import (
	"syscall"
	"time"
	"unsafe"
)

func checkDebugger() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	ntdll := syscall.NewLazyDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	handle, _ := syscall.GetCurrentProcess()
	var debug int32
	ntQueryInformationProcess.Call(
		uintptr(handle),
		uintptr(7), // ProcessDebugPort
		uintptr(unsafe.Pointer(&debug)),
		uintptr(4),
		uintptr(0),
	)
	return debug != 0
}

func getSystemBootTime() time.Time {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount64.Call()
	uptime := time.Duration(ret) * time.Millisecond
	return time.Now().Add(-uptime)
}
