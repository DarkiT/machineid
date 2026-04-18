//go:build windows

package cert

import (
	"syscall"
	"unsafe"
)

// isBeingDebuggedByPEB 通过 PEB 的 BeingDebugged 标志检测调试器。
//
// 使用 NtQueryInformationProcess(ProcessBasicInformation) 获取 PEB 地址。
var isBeingDebuggedByPEB = func() bool {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQueryInformationProcess")
	const ProcessBasicInformation = 0

	type processBasicInformation struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessID uintptr
		Reserved3       uintptr
	}

	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}

	var pbi processBasicInformation
	var retLen uintptr
	status, _, _ := proc.Call(
		uintptr(h),
		uintptr(ProcessBasicInformation),
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 || pbi.PebBaseAddress == 0 {
		return false
	}

	// PEB.BeingDebugged 偏移 0x2（byte）。
	beingDebugged := *(*byte)(unsafe.Pointer(pbi.PebBaseAddress + 2))
	return beingDebugged != 0
}
