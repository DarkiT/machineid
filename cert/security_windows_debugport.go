//go:build windows

package cert

import (
	"syscall"
	"unsafe"
)

// isDebugPortPresent 通过 NtQueryInformationProcess 检测调试端口。
//
// ProcessDebugPort (7): 返回 -1 / 非 0 常表示被调试。
func isDebugPortPresent() bool {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQueryInformationProcess")
	const ProcessDebugPort = 7

	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}

	var debugPort uintptr
	var retLen uintptr
	status, _, _ := proc.Call(
		uintptr(h),
		uintptr(ProcessDebugPort),
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return false
	}

	// 文档/实现中常见约定：debugPort 为 0 表示无调试端口。
	return debugPort != 0
}

// isDebugObjectPresent 通过 NtQueryInformationProcess 检测调试对象句柄。
//
// ProcessDebugObjectHandle (30): 返回非 0 表示存在调试对象。
func isDebugObjectPresent() bool {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQueryInformationProcess")
	const ProcessDebugObjectHandle = 30

	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}

	var debugObject uintptr
	var retLen uintptr
	status, _, _ := proc.Call(
		uintptr(h),
		uintptr(ProcessDebugObjectHandle),
		uintptr(unsafe.Pointer(&debugObject)),
		unsafe.Sizeof(debugObject),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return false
	}
	return debugObject != 0
}

// isDebugFlagsSuspicious 通过 NtQueryInformationProcess 检测调试标志。
//
// ProcessDebugFlags (31): 常见约定是返回 1 表示未被调试，0 表示被调试。
func isDebugFlagsSuspicious() bool {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQueryInformationProcess")
	const ProcessDebugFlags = 31

	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}

	var flags uint32
	var retLen uintptr
	status, _, _ := proc.Call(
		uintptr(h),
		uintptr(ProcessDebugFlags),
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return false
	}

	// flags==0 通常表示被调试。
	return flags == 0
}
