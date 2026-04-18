//go:build windows && amd64

package cert

import (
	"syscall"
	"unsafe"
)

const (
	contextAmd64DebugRegisters = 0x00100010 // CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64
)

// 只定义到调试寄存器字段，避免引入完整 CONTEXT 结构的兼容风险。
// Windows x64 CONTEXT 中 Dr0-Dr7 位于前部固定位置。
type contextDebugAmd64 struct {
	P1Home      uint64
	P2Home      uint64
	P3Home      uint64
	P4Home      uint64
	P5Home      uint64
	P6Home      uint64
	ContextFlags uint32
	MxCsr       uint32
	SegCs       uint16
	SegDs       uint16
	SegEs       uint16
	SegFs       uint16
	SegGs       uint16
	SegSs       uint16
	EFlags      uint32
	Dr0         uint64
	Dr1         uint64
	Dr2         uint64
	Dr3         uint64
	Dr6         uint64
	Dr7         uint64
}

func hasHardwareBreakpoints() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getThreadContext := kernel32.NewProc("GetThreadContext")

	var ctx contextDebugAmd64
	ctx.ContextFlags = contextAmd64DebugRegisters

	// GetCurrentThread 返回伪句柄（无需 CloseHandle）。
	h, _, _ := kernel32.NewProc("GetCurrentThread").Call()
	ret, _, _ := getThreadContext.Call(
		h,
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		return false
	}

	// DR7: 启用位通常在低位；DR6: 状态位可能提示触发。
	// 这里将 DR0-DR3 非零作为强信号，DR7/DR6 作为辅助信号。
	if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 {
		return true
	}
	if ctx.Dr7 != 0 {
		return true
	}
	if ctx.Dr6 != 0 {
		return true
	}
	return false
}
