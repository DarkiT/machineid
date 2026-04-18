//go:build windows && 386

package cert

import (
	"syscall"
	"unsafe"
)

const (
	contextI386DebugRegisters = 0x00010010 // CONTEXT_DEBUG_REGISTERS | CONTEXT_i386
)

// Windows x86 CONTEXT（简化到调试寄存器部分）。
type contextDebugI386 struct {
	ContextFlags uint32
	Dr0          uint32
	Dr1          uint32
	Dr2          uint32
	Dr3          uint32
	Dr6          uint32
	Dr7          uint32
}

func hasHardwareBreakpoints() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getThreadContext := kernel32.NewProc("GetThreadContext")

	var ctx contextDebugI386
	ctx.ContextFlags = contextI386DebugRegisters

	// GetCurrentThread 返回伪句柄（无需 CloseHandle）。
	h, _, _ := kernel32.NewProc("GetCurrentThread").Call()
	ret, _, _ := getThreadContext.Call(
		h,
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		return false
	}

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
