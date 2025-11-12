//go:build linux
// +build linux

package cert

import (
	"syscall"
	"unsafe"
)

// mprotectLinux 仅在 Linux 环境下设置内存页权限
func (sm *SecurityManager) mprotectLinux() error {
	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	// 设置为只读
	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, ptr, size, syscall.PROT_READ)
	if errno != 0 {
		return errno
	}

	return nil
}
