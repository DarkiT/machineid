//go:build linux
// +build linux

package cert

import (
	"syscall"
	"unsafe"
)

// mprotect 在 Linux 环境下设置内存页权限
//nolint:unused // 预留接口，避免静态检查误报
func (sm *SecurityManager) mprotect() error {
	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	// 设置为只读
	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, ptr, size, syscall.PROT_READ)
	if errno != 0 {
		return errno
	}

	return nil
}

// mprotectReadWrite 将内存页权限恢复为可读写（用于需要修改内存时）
//nolint:unused // 预留接口，避免静态检查误报
func (sm *SecurityManager) mprotectReadWrite() error {
	if len(sm.memProtect) == 0 {
		return nil
	}

	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, ptr, size, syscall.PROT_READ|syscall.PROT_WRITE)
	if errno != 0 {
		return errno
	}

	return nil
}
