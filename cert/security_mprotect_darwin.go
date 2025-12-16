//go:build darwin
// +build darwin

package cert

import (
	"syscall"
	"unsafe"
)

// mprotect 在 macOS 环境下设置内存页权限
func (sm *SecurityManager) mprotect() error {
	if len(sm.memProtect) == 0 {
		return nil
	}

	// 获取内存地址和大小
	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	// 在 macOS 上，需要确保地址按页对齐
	// 获取页大小
	pageSize := uintptr(syscall.Getpagesize())

	// 对齐到页边界
	alignedPtr := ptr &^ (pageSize - 1)
	offset := ptr - alignedPtr
	alignedSize := (size + offset + pageSize - 1) &^ (pageSize - 1)

	// 调用 mprotect 系统调用设置为只读
	// int mprotect(void *addr, size_t len, int prot);
	// PROT_READ = 0x01 (只读)
	_, _, errno := syscall.Syscall(
		syscall.SYS_MPROTECT,
		alignedPtr,
		alignedSize,
		uintptr(syscall.PROT_READ),
	)

	if errno != 0 {
		// 如果 mprotect 失败（例如在某些受限环境中），静默失败
		// 这样不会阻止程序运行，只是内存保护不生效
		return nil
	}

	return nil
}

// mprotectReadWrite 将内存页权限恢复为可读写（用于需要修改内存时）
func (sm *SecurityManager) mprotectReadWrite() error {
	if len(sm.memProtect) == 0 {
		return nil
	}

	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	pageSize := uintptr(syscall.Getpagesize())
	alignedPtr := ptr &^ (pageSize - 1)
	offset := ptr - alignedPtr
	alignedSize := (size + offset + pageSize - 1) &^ (pageSize - 1)

	// 设置为可读写
	// PROT_READ | PROT_WRITE = 0x01 | 0x02 = 0x03
	_, _, errno := syscall.Syscall(
		syscall.SYS_MPROTECT,
		alignedPtr,
		alignedSize,
		uintptr(syscall.PROT_READ|syscall.PROT_WRITE),
	)

	if errno != 0 {
		return nil
	}

	return nil
}
