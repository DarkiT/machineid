//go:build windows
// +build windows

package cert

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// Windows 内存保护常量
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
)

// mprotect 在 Windows 环境下设置内存页权限
func (sm *SecurityManager) mprotect() error {
	if len(sm.memProtect) == 0 {
		return fmt.Errorf("memory protection buffer is empty")
	}

	// 获取 kernel32.dll 和 VirtualProtect 函数
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualProtect := kernel32.NewProc("VirtualProtect")

	// 获取内存地址和大小
	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	// 用于接收旧的保护属性
	var oldProtect uint32

	// 调用 VirtualProtect 设置为只读
	// BOOL VirtualProtect(
	//   LPVOID lpAddress,        // 要修改保护属性的内存起始地址
	//   SIZE_T dwSize,           // 要修改的区域大小（字节）
	//   DWORD  flNewProtect,     // 新的保护属性
	//   PDWORD lpflOldProtect    // 接收旧保护属性的指针
	// )
	ret, _, err := virtualProtect.Call(
		ptr,
		size,
		uintptr(PAGE_READONLY),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// 检查返回值（非零表示成功）
	if ret == 0 {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}

	return nil
}

// mprotectReadWrite 将内存页权限恢复为可读写（用于需要修改内存时）
func (sm *SecurityManager) mprotectReadWrite() error {
	if len(sm.memProtect) == 0 {
		return fmt.Errorf("memory protection buffer is empty")
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualProtect := kernel32.NewProc("VirtualProtect")

	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	var oldProtect uint32

	// 设置为可读写
	ret, _, err := virtualProtect.Call(
		ptr,
		size,
		uintptr(PAGE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret == 0 {
		return fmt.Errorf("VirtualProtect (read-write) failed: %v", err)
	}

	return nil
}
