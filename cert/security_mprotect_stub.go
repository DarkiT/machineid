//go:build !linux
// +build !linux

package cert

// mprotectLinux 在非 Linux 环境下为空操作，避免平台不支持的系统调用
func (sm *SecurityManager) mprotectLinux() error {
	return nil
}
