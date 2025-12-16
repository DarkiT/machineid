//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package cert

// mprotect 在不支持的平台上为空操作
func (sm *SecurityManager) mprotect() error {
	return nil
}
