//go:build !linux

package machineid

// isHexString 检查字符串是否全为十六进制字符（0-9a-fA-F）。
// 非 Linux 平台提供 stub，避免与 Linux 版本重复定义。
func isHexString(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}
