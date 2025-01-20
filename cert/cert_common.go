//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package cert

import "time"

var processStartTime = time.Now() // 默认使用程序启动时间

// checkDebugger 检查是否存在调试器
func checkDebugger() bool {
	return false
}

// getSystemBootTime 获取系统启动时间
func getSystemBootTime() time.Time {
	return processStartTime
}
