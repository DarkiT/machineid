//go:build linux
// +build linux

package cert

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var processStartTime = getProcessStartTime()

func checkDebugger() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			return pid != "0"
		}
	}
	return false
}

func getSystemBootTime() time.Time {
	// 从 /proc/uptime 读取系统运行时间
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return processStartTime
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return processStartTime
	}

	uptime, err := time.ParseDuration(fields[0] + "s")
	if err != nil {
		return processStartTime
	}

	return time.Now().Add(-uptime)
}

func getProcessStartTime() time.Time {
	// 读取 /proc/self/stat 获取进程启动时间
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return time.Now()
	}

	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return time.Now()
	}

	// 第22个字段是进程启动时间（以系统启动后的时钟滴答数表示）
	var startTicks int64
	if _, err := fmt.Sscanf(fields[21], "%d", &startTicks); err != nil {
		return time.Now()
	}

	// 获取系统时钟频率
	clockTicks := int64(100) // 大多数Linux系统默认为100
	if startTicks > 0 {
		// 计算进程启动时间
		uptime := time.Duration(startTicks) * time.Second / time.Duration(clockTicks)
		return time.Now().Add(-uptime)
	}

	return time.Now()
}
