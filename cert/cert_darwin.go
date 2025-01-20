//go:build darwin
// +build darwin

package cert

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var processStartTime = getProcessStartTime()

func getProcessStartTime() time.Time {
	pid := os.Getpid()
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=")
	output, err := cmd.Output()
	if err != nil {
		return time.Now()
	}

	// 解析 ps 命令输出的时间格式
	t, err := time.Parse("Mon Jan 2 15:04:05 2006", string(output))
	if err != nil {
		return time.Now()
	}
	return t
}

func checkDebugger() bool {
	// macOS 下可以通过 sysctl 检查
	cmd := exec.Command("sysctl", "kern.proc.pid."+strconv.Itoa(os.Getpid()))
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "P_TRACED")
}

func getSystemBootTime() time.Time {
	// macOS 下可以通过 sysctl 获取启动时间
	cmd := exec.Command("sysctl", "-n", "kern.boottime")
	output, err := cmd.Output()
	if err != nil {
		return processStartTime
	}

	// 解析输出格式: { sec = 1234567890, usec = 123456 }
	parts := strings.Fields(string(output))
	if len(parts) < 3 {
		return processStartTime
	}

	sec, err := strconv.ParseInt(strings.TrimRight(parts[2], ","), 10, 64)
	if err != nil {
		return processStartTime
	}

	return time.Unix(sec, 0)
}
