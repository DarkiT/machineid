//go:build aix
// +build aix

package machineid

import (
	"os"
	"os/exec"
	"strings"
)

func machineID() (string, error) {
	// AIX系统可以使用uname -u命令获取系统ID
	out, err := exec.Command("uname", "-u").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// isContainerEnvironment AIX下的容器检测（比较简单）
func isContainerEnvironment() bool {
	// 检查环境变量
	envVars := []string{
		"CONTAINER_ID",
		"DOCKER_CONTAINER_ID",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			return true
		}
	}
	return false
}

func getContainerID() string {
	envVars := []string{
		"CONTAINER_ID",
		"DOCKER_CONTAINER_ID",
		"HOSTNAME",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" && len(value) >= 12 {
			return value
		}
	}
	return ""
}
