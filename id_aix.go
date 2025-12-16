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
	trimmed := strings.ToUpper(strings.TrimSpace(string(out)))
	if isContainerEnvironment() {
		if cid := getContainerID(); cid != "" {
			if normalized := normalizeContainerIDCandidate(cid); normalized != "" {
				return strings.ToUpper(normalized), nil
			}
			return strings.ToUpper(trim(cid)), nil
		}
		if scoped := deriveContainerScopedID(trimmed); scoped != "" {
			return scoped, nil
		}
	}
	return trimmed, nil
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
		if value := os.Getenv(envVar); value != "" {
			if normalized := normalizeContainerIDCandidate(value); normalized != "" {
				return strings.ToUpper(normalized)
			}
		}
	}
	return ""
}
