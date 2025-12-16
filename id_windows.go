//go:build windows
// +build windows

package machineid

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// machineID returns the key MachineGuid in registry `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`.
// If there is an error running the commad an empty string is returned.
func machineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()

	s, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(s)
	if isContainerEnvironment() {
		if cid := getContainerID(); cid != "" {
			if normalized := normalizeContainerIDCandidate(cid); normalized != "" {
				return normalized, nil
			}
			return trim(cid), nil
		}
		if scoped := deriveContainerScopedID(trimmed); scoped != "" {
			return scoped, nil
		}
	}
	return trimmed, nil
}

// isContainerEnvironment Windows下的容器检测
func isContainerEnvironment() bool {
	// Windows容器检测相对简单，主要检查环境变量
	envVars := []string{
		"CONTAINER_ID",
		"DOCKER_CONTAINER_ID",
		"SERVER_NAME", // Windows容器常用
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
