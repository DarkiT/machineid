//go:build freebsd || netbsd || openbsd || dragonfly || solaris
// +build freebsd netbsd openbsd dragonfly solaris

package machineid

import (
	"bytes"
	"os"
)

const hostidPath = "/etc/hostid"

// machineID returns the uuid specified at `/etc/hostid`.
// If the returned value is empty, the uuid from a call to `kenv -q smbios.system.uuid` is returned.
// If there is an error an empty string is returned.
func machineID() (string, error) {
	id, err := readHostid()
	if err != nil {
		// try fallback
		id, err = readKenv()
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func readHostid() (string, error) {
	buf, err := readFile(hostidPath)
	if err != nil {
		return "", err
	}
	return trim(string(buf)), nil
}

func readKenv() (string, error) {
	buf := &bytes.Buffer{}
	err := run(buf, os.Stderr, "kenv", "-q", "smbios.system.uuid")
	if err != nil {
		return "", err
	}
	return trim(buf.String()), nil
}

// isContainerEnvironment BSD下的容器检测
func isContainerEnvironment() bool {
	// 检查Docker环境标识
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

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
