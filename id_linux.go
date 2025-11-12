//go:build linux
// +build linux

package machineid

import (
	"os"
	"path"
	"strings"
)

const (
	// the environment variable name pointing to the machine id pathname
	ENV_VARNAME = "MACHINE_ID_FILE"

	// dbusPath is the default path for dbus machine id.
	dbusPath = "/var/lib/dbus/machine-id"
	// dbusPathEtc is the default path for dbus machine id located in /etc.
	// Some systems (like Fedora 20) only know this path.
	// Sometimes it's the other way round.
	dbusPathEtc = "/etc/machine-id"

	// this returns a random uuid each time it's read
	linuxRandomUuid = "/proc/sys/kernel/random/uuid"
)

// machineID returns the uuid specified in the "canonical" locations. If not such value is found, one is generated and persisted.
// The machine id is looked in:
//   - the file pointed by the `MACHINE_ID_FILE` env var
//   - `/var/lib/dbus/machine-id`
//   - `/etc/machine-id`
//   - `$HOME/.config/machine-id`
//
// If no such file is found, a random uuid is generated and persisted in the first
// writable file among `$MACHINE_ID_FILE`, `/var/lib/dbus/machine-id`, `/etc/machine-id`, `$HOME/.config/machine-id`.
//
// If there is an error reading _all_ the files an empty string is returned.
// The logic implemented is a variation of the one described in https://github.com/denisbrodbeck/machineid/issues/5#issuecomment-523803164
// See also https://unix.stackexchange.com/questions/144812/generate-consistent-machine-unique-id
func machineID() (string, error) {
	isContainer := false

	env_pathname := os.Getenv(ENV_VARNAME)

	userMachineId := path.Join(os.Getenv("HOME"), ".config", "machine-id")

	containerID := getContainerID()

	if dockerEnvExist("/.dockerenv") || dockerEnvExist("/.dockerinit") || containerID != "" {
		isContainer = true
	}

	if isContainer {
		return trim(containerID), nil
	}

	id, err := readFirstFile([]string{
		env_pathname, dbusPath, dbusPathEtc, userMachineId,
	})
	if err != nil {
		id, err = readFile(linuxRandomUuid)
		if err == nil {
			if writeErr := writeFirstFile([]string{
				env_pathname, dbusPathEtc, dbusPath, userMachineId,
			}, id); writeErr != nil {
				return "", writeErr
			}
		}
	}

	return trim(string(id)), err
}

func getContainerID() string {
	// 尝试多种方法检测容器ID

	// 方法1：检查 /proc/self/cgroup
	if id := getContainerIDFromCgroup(); id != "" {
		return id
	}

	// 方法2：检查 /proc/self/mountinfo
	if id := getContainerIDFromMountinfo(); id != "" {
		return id
	}

	// 方法3：检查环境变量
	if id := getContainerIDFromEnv(); id != "" {
		return id
	}

	return ""
}

func getContainerIDFromCgroup() string {
	content, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "docker") || strings.Contains(line, "containerd") ||
			strings.Contains(line, "containers") || strings.Contains(line, "sandbox") {
			// 提取容器ID
			parts := strings.Split(line, "/")
			for _, part := range parts {
				// 清理docker前缀
				if strings.HasPrefix(part, "docker-") {
					part = strings.TrimPrefix(part, "docker-")
					part = strings.TrimSuffix(part, ".scope")
				}
				if len(part) == 64 && isHexString(part) {
					return part
				}
			}
		}
	}
	return ""
}

func getContainerIDFromMountinfo() string {
	content, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		field := strings.Split(line, " ")
		if len(field) < 10 {
			continue
		}
		cgroup_path := field[3]
		if len(cgroup_path) < 64 {
			continue
		}

		if !strings.Contains(cgroup_path, "/docker/") &&
			!strings.Contains(cgroup_path, "/containers/") &&
			!strings.Contains(cgroup_path, "/containerd/") &&
			!strings.Contains(cgroup_path, "/sandboxes/") {
			continue
		}

		pos := strings.Split(cgroup_path, "/")
		for _, containerID := range pos {
			if strings.HasPrefix(containerID, "docker-") {
				containerID = strings.TrimPrefix(containerID, "docker-")
				containerID = strings.TrimSuffix(containerID, ".scope")
			}
			if len(containerID) == 64 && isHexString(containerID) {
				return containerID
			}
		}
	}
	return ""
}

func getContainerIDFromEnv() string {
	// 检查常见的容器环境变量
	envVars := []string{
		"HOSTNAME",
		"CONTAINER_ID",
		"DOCKER_CONTAINER_ID",
		"POD_NAME",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" && len(value) == 64 && isHexString(value) {
			return value
		}
	}
	return ""
}

// isHexString 检查字符串是否为有效的十六进制字符串
func isHexString(s string) bool {
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if isDigit || isLowerHex || isUpperHex {
			continue
		}
		return false
	}
	return true
}

func dockerEnvExist(_path string) bool {
	if _, err := os.Stat(_path); err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

// isContainerEnvironment 检查是否在容器环境中运行
func isContainerEnvironment() bool {
	// 检查容器环境标识文件
	if dockerEnvExist("/.dockerenv") || dockerEnvExist("/.dockerinit") {
		return true
	}
	// 检查是否能获取到容器ID
	return getContainerID() != ""
}
