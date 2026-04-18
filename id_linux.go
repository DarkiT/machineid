//go:build linux
// +build linux

package machineid

import (
	"os"
	"path"
	"strings"
)

var (
	hostHardwareMachineIDProvider    = getPreferredHardwareMachineID
	containerScopedMachineIDProvider = deriveContainerScopedID
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
	containerID := getContainerID()
	isContainer := containerEnvDetector()

	baseID, err := readLinuxBaseMachineID()
	if err != nil {
		return "", err
	}

	if resolved, _ := resolvePreferredMachineID(baseID, containerID, isContainer); resolved != "" {
		return resolved, nil
	}

	return baseID, nil
}

func readLinuxBaseMachineID() (string, error) {
	envPathname := os.Getenv(ENV_VARNAME)
	userMachineID := path.Join(os.Getenv("HOME"), ".config", "machine-id")

	id, err := readFirstFile([]string{
		envPathname, dbusPath, dbusPathEtc, userMachineID,
	})
	if err != nil {
		id, err = readFile(linuxRandomUuid)
		if err == nil {
			if writeErr := writeFirstFile([]string{
				envPathname, dbusPathEtc, dbusPath, userMachineID,
			}, id); writeErr != nil {
				return "", writeErr
			}
		}
	}
	if err != nil {
		return "", err
	}
	return normalizeMachineIDValue(string(id)), nil
}

func normalizeMachineIDValue(value string) string {
	return strings.ToUpper(trim(value))
}

func resolvePreferredMachineID(baseID, containerID string, isContainer bool) (string, IDSource) {
	hostID := normalizeMachineIDValue(hostHardwareMachineIDProvider())
	containerID = normalizeMachineIDValue(containerID)
	scopedID := ""
	if isContainer {
		scopedID = normalizeMachineIDValue(containerScopedMachineIDProvider(baseID))
	}
	return resolvePreferredMachineIDCandidates(baseID, hostID, containerID, scopedID, isContainer)
}

func resolvePreferredMachineIDCandidates(baseID, hostID, containerID, scopedID string, isContainer bool) (string, IDSource) {
	if hostID != "" {
		return hostID, IDSourceHostHardware
	}
	if isContainer {
		if containerID != "" {
			return containerID, IDSourceContainerID
		}
		if scopedID != "" {
			return scopedID, IDSourceContainerScoped
		}
	}
	if normalizedBaseID := normalizeMachineIDValue(baseID); normalizedBaseID != "" {
		return normalizedBaseID, IDSourceMachineID
	}
	return "", IDSourceUnknown
}

func getContainerID() string {
	// 尝试多种方法检测容器ID

	// 方法1：检查 /proc/self/cgroup
	if id := getContainerIDFromCgroup(); id != "" {
		return strings.ToUpper(id)
	}

	// 方法2：检查 /proc/self/mountinfo
	if id := getContainerIDFromMountinfo(); id != "" {
		return strings.ToUpper(id)
	}

	// 方法3：检查环境变量
	if id := getContainerIDFromEnv(); id != "" {
		return strings.ToUpper(id)
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
			if candidate := extractContainerIDFromPath(line); candidate != "" {
				return candidate
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
		cgroupPath := field[3]
		if !strings.Contains(cgroupPath, "/docker/") &&
			!strings.Contains(cgroupPath, "/containers/") &&
			!strings.Contains(cgroupPath, "/containerd/") &&
			!strings.Contains(cgroupPath, "/sandboxes/") {
			continue
		}
		if candidate := extractContainerIDFromPath(cgroupPath); candidate != "" {
			return candidate
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
		if value := os.Getenv(envVar); value != "" {
			if candidate := normalizeContainerIDCandidate(value); candidate != "" {
				return candidate
			}
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

func extractContainerIDFromPath(path string) string {
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if candidate := normalizeContainerIDCandidate(seg); candidate != "" {
			return candidate
		}
	}
	return ""
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
