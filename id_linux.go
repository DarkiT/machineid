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
			writeFirstFile([]string{
				env_pathname, dbusPathEtc, dbusPath, userMachineId,
			}, id)
		}
	}

	return trim(string(id)), err
}

func getContainerID() string {
	containerID := ""
	content, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return containerID
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

		if strings.Index(cgroup_path, "/docker/") == -1 &&
			strings.Index(cgroup_path, "/containers/") == -1 &&
			strings.Index(cgroup_path, "/containerd/") == -1 &&
			strings.Index(cgroup_path, "/sandboxes/") == -1 {
			continue
		}

		pos := strings.Split(cgroup_path, "/")

		if len(pos) < 2 {
			continue
		}

		for _, containerID = range pos {
			docker_str := "docker-"
			if strings.Index(containerID, docker_str) > 0 {
				containerID = strings.ReplaceAll(containerID, docker_str, "")
			}
			if len(containerID) == 64 {
				return containerID
			}
		}
	}
	return containerID
}

func dockerEnvExist(_path string) bool {
	if _, err := os.Stat(_path); err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}
