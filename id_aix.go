//go:build aix
// +build aix

package machineid

import (
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
