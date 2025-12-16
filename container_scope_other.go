//go:build !linux && !windows
// +build !linux,!windows

package machineid

import "os"

func defaultContainerHints() []string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return []string{hostname}
	}
	return nil
}
