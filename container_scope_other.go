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

func init() {
	allowK8sEnvHint = func() bool {
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			return true
		}
		if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
			return true
		}
		if os.Getenv("POD_NAME") != "" || os.Getenv("POD_UID") != "" {
			return true
		}
		return false
	}
}
