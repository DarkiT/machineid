//go:build windows
// +build windows

package machineid

import "os"

func defaultContainerHints() []string {
	hints := []string{}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		hints = append(hints, hostname)
	}
	if value := os.Getenv("COMPUTERNAME"); value != "" {
		hints = append(hints, value)
	}
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		hints = append(hints, domain)
	}
	return hints
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
