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
