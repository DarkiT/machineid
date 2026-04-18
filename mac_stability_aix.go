//go:build aix
// +build aix

package machineid

import (
	"net"
	"strings"
)

// inferInterfaceStabilityPlatform AIX 平台 MAC 稳定性检测
// AIX 缺少统一的稳定性接口，这里仅排除回环接口。
func inferInterfaceStabilityPlatform(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)
	if strings.HasPrefix(name, "lo") {
		return false
	}
	return true
}
