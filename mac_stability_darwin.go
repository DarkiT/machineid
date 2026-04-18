//go:build darwin
// +build darwin

package machineid

import (
	"net"
	"strings"
)

// inferInterfaceStabilityPlatform macOS 平台 MAC 稳定性检测
func inferInterfaceStabilityPlatform(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)

	// 排除已知的虚拟接口
	virtualPrefixes := []string{
		"lo",        // 回环
		"bridge",    // 网桥
		"utun",      // 用户空间隧道 (VPN)
		"ipsec",     // IPSec
		"gif",       // 通用隧道
		"stf",       // 6to4 隧道
		"awdl",      // Apple Wireless Direct Link
		"llw",       // Low Latency WLAN
		"ap",        // 接入点
		"vmnet",     // VMware
		"vboxnet",   // VirtualBox
		"vnic",      // 虚拟网卡
		"tap",       // TAP 设备
		"tun",       // TUN 设备
		"feth",      // 虚拟以太网
		"zt",        // ZeroTier
		"tailscale", // Tailscale
		"wg",        // WireGuard
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	// 物理网卡通常是 en0, en1 等
	if strings.HasPrefix(name, "en") {
		// 进一步检查是否为真正的物理网卡
		return isPhysicalMacOSInterface(name)
	}

	return false
}

// isPhysicalMacOSInterface 检查是否为 macOS 物理网卡
func isPhysicalMacOSInterface(ifaceName string) bool {
	// 使用 networksetup 检查网卡类型
	output, err := commandOutput("networksetup", "-listallhardwareports")
	if err != nil {
		// 无法执行命令时，根据名称判断
		// en0 通常是内置以太网或 Wi-Fi
		return strings.HasPrefix(ifaceName, "en")
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Device: "+ifaceName) {
			// 检查上一行的硬件端口类型
			if i > 0 {
				portLine := lines[i-1]
				// 物理端口类型
				physicalPorts := []string{
					"Ethernet",
					"Wi-Fi",
					"Thunderbolt",
					"USB Ethernet",
				}
				for _, port := range physicalPorts {
					if strings.Contains(portLine, port) {
						return true
					}
				}
				// 虚拟端口类型
				virtualPorts := []string{
					"Bridge",
					"Bluetooth",
					"iPhone USB",
					"Thunderbolt Bridge",
				}
				for _, port := range virtualPorts {
					if strings.Contains(portLine, port) {
						return false
					}
				}
			}
		}
	}

	// 默认 en0, en1 认为是物理网卡
	return strings.HasPrefix(ifaceName, "en")
}

// isKnownVirtualInterface macOS 平台检查是否为已知虚拟接口
func isKnownVirtualInterface(name string) bool {
	name = strings.ToLower(name)
	virtualPrefixes := []string{
		"lo",
		"bridge",
		"utun",
		"ipsec",
		"gif",
		"stf",
		"awdl",
		"llw",
		"ap",
		"vmnet",
		"vboxnet",
		"vnic",
		"tap",
		"tun",
		"feth",
		"zt",
		"tailscale",
		"wg",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
