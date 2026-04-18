//go:build linux
// +build linux

package machineid

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

// inferInterfaceStabilityPlatform Linux 平台 MAC 稳定性检测
// 通过读取 /sys/class/net/{iface}/addr_assign_type 判断
// 值为 "0" 表示硬件分配（稳定），其他值表示软件分配（不稳定）
func inferInterfaceStabilityPlatform(iface net.Interface) bool {
	assignTypePath := filepath.Join("/sys/class/net", iface.Name, "addr_assign_type")
	data, err := os.ReadFile(assignTypePath)
	if err != nil {
		// 无法读取时，检查是否为已知的虚拟接口类型
		return !isKnownVirtualInterface(iface.Name)
	}
	typ := strings.TrimSpace(string(data))
	// addr_assign_type 值含义:
	// 0 = 硬件分配（稳定）
	// 1 = 软件分配（不稳定）
	// 2 = 随机分配（不稳定）
	// 3 = 从其他设备继承（可能不稳定）
	return typ == "0"
}

// isKnownVirtualInterface 检查是否为已知的虚拟接口
func isKnownVirtualInterface(name string) bool {
	name = strings.ToLower(name)
	virtualPrefixes := []string{
		"veth",      // Docker/容器虚拟以太网
		"docker",    // Docker 网桥
		"br-",       // 网桥
		"virbr",     // libvirt 网桥
		"vmnet",     // VMware
		"vboxnet",   // VirtualBox
		"zt",        // ZeroTier
		"tailscale", // Tailscale
		"tun",       // TUN 设备
		"tap",       // TAP 设备
		"wg",        // WireGuard
		"dummy",     // 虚拟设备
		"bond",      // 绑定设备
		"team",      // 团队设备
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
