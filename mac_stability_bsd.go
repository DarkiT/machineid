//go:build freebsd || openbsd || netbsd || dragonfly || solaris
// +build freebsd openbsd netbsd dragonfly solaris

package machineid

import (
	"net"
	"strconv"
	"strings"
)

var bsdCommandOutput = func(name string, args ...string) ([]byte, error) {
	return commandOutput(name, args...)
}

// inferInterfaceStabilityPlatform BSD/Solaris 平台 MAC 稳定性检测
// 结合 sysctl/ifconfig 的网卡类型信息，优先判断物理网卡。
func inferInterfaceStabilityPlatform(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)
	if isKnownVirtualInterface(name) {
		return false
	}

	if stable, ok := inferInterfaceStabilityFromSysctl(name); ok {
		return stable
	}
	if stable, ok := inferInterfaceStabilityFromIfconfig(name); ok {
		return stable
	}

	return true
}

func inferInterfaceStabilityFromSysctl(ifaceName string) (bool, bool) {
	oid := "net.link.ether.inet." + ifaceName + ".iftype"
	out, err := bsdCommandOutput("sysctl", "-n", oid)
	if err != nil {
		return false, false
	}

	value := strings.TrimSpace(string(out))
	if value == "" {
		return false, false
	}
	ifType, err := strconv.Atoi(value)
	if err != nil {
		return false, false
	}

	// 常见物理网卡类型：6 以太网，71 无线网卡
	switch ifType {
	case 6, 71:
		return true, true
	case 24, 131:
		return false, true
	default:
		return false, false
	}
}

func inferInterfaceStabilityFromIfconfig(ifaceName string) (bool, bool) {
	out, err := bsdCommandOutput("ifconfig", ifaceName)
	if err != nil {
		return false, false
	}

	info := strings.ToLower(string(out))
	if info == "" {
		return false, false
	}

	if strings.Contains(info, "loopback") || strings.Contains(info, "tunnel") || strings.Contains(info, "virtual") {
		return false, true
	}

	if strings.Contains(info, "link type: ethernet") || strings.Contains(info, "link type: ieee802.11") {
		return true, true
	}
	if strings.Contains(info, "encap: ethernet") || strings.Contains(info, "encap: ieee802.11") {
		return true, true
	}
	if strings.Contains(info, "encap:") {
		if strings.Contains(info, "loopback") || strings.Contains(info, "tunnel") {
			return false, true
		}
		if strings.Contains(info, "ethernet") || strings.Contains(info, "ieee802.11") || strings.Contains(info, "ieee 802.11") {
			return true, true
		}
		return false, true
	}

	if strings.Contains(info, "media:") {
		if strings.Contains(info, "ethernet") || strings.Contains(info, "ieee 802.11") || strings.Contains(info, "ieee802.11") {
			return true, true
		}
		return false, true
	}

	if strings.Contains(info, "lladdr ") || strings.Contains(info, "ether ") {
		return true, true
	}

	if strings.Contains(info, "status:") {
		if strings.Contains(info, "active") {
			return true, true
		}
		if strings.Contains(info, "no carrier") || strings.Contains(info, "inactive") {
			return false, true
		}
	}

	return false, false
}

// isKnownVirtualInterface BSD/Solaris 平台已知虚拟接口判断
func isKnownVirtualInterface(name string) bool {
	name = strings.ToLower(name)
	// 网络接口前缀分类
	virtualPrefixes := []string{
		// ========== 回环接口 ==========
		"lo", "loopback",

		// ========== 网桥与虚拟交换机 ==========
		"bridge", "br",

		// ========== 虚拟化与虚拟机 ==========
		"vbox",  // VirtualBox 虚拟网络接口
		"vmnet", // VMware 虚拟网络接口
		"vnic",  // 通用虚拟网卡 (可补充)
		"xn",    // Xen 虚拟网络接口

		// ========== 隧道与虚拟设备 ==========
		"tap",   // 虚拟以太网隧道 (TAP)
		"tun",   // 虚拟网络隧道 (TUN)
		"wg",    // WireGuard VPN 隧道
		"utun",  // macOS 用户态隧道
		"gif",   // Generic Tunnel (BSD)
		"stf",   // 6to4 隧道 (BSD)
		"gre",   // GRE 隧道
		"vxlan", // VXLAN 虚拟扩展局域网
		"enc",   // 封装接口 (IPsec)

		// ========== 防火墙与安全 ==========
		"pflog",  // PF 防火墙日志接口
		"pfsync", // PF 防火墙状态同步

		// ========== 聚合与VLAN ==========
		"vlan",  // VLAN 接口
		"lagg",  // 链路聚合接口 (BSD)
		"trunk", // 中继接口/Trunk 端口

		// ========== 容器与虚拟化网络 ==========
		"epair", // 成对以太网接口 (BSD Jail)
		"vnet",  // 虚拟网络接口 (BSD Jail)

		// ========== VPN 与远程接入 ==========
		"tailscale", // Tailscale VPN
		"zt",        // ZeroTier VPN
		"wg",        // WireGuard VPN

		// ========== 高可用与冗余 ==========
		"carp", // Common Address Redundancy Protocol

		// ========== 拨号与广域网 ==========
		"ppp", // 点对点协议
		"sl",  // 串行线路 IP (SLIP)

		// ========== 其他特殊接口 ==========
		"faith", // IPv6-to-IPv4 转发 (BSD)
		"disc",  // 丢弃接口 (Discard)
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
