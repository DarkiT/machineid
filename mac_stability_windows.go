//go:build windows
// +build windows

package machineid

import (
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows 网卡类型常量
const (
	IF_TYPE_ETHERNET_CSMACD   = 6   // 以太网
	IF_TYPE_IEEE80211         = 71  // 无线网卡
	IF_TYPE_TUNNEL            = 131 // 隧道
	IF_TYPE_SOFTWARE_LOOPBACK = 24  // 软件回环
)

// MIB_IF_ROW2 Windows 网卡信息结构
type MIB_IF_ROW2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               windows.GUID
	Alias                       [514]uint16
	Description                 [514]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint32
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 windows.GUID
	ConnectionType              uint32
	// ... 其他字段省略
}

var (
	modiphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIfEntry2                 = modiphlpapi.NewProc("GetIfEntry2")
	procConvertInterfaceIndexToLuid = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
)

// inferInterfaceStabilityPlatform Windows 平台 MAC 稳定性检测
func inferInterfaceStabilityPlatform(iface net.Interface) bool {
	// 首先检查接口名称
	name := strings.ToLower(iface.Name)

	// 排除已知的虚拟接口
	virtualPrefixes := []string{
		"vethernet",    // Hyper-V 虚拟以太网
		"vmware",       // VMware
		"virtualbox",   // VirtualBox
		"vmnet",        // VMware 网络
		"vbox",         // VirtualBox
		"tap-",         // TAP 设备
		"tun",          // TUN 设备
		"loopback",     // 回环
		"isatap",       // ISATAP 隧道
		"teredo",       // Teredo 隧道
		"6to4",         // 6to4 隧道
		"bluetooth",    // 蓝牙
		"wi-fi direct", // Wi-Fi Direct
	}
	for _, prefix := range virtualPrefixes {
		if strings.Contains(name, prefix) {
			return false
		}
	}

	// 尝试通过 Windows API 获取更详细的信息
	ifType := getInterfaceType(iface.Index)
	switch ifType {
	case IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211:
		// 以太网或无线网卡，检查是否有永久 MAC 地址
		return hasPermanentMACAddress(iface.Index)
	case IF_TYPE_TUNNEL, IF_TYPE_SOFTWARE_LOOPBACK:
		return false
	default:
		// 未知类型，根据名称判断
		return !strings.Contains(name, "virtual")
	}
}

// getInterfaceType 获取网卡类型
func getInterfaceType(ifIndex int) uint32 {
	if procGetIfEntry2.Find() != nil {
		return 0
	}

	var row MIB_IF_ROW2

	// 先转换索引到 LUID
	if procConvertInterfaceIndexToLuid.Find() == nil {
		procConvertInterfaceIndexToLuid.Call(
			uintptr(ifIndex),
			uintptr(unsafe.Pointer(&row.InterfaceLuid)),
		)
	}

	row.InterfaceIndex = uint32(ifIndex)

	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return 0
	}

	return row.Type
}

// hasPermanentMACAddress 检查是否有永久 MAC 地址
func hasPermanentMACAddress(ifIndex int) bool {
	if procGetIfEntry2.Find() != nil {
		return true // 无法检测时默认认为稳定
	}

	var row MIB_IF_ROW2
	row.InterfaceIndex = uint32(ifIndex)

	// 转换索引到 LUID
	if procConvertInterfaceIndexToLuid.Find() == nil {
		procConvertInterfaceIndexToLuid.Call(
			uintptr(ifIndex),
			uintptr(unsafe.Pointer(&row.InterfaceLuid)),
		)
	}

	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return true
	}

	// 检查永久 MAC 地址是否与当前 MAC 地址相同
	// 如果不同，说明 MAC 被修改过
	if row.PhysicalAddressLength > 0 {
		for i := uint32(0); i < row.PhysicalAddressLength; i++ {
			if row.PhysicalAddress[i] != row.PermanentPhysicalAddress[i] {
				return false // MAC 被修改过
			}
		}
	}

	return true
}

// isKnownVirtualInterface Windows 平台检查是否为已知虚拟接口
func isKnownVirtualInterface(name string) bool {
	name = strings.ToLower(name)
	virtualKeywords := []string{
		"virtual",
		"vmware",
		"virtualbox",
		"vbox",
		"hyper-v",
		"vmnet",
		"tap",
		"tun",
		"loopback",
		"isatap",
		"teredo",
		"6to4",
		"bluetooth",
	}
	for _, keyword := range virtualKeywords {
		if strings.Contains(name, keyword) {
			return true
		}
	}
	return false
}
