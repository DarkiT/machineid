//go:build windows
// +build windows

package machineid

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// windowsHardwareInfo Windows平台硬件信息
type windowsHardwareInfo struct {
	ProductUUID   string   `json:"product_uuid,omitempty"`
	ProductSerial string   `json:"product_serial,omitempty"`
	CPUSignature  string   `json:"cpu_signature,omitempty"`
	BoardSerial   string   `json:"board_serial,omitempty"`
	SystemVendor  string   `json:"system_vendor,omitempty"`
	ProductName   string   `json:"product_name,omitempty"`
	MemorySize    uint64   `json:"memory_size,omitempty"`
	DiskSerials   []string `json:"disk_serials,omitempty"`
	MACAddresses  []string `json:"mac_addresses,omitempty"`
}

// Windows硬件信息缓存
var (
	hardwareCacheMu   sync.RWMutex
	cachedHardware    *windowsHardwareInfo
	hardwareCacheTime time.Time
	hardwareCacheTTL  = 30 * time.Minute
)

// GetHardwareInfo Windows版本的硬件信息获取
func GetHardwareInfo() (*windowsHardwareInfo, error) {
	// 检查缓存
	hardwareCacheMu.RLock()
	if time.Since(hardwareCacheTime) < hardwareCacheTTL && cachedHardware != nil {
		defer hardwareCacheMu.RUnlock()
		return cachedHardware, nil
	}
	hardwareCacheMu.RUnlock()

	// 获取新的硬件信息
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	// 双重检查
	if time.Since(hardwareCacheTime) < hardwareCacheTTL && cachedHardware != nil {
		return cachedHardware, nil
	}

	info := &windowsHardwareInfo{}

	// 获取Windows硬件信息
	getWindowsHardwareInfo(info)

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// getWindowsHardwareInfo 获取Windows特定的硬件信息
func getWindowsHardwareInfo(info *windowsHardwareInfo) {
	// 从注册表获取各种硬件信息
	getRegistryHardwareInfo(info)

	// 获取系统信息
	getWindowsSystemInfo(info)

	// 获取网络信息
	if mac := getMACAddr(); mac != "" {
		info.MACAddresses = []string{mac}
	}
}

// getRegistryHardwareInfo 从注册表获取硬件信息
func getRegistryHardwareInfo(info *windowsHardwareInfo) {
	// 计算机硬件信息路径
	regPaths := map[string]struct {
		path string
		key  string
		dest *string
	}{
		"machine_guid": {
			`SOFTWARE\Microsoft\Cryptography`,
			"MachineGuid",
			&info.ProductUUID,
		},
		"computer_hardware_id": {
			`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`,
			"ComputerName",
			&info.ProductSerial,
		},
		"processor_identifier": {
			`HARDWARE\DESCRIPTION\System\CentralProcessor\0`,
			"ProcessorNameString",
			&info.CPUSignature,
		},
	}

	for _, regInfo := range regPaths {
		if value := readRegistryString(registry.LOCAL_MACHINE, regInfo.path, regInfo.key); value != "" {
			*regInfo.dest = value
		}
	}

	// 尝试获取BIOS信息
	if biosSerial := readRegistryString(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardProduct"); biosSerial != "" {
		info.BoardSerial = biosSerial
	}

	// 系统厂商信息
	if vendor := readRegistryString(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"); vendor != "" {
		info.SystemVendor = vendor
	}

	if product := readRegistryString(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"); product != "" {
		info.ProductName = product
	}
}

// getWindowsSystemInfo 获取Windows系统信息
func getWindowsSystemInfo(info *windowsHardwareInfo) {
	// 获取内存信息
	if memSize := getWindowsMemorySize(); memSize > 0 {
		info.MemorySize = memSize
	}

	// 获取硬盘信息
	if diskSerials := getWindowsDiskSerials(); len(diskSerials) > 0 {
		info.DiskSerials = diskSerials
	}
}

// readRegistryString 读取注册表字符串值
func readRegistryString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	value, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

// getWindowsMemorySize 获取Windows内存大小
func getWindowsMemorySize() uint64 {
	// 这里可以使用Windows API获取内存信息
	// 简化实现，通过环境变量或其他方式
	return 0
}

// getWindowsDiskSerials 获取Windows硬盘序列号
func getWindowsDiskSerials() []string {
	// Windows下可以通过WMI或其他方式获取硬盘序列号
	// 这里是简化实现
	var serials []string

	// 尝试从注册表获取存储设备信息
	// 实际实现可能需要更复杂的逻辑

	return serials
}

// GetHardwareFingerprint Windows版本的硬件指纹
func GetHardwareFingerprint() (string, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return "", err
	}

	// 收集Windows特定的硬件标识符
	var components []string

	// Windows的MachineGuid是最重要的标识符
	if info.ProductUUID != "" {
		components = append(components, "machine_guid:"+info.ProductUUID)
	}

	// CPU信息
	if info.CPUSignature != "" {
		components = append(components, "cpu:"+info.CPUSignature)
	}

	// 系统信息
	if info.SystemVendor != "" && info.ProductName != "" {
		components = append(components, "system:"+info.SystemVendor+":"+info.ProductName)
	}

	// BIOS信息
	if info.BoardSerial != "" {
		components = append(components, "board:"+info.BoardSerial)
	}

	// MAC地址作为备选
	if len(info.MACAddresses) > 0 {
		components = append(components, "mac:"+info.MACAddresses[0])
	}

	if len(components) == 0 {
		return "", fmt.Errorf("no hardware identifiers available")
	}

	// 生成指纹
	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash), nil
}

// ProtectedIDWithHardware Windows版本
func ProtectedIDWithHardware(appID string) (string, error) {
	fingerprint, err := GetHardwareFingerprint()
	if err != nil {
		return "", fmt.Errorf("machineid: failed to get hardware fingerprint: %v", err)
	}

	id, err := ID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}

	// 组合机器ID和硬件指纹
	combined := fmt.Sprintf("%s/%s/%s", appID, id, fingerprint)
	return protect(combined, id), nil
}

// ClearHardwareCache Windows版本
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}
