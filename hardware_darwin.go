//go:build darwin
// +build darwin

package machineid

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// darwinHardwareInfo macOS平台硬件信息
type darwinHardwareInfo struct {
	ProductUUID   string   `json:"product_uuid,omitempty"`
	ProductSerial string   `json:"product_serial,omitempty"`
	ProductName   string   `json:"product_name,omitempty"`
	CPUSignature  string   `json:"cpu_signature,omitempty"`
	SystemVendor  string   `json:"system_vendor,omitempty"`
	DiskSerials   []string `json:"disk_serials,omitempty"`
	MACAddresses  []string `json:"mac_addresses,omitempty"`
}

// macOS硬件信息缓存
var (
	hardwareCacheMu   sync.RWMutex
	cachedHardware    *darwinHardwareInfo
	hardwareCacheTime time.Time
	hardwareCacheTTL  = 30 * time.Minute
)

// GetHardwareInfo macOS版本的硬件信息获取
func GetHardwareInfo() (*darwinHardwareInfo, error) {
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

	info := &darwinHardwareInfo{}

	// 获取macOS硬件信息
	getMacOSHardwareInfo(info)

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// getMacOSHardwareInfo 获取macOS特定的硬件信息
func getMacOSHardwareInfo(info *darwinHardwareInfo) {
	// 使用system_profiler获取硬件信息
	getSystemProfilerInfo(info)

	// 使用ioreg获取硬件信息
	getIORegistryInfo(info)

	// 获取网络信息
	if macInfo, err := getMACAddr(); err == nil && macInfo != nil && macInfo.Address != "" {
		info.MACAddresses = []string{macInfo.Address}
	}
}

// getSystemProfilerInfo 使用system_profiler获取硬件信息
func getSystemProfilerInfo(info *darwinHardwareInfo) {
	// 获取硬件概览
	if output, err := exec.Command("system_profiler", "SPHardwareDataType").Output(); err == nil {
		parseSystemProfilerOutput(string(output), info)
	}

	// 获取存储信息
	if output, err := exec.Command("system_profiler", "SPStorageDataType").Output(); err == nil {
		parseStorageInfo(string(output), info)
	}
}

// parseSystemProfilerOutput 解析system_profiler输出
func parseSystemProfilerOutput(output string, info *darwinHardwareInfo) {
	if info.SystemVendor == "" {
		info.SystemVendor = "Apple" // macOS都是Apple
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Serial Number") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				info.ProductSerial = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Hardware UUID") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				info.ProductUUID = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Model Identifier") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				info.ProductName = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Processor Name") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				info.CPUSignature = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Total Number of Cores") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				// 解析核心数
				coreStr := strings.TrimSpace(parts[1])
				if strings.Contains(coreStr, " ") {
					coreStr = strings.Fields(coreStr)[0]
				}
				// 这里可以解析数字，简化处理
			}
		} else if strings.Contains(line, "Memory") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				// 解析内存大小
				memStr := strings.TrimSpace(parts[1])
				// 简化处理，实际可以解析GB等单位
				if memStr != "" && info.SystemVendor == "" {
					info.SystemVendor = "Apple" // macOS都是Apple
				}
			}
		}
	}
}

// parseStorageInfo 解析存储信息
func parseStorageInfo(output string, info *darwinHardwareInfo) {
	lines := strings.Split(output, "\n")
	var diskSerials []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Device / Media Name") {
			// 查找设备序列号
			// 实际实现需要更复杂的解析逻辑
		}
	}

	if len(diskSerials) > 0 {
		info.DiskSerials = diskSerials
	}
}

// getIORegistryInfo 使用ioreg获取IO注册表信息
func getIORegistryInfo(info *darwinHardwareInfo) {
	// 获取平台专家设备信息
	if output, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
		parseIORegistryOutput(string(output), info)
	}
}

// parseIORegistryOutput 解析ioreg输出
func parseIORegistryOutput(output string, info *darwinHardwareInfo) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 查找IOPlatformUUID
		if strings.Contains(line, "IOPlatformUUID") {
			if parts := strings.SplitAfter(line, `" = "`); len(parts) == 2 {
				uuid := strings.TrimRight(parts[1], `"`)
				if info.ProductUUID == "" { // 如果还没有设置UUID
					info.ProductUUID = uuid
				}
			}
		} else if strings.Contains(line, "IOPlatformSerialNumber") {
			if parts := strings.SplitAfter(line, `" = "`); len(parts) == 2 {
				serial := strings.TrimRight(parts[1], `"`)
				if info.ProductSerial == "" {
					info.ProductSerial = serial
				}
			}
		}
	}
}

// GetHardwareFingerprint macOS版本的硬件指纹
func GetHardwareFingerprint() (string, error) {
	status, err := GetHardwareFingerprintStatus()
	if err != nil {
		return "", err
	}
	return status.Value, nil
}

// GetHardwareFingerprintStatus 返回指纹与稳定性
func GetHardwareFingerprintStatus() (*FingerprintStatus, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return nil, err
	}

	var components []string
	if info.ProductUUID != "" {
		components = append(components, "platform_uuid:"+info.ProductUUID)
	}
	if info.ProductSerial != "" {
		components = append(components, "serial:"+info.ProductSerial)
	}
	if info.ProductName != "" {
		components = append(components, "model:"+info.ProductName)
	}
	if info.CPUSignature != "" {
		components = append(components, "cpu:"+info.CPUSignature)
	}
	if len(info.DiskSerials) > 0 {
		components = append(components, "disk:"+info.DiskSerials[0])
	}
	if len(info.MACAddresses) > 0 {
		components = append(components, "mac:"+info.MACAddresses[0])
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("no hardware identifiers available")
	}

	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	stable := info.ProductUUID != "" && info.ProductSerial != ""
	return &FingerprintStatus{Value: fmt.Sprintf("%x", hash), Stable: stable}, nil
}

// ProtectedIDWithHardware macOS版本
func ProtectedIDWithHardware(appID string) (string, error) {
	status, err := GetHardwareFingerprintStatus()
	if err != nil {
		return "", fmt.Errorf("machineid: failed to get hardware fingerprint: %v", err)
	}

	id, err := ID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}

	// 组合机器ID和硬件指纹
	combined := fmt.Sprintf("%s/%s/%s", appID, id, status.Value)
	return protect(combined, id), nil
}

// ClearHardwareCache macOS版本
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}
