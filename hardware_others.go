//go:build !linux && !windows && !darwin

package machineid

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// otherHardwareInfo 其他平台简化硬件信息
type otherHardwareInfo struct {
	MACAddresses []string `json:"mac_addresses,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	MachineID    string   `json:"machine_id,omitempty"`
}

// 其他平台的硬件信息缓存
var (
	hardwareCacheMu   sync.RWMutex
	cachedHardware    *otherHardwareInfo
	hardwareCacheTime time.Time
	hardwareCacheTTL  = 30 * time.Minute
)

// GetHardwareInfo 其他平台的硬件信息获取（简化版）
func GetHardwareInfo() (*otherHardwareInfo, error) {
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

	info := &otherHardwareInfo{}

	// 对于其他平台，只获取基本的网络信息
	if macInfo, err := getMACAddr(); err == nil && macInfo != nil && macInfo.Address != "" {
		info.MACAddresses = []string{macInfo.Address}
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		info.Hostname = hostname
	}
	if id, err := ID(); err == nil && id != "" {
		info.MachineID = id
	}

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// GetHardwareFingerprint 其他平台的硬件指纹（简化版）
func GetHardwareFingerprint() (string, error) {
	status, err := GetHardwareFingerprintStatus()
	if err != nil {
		return "", err
	}
	return status.Value, nil
}

// GetHardwareFingerprintStatus 返回简单指纹信息
func GetHardwareFingerprintStatus() (*FingerprintStatus, error) {
	return defaultFingerprintStatusProvider()
}

func builtinHardwareSignals(_ context.Context) ([]HardwareSignal, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return nil, err
	}

	var signals []HardwareSignal
	if len(info.MACAddresses) > 0 {
		signals = append(signals, HardwareSignal{
			Name:   "mac",
			Value:  info.MACAddresses[0],
			Weight: 100,
			Strong: true,
			Scope:  HardwareScopeNetwork,
			Source: "builtin/other",
		})
	}
	if info.MachineID != "" {
		signals = append(signals, HardwareSignal{
			Name:   "machine_id",
			Value:  info.MachineID,
			Weight: 40,
			Scope:  HardwareScopeRuntime,
			Source: "builtin/other",
		})
	}
	if info.Hostname != "" {
		signals = append(signals, HardwareSignal{
			Name:   "hostname",
			Value:  info.Hostname,
			Weight: 20,
			Scope:  HardwareScopeRuntime,
			Source: "builtin/other",
		})
	}
	return signals, nil
}

// ProtectedIDWithHardware 其他平台版本
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

// ClearHardwareCache 其他平台版本
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}
