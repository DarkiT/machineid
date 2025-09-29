//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package machineid

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// otherHardwareInfo 其他平台简化硬件信息
type otherHardwareInfo struct {
	MACAddresses []string `json:"mac_addresses,omitempty"`
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
	if mac := getMACAddr(); mac != "" {
		info.MACAddresses = []string{mac}
	}

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// GetHardwareFingerprint 其他平台的硬件指纹（简化版）
func GetHardwareFingerprint() (string, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return "", err
	}

	// 对于其他平台，主要依赖MAC地址
	var components []string

	if len(info.MACAddresses) > 0 {
		components = append(components, "mac:"+info.MACAddresses[0])
	}

	if len(components) == 0 {
		return "", fmt.Errorf("no hardware identifiers available")
	}

	// 生成指纹
	combined := fmt.Sprintf("other_platform|%s", components[0])
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash), nil
}

// ProtectedIDWithHardware 其他平台版本
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

// ClearHardwareCache 其他平台版本
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}
