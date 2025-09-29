// Package machineid provides support for reading the unique machine id of most OSs (without admin privileges).
//
// https://github.com/darkit/machineid
//
// https://godoc.org/github.com/darkit/machineid/cmd/machineid
//
// This package is Cross-Platform (tested on Win7+, Debian 8+, Ubuntu 14.04+, OS X 10.6+, FreeBSD 11+)
// and does not use any internal hardware IDs (no MAC, BIOS, or CPU).
//
// Returned machine IDs are generally stable for the OS installation
// and usually stay the same after updates or hardware changes.
//
// This package allows sharing of machine IDs in a secure way by
// calculating HMAC-SHA256 over a user provided app ID, which is keyed by the machine id.
//
// Caveat: Image-based environments have usually the same machine-id (perfect clone).
// Linux users can generate a new id with `dbus-uuidgen` and put the id into
// `/var/lib/dbus/machine-id` and `/etc/machine-id`.
// Windows users can use the `sysprep` toolchain to create images, which produce valid images ready for distribution.
package machineid // import "github.com/darkit/machineid"

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	cacheMu      sync.RWMutex
	cachedID     string
	cachedError  error
	cacheTime    time.Time
	cacheTTL     = 5 * time.Minute // 缓存5分钟
	macCacheMu   sync.RWMutex
	cachedMAC    string
	macCacheTime time.Time
)

// ID returns the platform specific machine id of the current host OS.
// Regard the returned id as "confidential" and consider using ProtectedID() instead.
func ID() (string, error) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(cacheTime) < cacheTTL && cachedID != "" {
		defer cacheMu.RUnlock()
		return cachedID, cachedError
	}
	cacheMu.RUnlock()

	// 获取新的ID
	cacheMu.Lock()
	defer cacheMu.Unlock()

	// 双重检查，防止并发时重复获取
	if time.Since(cacheTime) < cacheTTL && cachedID != "" {
		return cachedID, cachedError
	}

	id, err := machineID()
	if err != nil {
		cachedError = fmt.Errorf("machineid: %v", err)
		cacheTime = time.Now()
		return "", cachedError
	}

	cachedID = id
	cachedError = nil
	cacheTime = time.Now()
	return id, nil
}

// ProtectedID returns a hashed version of the machine ID in a cryptographically secure way,
// using intelligent priority-based hardware binding when available.
//
// Priority order:
// 1. Hardware fingerprint (most stable)
// 2. MAC address binding (fallback)
// 3. Pure machine ID (basic)
func ProtectedID(appID string) (string, error) {
	return protectedIDWithPriority(appID, false)
}

// ProtectedIDWithMAC returns a hashed version of the machine ID bound to MAC address.
// Deprecated: Use ProtectedID instead, which intelligently handles hardware binding.
func ProtectedIDWithMAC(appID string) (string, error) {
	return protectedIDWithPriority(appID, true)
}

// protectedIDWithPriority 智能优先级处理的保护ID生成
func protectedIDWithPriority(appID string, forceMACBinding bool) (string, error) {
	id, err := ID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}

	// 如果强制要求MAC绑定，或者硬件指纹不可用时，尝试MAC绑定
	if forceMACBinding {
		if macAddr := getMACAddr(); macAddr != "" {
			combined := fmt.Sprintf("%s/%s", appID, macAddr)
			return protect(combined, id), nil
		}
	} else {
		// 智能优先级处理
		// 1. 尝试硬件指纹（如果支持）
		if fingerprint, err := GetHardwareFingerprint(); err == nil && fingerprint != "" {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, fingerprint)
			return protect(combined, id), nil
		}

		// 2. 回退到MAC地址绑定
		if macAddr := getMACAddr(); macAddr != "" {
			combined := fmt.Sprintf("%s/%s", appID, macAddr)
			return protect(combined, id), nil
		}
	}

	// 3. 基础保护ID（纯机器码）
	return protect(appID, id), nil
}

// 获取网卡 MAC 地址，返回所有物理网卡中MAC地址最小的那个
func getMACAddr() (macAddr string) {
	// 检查缓存
	macCacheMu.RLock()
	if time.Since(macCacheTime) < cacheTTL && cachedMAC != "" {
		defer macCacheMu.RUnlock()
		return cachedMAC
	}
	macCacheMu.RUnlock()

	// 获取新的MAC地址
	macCacheMu.Lock()
	defer macCacheMu.Unlock()

	// 双重检查
	if time.Since(macCacheTime) < cacheTTL && cachedMAC != "" {
		return cachedMAC
	}

	// 获取所有网络接口
	ifas, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// 用于存储找到的最小MAC地址
	var minMACAddr string

	// 遍历所有网卡
	for _, iface := range ifas {
		// 过滤条件：
		// 1. 不是回环接口 (FlagLoopback)
		// 2. 有MAC地址
		// 3. 接口处于开启状态 (FlagUp)
		// 4. 不是虚拟接口 (FlagPointToPoint)
		if iface.Flags&net.FlagLoopback == 0 && // 不是回环接口
			iface.HardwareAddr != nil && // 有MAC地址
			iface.Flags&net.FlagUp != 0 && // 接口是启用的
			iface.Flags&net.FlagPointToPoint == 0 && // 不是点对点接口（虚拟接口）
			len(iface.HardwareAddr.String()) > 0 { // MAC地址长度大于0

			currentMAC := iface.HardwareAddr.String()

			// 如果是第一个找到的MAC地址，或者当前MAC地址小于已存储的最小值
			if minMACAddr == "" || currentMAC < minMACAddr {
				minMACAddr = currentMAC
			}
		}
	}

	cachedMAC = minMACAddr
	macCacheTime = time.Now()
	return minMACAddr
}

// GetMACAddress 获取主网卡的MAC地址，提供给用户直接使用
func GetMACAddress() (string, error) {
	mac := getMACAddr()
	if mac == "" {
		return "", fmt.Errorf("machineid: no valid MAC address found")
	}
	return mac, nil
}

// IsContainer 检查当前程序是否运行在容器环境中
func IsContainer() bool {
	return isContainerEnvironment()
}

// ClearCache 清除所有缓存，强制下次调用重新获取
func ClearCache() {
	cacheMu.Lock()
	cachedID = ""
	cachedError = nil
	cacheTime = time.Time{}
	cacheMu.Unlock()

	macCacheMu.Lock()
	cachedMAC = ""
	macCacheTime = time.Time{}
	macCacheMu.Unlock()

	// 清除硬件信息缓存
	ClearHardwareCache()
}

// Info 返回系统信息摘要
type Info struct {
	MachineID   string `json:"machine_id"`             // 原始机器码
	ProtectedID string `json:"protected_id"`           // 应用保护机器码
	MACAddress  string `json:"mac_address,omitempty"`  // MAC地址（可选硬件绑定）
	IsContainer bool   `json:"is_container"`           // 是否容器环境
	ContainerID string `json:"container_id,omitempty"` // 容器ID
}

// GetInfo 获取系统信息摘要
func GetInfo(appID string) (*Info, error) {
	info := &Info{}

	// 获取机器ID
	id, err := ID()
	if err != nil {
		return nil, err
	}
	info.MachineID = id

	// 生成智能保护ID
	if appID != "" {
		protectedID, err := ProtectedID(appID)
		if err != nil {
			return nil, err
		}
		info.ProtectedID = protectedID
	}

	// 获取MAC地址（可选）
	if mac := getMACAddr(); mac != "" {
		info.MACAddress = mac
	}

	// 检查容器环境
	info.IsContainer = IsContainer()
	if info.IsContainer {
		if containerID := getContainerID(); containerID != "" {
			info.ContainerID = containerID
		}
	}

	return info, nil
}
