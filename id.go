// Package machineid provides support for reading the unique machine id of most OSs (without admin privileges).
//
// https://github.com/darkit/machineid
//
// https://godoc.org/github.com/darkit/machineid/cmd/machineid
//
// This package is Cross-Platform (tested on Win7+, Debian 8+, Ubuntu 14.04+, OS X 10.6+, FreeBSD 11+)
// and keeps the raw ID API focused on a stable host identity; higher-level APIs may
// additionally combine hardware signals, and on Linux the raw ID prefers host-visible
// hardware identity when it is truly available.
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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	cacheMu         sync.RWMutex
	cachedID        string
	cachedError     error
	cacheTime       time.Time
	cacheSuccessTTL = 5 * time.Minute  // 成功缓存5分钟
	cacheFailureTTL = 10 * time.Second // 失败缓存10秒（临时错误快速重试）

	macCacheMu         sync.RWMutex
	macCacheValue      *MACInfo
	macCacheErr        error
	macCacheTime       time.Time
	macCacheSuccessTTL = 5 * time.Minute
	macCacheFailureTTL = 10 * time.Second

	fingerprintStatusProvider = GetHardwareFingerprintStatus
	macResolver               = resolveMACAddr
	machineIDProvider         = machineID
	idProvider                = ID
	containerEnvDetector      = isContainerEnvironment
	containerIDProvider       = getContainerID
)

// BindingMode 表示保护ID最终采用的绑定模式
type BindingMode string

const (
	BindingModeFingerprint BindingMode = "fingerprint"
	BindingModeMAC         BindingMode = "mac"
	BindingModeMachineID   BindingMode = "machine_id"
	BindingModeCustom      BindingMode = "custom"
)

// BindingResult 描述生成保护ID时采用的模式与降级原因
type BindingResult struct {
	Hash             string
	Mode             BindingMode
	Provider         string
	FingerprintError error
	MACError         error
	ContainerMode    string // ContainerMode 容器绑定模式: "host"/"container"/"hybrid"/"none"
	ContainerID      string // ContainerID 容器ID（如果检测到）
}

// FingerprintStatus 描述硬件指纹的值与稳定性
type FingerprintStatus struct {
	Value  string
	Stable bool
}

// MACInfo 描述筛选到的 MAC 地址与其稳定性
type MACInfo struct {
	Address  string   // 主 MAC 地址（字典序最小的稳定 MAC）
	Stable   bool     // 主 MAC 是否稳定
	Iface    string   // 主 MAC 所属网卡名称
	AllMACs  []string // 所有稳定 MAC 地址（排序后）
	Combined string   // 所有稳定 MAC 组合后的哈希值
}

// UniqueIDMode 定义唯一性策略（宿主机唯一或容器唯一）。
type UniqueIDMode int

const (
	UniqueIDModeContainer UniqueIDMode = iota
	UniqueIDModeHost
)

// UniqueIDOptions 控制“唯一性增强”机器码的生成行为。
type UniqueIDOptions struct {
	// EnableContainer 是否启用容器感知逻辑（容器内更强调隔离与唯一性）。
	EnableContainer bool
	// ContainerConfig 容器绑定配置；为 nil 时使用默认配置。
	ContainerConfig *ContainerBindingConfig
	// Mode 指定唯一性策略；默认容器唯一。
	Mode UniqueIDMode
	// EnableCustomProviders 是否启用自定义绑定提供者。
	EnableCustomProviders bool
	// ForceMACBinding 是否强制使用 MAC 绑定（会绕过其他策略）。
	ForceMACBinding bool
}

// DefaultUniqueIDOptions 返回默认选项（容器感知 + 自定义提供者）。
func DefaultUniqueIDOptions() *UniqueIDOptions {
	return &UniqueIDOptions{
		EnableContainer:       true,
		ContainerConfig:       nil,
		Mode:                  UniqueIDModeContainer,
		EnableCustomProviders: true,
		ForceMACBinding:       false,
	}
}

func normalizeUniqueIDOptions(options *UniqueIDOptions) *UniqueIDOptions {
	if options == nil {
		return DefaultUniqueIDOptions()
	}
	copied := *options
	if !options.EnableContainer && options.ContainerConfig != nil {
		// 关闭容器逻辑时忽略容器配置，避免误用。
		copied.ContainerConfig = nil
	}
	return &copied
}

// ID returns the platform specific machine id of the current host OS.
// Regard the returned id as "confidential" and consider using ProtectedID() instead.
func ID() (string, error) {
	// 检查缓存
	cacheMu.RLock()
	elapsed := time.Since(cacheTime)
	// 成功缓存：有 ID 且未过期
	if cachedID != "" && elapsed < cacheSuccessTTL {
		defer cacheMu.RUnlock()
		return cachedID, cachedError
	}
	// 失败缓存：无 ID 但有错误且未过期
	if cachedID == "" && cachedError != nil && elapsed < cacheFailureTTL {
		defer cacheMu.RUnlock()
		return "", cachedError
	}
	cacheMu.RUnlock()

	// 获取新的ID
	cacheMu.Lock()
	defer cacheMu.Unlock()

	// 双重检查，防止并发时重复获取
	elapsed = time.Since(cacheTime)
	if cachedID != "" && elapsed < cacheSuccessTTL {
		return cachedID, cachedError
	}
	if cachedID == "" && cachedError != nil && elapsed < cacheFailureTTL {
		return "", cachedError
	}

	id, err := machineIDProvider()
	if err != nil {
		cachedID = ""
		cachedError = fmt.Errorf("machineid: %v", err)
		cacheTime = time.Now()
		return "", cachedError
	}

	cachedID = strings.ToUpper(id)
	cachedError = nil
	cacheTime = time.Now()
	return cachedID, nil
}

// ProtectedID returns a hashed version of the machine ID in a cryptographically secure way,
// using intelligent priority-based hardware binding when available.
//
// Priority order:
// 1. Hardware fingerprint (most stable)
// 2. MAC address binding (fallback)
// 3. Pure machine ID (basic)
func ProtectedID(appID string) (string, error) {
	result, err := ProtectedIDResult(appID)
	if err != nil {
		return "", err
	}
	return result.Hash, nil
}

// ProtectedIDResult 返回包含详细绑定信息的结果
func ProtectedIDResult(appID string) (*BindingResult, error) {
	// 默认不启用容器特征派生逻辑，保持历史优先级：fingerprint -> MAC -> machine-id
	return protectedIDWithPriority(appID, false)
}

// UniqueID 返回“唯一性增强”的保护机器码（兼容 ID() 行为，不影响已有接口）。
func UniqueID(appID string) (string, error) {
	result, err := UniqueIDResult(appID, nil)
	if err != nil {
		return "", err
	}
	return result.Hash, nil
}

// UniqueIDResult 返回“唯一性增强”结果（包含绑定来源与容器信息）。
func UniqueIDResult(appID string, options *UniqueIDOptions) (*BindingResult, error) {
	opts := normalizeUniqueIDOptions(options)

	if opts.ForceMACBinding {
		return ProtectedIDWithMACResult(appID)
	}

	id, err := idProvider()
	if err != nil {
		return nil, fmt.Errorf("machineid: %v", err)
	}

	result := &BindingResult{}
	isContainer := false
	var containerConfig *ContainerBindingConfig

	if opts.EnableContainer && IsContainer() {
		isContainer = true
		result.ContainerID = containerIDProvider()
		containerConfig = opts.ContainerConfig
		if containerConfig == nil {
			containerConfig = DefaultContainerBindingConfig()
		} else {
			copied := *containerConfig
			containerConfig = &copied
		}
		switch opts.Mode {
		case UniqueIDModeHost:
			containerConfig.Mode = ContainerBindingHost
			containerConfig.FallbackToContainer = false
			containerConfig.PreferHostHardware = true
		case UniqueIDModeContainer:
			containerConfig.Mode = ContainerBindingContainer
			containerConfig.PreferHostHardware = false
		}
		if err := containerConfig.Validate(); err != nil {
			return nil, fmt.Errorf("invalid container binding config: %w", err)
		}
		result.ContainerMode = selectBindingStrategy(containerConfig)
	}

	if isContainer && containerConfig != nil {
		containerResult, ok, err := uniqueIDFromContainer(appID, id, result.ContainerMode, containerConfig, result.ContainerID)
		if err != nil {
			return nil, err
		}
		if ok {
			containerResult.ContainerMode = result.ContainerMode
			containerResult.ContainerID = result.ContainerID
			return containerResult, nil
		}
	}

	// 尝试硬件指纹
	if fpStatus, fpErr := fingerprintStatusProvider(); fpErr == nil && fpStatus != nil {
		if fpStatus.Stable && fpStatus.Value != "" {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, fpStatus.Value)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeFingerprint
			result.Provider = string(BindingModeFingerprint)
			return result, nil
		}
		result.FingerprintError = fmt.Errorf("hardware fingerprint unstable")
	} else if fpErr != nil {
		result.FingerprintError = fpErr
	}

	// 尝试 MAC 绑定
	if macInfo, macErr := macResolver(); macErr == nil && macInfo != nil {
		if macInfo.Stable {
			combined := fmt.Sprintf("%s/%s", appID, macInfo.Address)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeMAC
			result.Provider = macInfo.Iface
			return result, nil
		}
		result.MACError = fmt.Errorf("unstable MAC address detected")
	} else if macErr != nil {
		result.MACError = macErr
	}

	// 尝试自定义绑定提供者
	if opts.EnableCustomProviders {
		if customResult, ok := uniqueIDFromBindingProviders(appID, id); ok {
			customResult.ContainerMode = result.ContainerMode
			customResult.ContainerID = result.ContainerID
			return customResult, nil
		}
	}

	// 最后降级为纯 machine-id
	result.Hash = protect(appID, id)
	result.Mode = BindingModeMachineID
	result.Provider = string(BindingModeMachineID)
	return result, nil
}

// ProtectedIDWithMAC returns a hashed version of the machine ID bound to MAC address.
// Deprecated: Use ProtectedID instead, which intelligently handles hardware binding.
func ProtectedIDWithMAC(appID string) (string, error) {
	result, err := protectedIDWithPriority(appID, true)
	if err != nil {
		return "", err
	}
	return result.Hash, nil
}

// ProtectedIDWithMACResult 返回强制 MAC 绑定模式下的详细结果
func ProtectedIDWithMACResult(appID string) (*BindingResult, error) {
	return protectedIDWithPriority(appID, true)
}

// protectedIDWithPriority 智能优先级处理的保护ID生成
func protectedIDWithPriority(appID string, forceMACBinding bool) (*BindingResult, error) {
	id, err := idProvider()
	if err != nil {
		return nil, fmt.Errorf("machineid: %v", err)
	}

	result := &BindingResult{}

	// 尝试硬件指纹
	if !forceMACBinding {
		if fpStatus, fpErr := fingerprintStatusProvider(); fpErr == nil && fpStatus != nil {
			if fpStatus.Stable && fpStatus.Value != "" {
				combined := fmt.Sprintf("%s/%s/%s", appID, id, fpStatus.Value)
				result.Hash = protect(combined, id)
				result.Mode = BindingModeFingerprint
				result.Provider = string(BindingModeFingerprint)
				return result, nil
			}
			result.FingerprintError = fmt.Errorf("hardware fingerprint unstable")
		} else if fpErr != nil {
			result.FingerprintError = fpErr
		}
	}

	// 如果要求MAC绑定或指纹失败，则尝试MAC
	if macInfo, macErr := macResolver(); macErr == nil && macInfo != nil {
		if forceMACBinding && !macInfo.Stable {
			return nil, fmt.Errorf("machineid: no stable MAC address available")
		}
		if macInfo.Stable {
			combined := fmt.Sprintf("%s/%s", appID, macInfo.Address)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeMAC
			result.Provider = macInfo.Iface
			return result, nil
		}
		result.MACError = fmt.Errorf("unstable MAC address detected")
	} else if macErr != nil {
		result.MACError = macErr
		if forceMACBinding {
			return nil, macErr
		}
	}

	if forceMACBinding {
		return nil, fmt.Errorf("machineid: unable to bind to MAC address")
	}

	// 3. 自定义绑定提供者（与 README 承诺保持一致）
	if customResult, ok := uniqueIDFromBindingProviders(appID, id); ok {
		customResult.FingerprintError = result.FingerprintError
		customResult.MACError = result.MACError
		return customResult, nil
	}

	// 4. 基础保护ID（纯机器码）
	result.Hash = protect(appID, id)
	result.Mode = BindingModeMachineID
	result.Provider = string(BindingModeMachineID)
	return result, nil
}

// 获取网卡 MAC 地址，优先返回稳定网卡
func getMACAddr() (*MACInfo, error) {
	return macResolver()
}

func resolveMACAddr() (*MACInfo, error) {
	macCacheMu.RLock()
	if macCacheValue != nil && time.Since(macCacheTime) < macCacheSuccessTTL {
		info := *macCacheValue
		macCacheMu.RUnlock()
		return &info, nil
	}
	if macCacheValue == nil && macCacheErr != nil && time.Since(macCacheTime) < macCacheFailureTTL {
		err := macCacheErr
		macCacheMu.RUnlock()
		return nil, err
	}
	macCacheMu.RUnlock()

	macCacheMu.Lock()
	defer macCacheMu.Unlock()

	if macCacheValue != nil && time.Since(macCacheTime) < macCacheSuccessTTL {
		info := *macCacheValue
		return &info, nil
	}
	if macCacheValue == nil && macCacheErr != nil && time.Since(macCacheTime) < macCacheFailureTTL {
		return nil, macCacheErr
	}

	info, err := selectMACCandidate()
	macCacheTime = time.Now()
	if err != nil {
		macCacheValue = nil
		macCacheErr = err
		return nil, err
	}
	macCacheValue = info
	macCacheErr = nil
	return info, nil
}

// selectMACCandidate 遍历网卡并挑选最优 MAC
// 收集所有稳定 MAC 地址，生成组合哈希以增强唯一性
func selectMACCandidate() (*MACInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("machineid: failed to list interfaces: %w", err)
	}

	var stableMACs []string
	var unstableMACs []string
	var bestStable *MACInfo
	var bestUnstable *MACInfo

	for _, iface := range ifaces {
		if !isInterfaceCandidate(iface) {
			continue
		}

		macStr := strings.ToLower(iface.HardwareAddr.String())
		if macStr == "" {
			continue
		}

		normalized := normalizeMACAddress(macStr)
		stable := inferInterfaceStability(iface)

		if stable {
			stableMACs = append(stableMACs, normalized)
			if bestStable == nil || normalized < normalizeMACAddress(bestStable.Address) {
				bestStable = &MACInfo{Address: macStr, Stable: true, Iface: iface.Name}
			}
		} else {
			unstableMACs = append(unstableMACs, normalized)
			if bestUnstable == nil || normalized < normalizeMACAddress(bestUnstable.Address) {
				bestUnstable = &MACInfo{Address: macStr, Stable: false, Iface: iface.Name}
			}
		}
	}

	// 构建结果
	var result *MACInfo
	switch {
	case bestStable != nil:
		result = bestStable
		// 排序所有稳定 MAC 以确保一致性
		sortStrings(stableMACs)
		result.AllMACs = stableMACs
		// 生成组合哈希：多个 MAC 组合后单个变化影响较小
		result.Combined = generateMACCombinedHash(stableMACs)
	case bestUnstable != nil:
		result = bestUnstable
		sortStrings(unstableMACs)
		result.AllMACs = unstableMACs
		result.Combined = generateMACCombinedHash(unstableMACs)
	default:
		return nil, errors.New("machineid: no suitable MAC address found")
	}

	return result, nil
}

// sortStrings 对字符串切片进行排序（简单冒泡排序，避免引入 sort 包）
func sortStrings(s []string) {
	for i := 0; i < len(s)-1; i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// generateMACCombinedHash 生成多个 MAC 地址的组合哈希
// 使用简单的异或组合，单个 MAC 变化不会完全改变结果
func generateMACCombinedHash(macs []string) string {
	if len(macs) == 0 {
		return ""
	}
	if len(macs) == 1 {
		return macs[0]
	}

	// 将所有 MAC 连接后计算哈希
	combined := strings.Join(macs, "|")
	return protect(combined, "mac-combined")
}

func isInterfaceCandidate(iface net.Interface) bool {
	if len(iface.HardwareAddr) == 0 {
		return false
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	name := strings.ToLower(iface.Name)
	ignoredPrefixes := []string{"lo", "docker", "veth", "br-", "vmnet", "zt", "tailscale"}
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

func normalizeMACAddress(mac string) string {
	return strings.ReplaceAll(mac, ":", "")
}

// inferInterfaceStability 检测网卡 MAC 地址是否稳定
// 调用平台特定实现进行检测
func inferInterfaceStability(iface net.Interface) bool {
	return inferInterfaceStabilityPlatform(iface)
}

// GetMACAddress 获取主网卡的MAC地址，提供给用户直接使用
func GetMACAddress() (string, error) {
	macInfo, err := getMACAddr()
	if err != nil {
		return "", err
	}
	if macInfo == nil || macInfo.Address == "" {
		return "", fmt.Errorf("machineid: no valid MAC address found")
	}
	if !macInfo.Stable {
		return "", fmt.Errorf("machineid: MAC address is not stable")
	}
	return macInfo.Address, nil
}

// IsContainer 检查当前程序是否运行在容器环境中
func IsContainer() bool {
	return containerEnvDetector()
}

// ClearCache 清除所有缓存，强制下次调用重新获取
func ClearCache() {
	cacheMu.Lock()
	cachedID = ""
	cachedError = nil
	cacheTime = time.Time{}
	cacheMu.Unlock()

	macCacheMu.Lock()
	macCacheValue = nil
	macCacheErr = nil
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
	info.MachineID = strings.ToUpper(id)

	// 生成智能保护ID
	if appID != "" {
		protectedID, err := ProtectedID(appID)
		if err != nil {
			return nil, err
		}
		info.ProtectedID = protectedID
	}

	// 获取MAC地址（可选）
	if macInfo, err := getMACAddr(); err == nil && macInfo != nil && macInfo.Stable {
		info.MACAddress = macInfo.Address
	}

	// 检查容器环境
	info.IsContainer = IsContainer()
	if info.IsContainer {
		if containerID := containerIDProvider(); containerID != "" {
			info.ContainerID = strings.ToUpper(containerID)
		}
	}

	return info, nil
}

// ProtectedIDWithContainerAware 容器感知的保护ID生成
//
// 容器绑定逻辑说明：
// - 非容器环境：保持历史行为，走“硬件指纹 → MAC → machine-id”的优先级链路（ContainerMode="none"）。
// - 容器环境：根据 ContainerBindingConfig 选择策略：
//   - host_hardware：在容器具备宿主机硬件可见性时，优先使用宿主机硬件指纹；不可用且允许降级则落到容器级。
//   - container_scoped：仅使用容器命名空间/挂载等稳定特征派生；再不行使用容器 ID；最后落回标准 machine-id。
//   - hybrid：尽量组合宿主机硬件指纹与容器稳定特征，兼顾稳定性与隔离性。
func ProtectedIDWithContainerAware(appID string, config *ContainerBindingConfig) (*BindingResult, error) {
	if config != nil {
		if err := config.Validate(); err != nil {
			return nil, fmt.Errorf("invalid container binding config: %w", err)
		}
	}

	id, err := idProvider()
	if err != nil {
		return nil, fmt.Errorf("machineid: %v", err)
	}

	result := &BindingResult{}
	isContainer := IsContainer()

	if isContainer {
		result.ContainerID = containerIDProvider()
	}

	// 非容器环境，使用标准优先级绑定
	if !isContainer {
		result.ContainerMode = "none"
		base, err := protectedIDWithPriority(appID, false)
		if err != nil {
			return nil, err
		}
		base.ContainerMode = result.ContainerMode
		base.ContainerID = result.ContainerID
		return base, nil
	}

	// 容器环境下的智能绑定：
	// 仅当明确配置 ContainerBindingConfig 时，才启用容器特征派生逻辑；
	// 传入 nil 表示保持历史行为（避免在容器里意外从 MAC/machine-id 变成 custom）。
	if config == nil {
		result.ContainerMode = "none"
		base, err := protectedIDWithPriority(appID, false)
		if err != nil {
			return nil, err
		}
		base.ContainerMode = result.ContainerMode
		base.ContainerID = result.ContainerID
		return base, nil
	}

	// 容器环境下的智能绑定（显式配置）
	strategy := selectBindingStrategy(config)
	result.ContainerMode = strategy

	switch strategy {
	case "host_hardware":
		// 使用宿主机硬件指纹
		if fpStatus, fpErr := fingerprintStatusProvider(); fpErr == nil && fpStatus != nil && fpStatus.Stable {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, fpStatus.Value)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeFingerprint
			result.Provider = "host_hardware"
			return result, nil
		}
		if !config.FallbackToContainer {
			return nil, fmt.Errorf("host hardware unavailable and fallback disabled")
		}
		fallthrough

	case "container_scoped":
		// 使用容器级派生ID
		features := getContainerPersistentFeaturesWithConfig(config)
		if combinedHints := combineContainerHintInput(resolveContainerFeatureCombineMode(config), features...); combinedHints != "" {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, combinedHints)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeCustom
			result.Provider = "container_scoped"
			return result, nil
		}
		// 降级到基础容器ID
		if result.ContainerID != "" {
			combined := fmt.Sprintf("%s/%s", appID, result.ContainerID)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeCustom
			result.Provider = "container_id"
			return result, nil
		}

	case "hybrid":
		// 混合模式：硬件指纹 + 容器特征
		var components []string
		if fpStatus, fpErr := fingerprintStatusProvider(); fpErr == nil && fpStatus != nil && fpStatus.Stable {
			components = append(components, fpStatus.Value)
		}
		features := getContainerPersistentFeaturesWithConfig(config)
		if combinedHints := combineContainerHintInput(resolveContainerFeatureCombineMode(config), features...); combinedHints != "" {
			components = append(components, combinedHints)
		}

		if len(components) > 0 {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, strings.Join(components, "|"))
			result.Hash = protect(combined, id)
			result.Mode = BindingModeCustom
			result.Provider = "hybrid"
			return result, nil
		}
	}

	// 最终降级：标准机器ID
	result.Hash = protect(appID, id)
	result.Mode = BindingModeMachineID
	result.Provider = "fallback"
	return result, nil
}

func uniqueIDFromContainer(appID, id, strategy string, config *ContainerBindingConfig, containerID string) (*BindingResult, bool, error) {
	result := &BindingResult{}

	switch strategy {
	case "host_hardware":
		if fpStatus, fpErr := fingerprintStatusProvider(); fpErr == nil && fpStatus != nil && fpStatus.Stable {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, fpStatus.Value)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeFingerprint
			result.Provider = "host_hardware"
			return result, true, nil
		}
		if config != nil && !config.FallbackToContainer {
			return nil, false, fmt.Errorf("host hardware unavailable and fallback disabled")
		}
		// fallback to container_scoped
		return uniqueIDFromContainer(appID, id, "container_scoped", config, containerID)

	case "container_scoped":
		features := getContainerPersistentFeaturesWithConfig(config)
		if combinedHints := combineContainerHintInput(resolveContainerFeatureCombineMode(config), features...); combinedHints != "" {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, combinedHints)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeCustom
			result.Provider = "container_scoped"
			return result, true, nil
		}
		if containerID != "" {
			combined := fmt.Sprintf("%s/%s", appID, containerID)
			result.Hash = protect(combined, id)
			result.Mode = BindingModeCustom
			result.Provider = "container_id"
			return result, true, nil
		}
		return result, false, nil

	case "hybrid":
		var components []string
		if fpStatus, fpErr := fingerprintStatusProvider(); fpErr == nil && fpStatus != nil && fpStatus.Stable {
			components = append(components, fpStatus.Value)
		}
		features := getContainerPersistentFeaturesWithConfig(config)
		if combinedHints := combineContainerHintInput(resolveContainerFeatureCombineMode(config), features...); combinedHints != "" {
			components = append(components, combinedHints)
		}
		if len(components) > 0 {
			combined := fmt.Sprintf("%s/%s/%s", appID, id, strings.Join(components, "|"))
			result.Hash = protect(combined, id)
			result.Mode = BindingModeCustom
			result.Provider = "hybrid"
			return result, true, nil
		}
		return result, false, nil
	}

	return result, false, nil
}

func uniqueIDFromBindingProviders(appID, id string) (*BindingResult, bool) {
	for _, provider := range listBindingProviders() {
		value, stable, err := provider.fn(appID, id)
		if err != nil || value == "" || !stable {
			continue
		}
		combined := fmt.Sprintf("%s/%s/%s", appID, id, value)
		result := &BindingResult{
			Hash:     protect(combined, id),
			Mode:     BindingModeCustom,
			Provider: provider.name,
		}
		return result, true
	}
	return nil, false
}
