//go:build darwin
// +build darwin

package machineid

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	chipTypeIntel        = "Intel"
	chipTypeAppleSilicon = "AppleSilicon"
)

// HardwareWeight 硬件信息权重
// 与 Linux 保持一致，用于按权重选择指纹组件。
type HardwareWeight struct {
	Name   string
	Value  string
	Weight int
}

// macOSHardwareInfo macOS 平台硬件信息（增强版）。
//
// 说明：
// - 优先从 `system_profiler -json` 解析，避免 awk/sed。
// - Apple Silicon 特有字段（如 Secure Enclave）需要在可用时才采集，避免在 Intel 机器报错。
type macOSHardwareInfo struct {
	ProductSerial string `json:"product_serial,omitempty"`
	BoardSerial   string `json:"board_serial,omitempty"`
	SystemUUID    string `json:"system_uuid,omitempty"`

	CPUSignature string `json:"cpu_signature,omitempty"`
	CPUCores     int    `json:"cpu_cores,omitempty"`
	MemorySize   uint64 `json:"memory_size,omitempty"`

	DiskSerials  []string `json:"disk_serials,omitempty"`
	MACAddresses []string `json:"mac_addresses,omitempty"`

	// ChipType 用于区分 Intel / AppleSilicon（Apple Silicon 进一步可通过 getAppleSiliconInfo 获取 M1/M2/M3）。
	ChipType string `json:"chip_type,omitempty"`

	// AppleSiliconChip 记录 M1/M2/M3 等更细的芯片信息（若可用）。
	AppleSiliconChip string `json:"apple_silicon_chip,omitempty"`

	// SecureEnclaveID 安全协处理器标识（若可用），Apple Silicon 通过 AppleARMPE 尝试获取。
	SecureEnclaveID string `json:"secure_enclave_id,omitempty"`
}

// macOS硬件信息缓存
var (
	hardwareCacheMu   sync.RWMutex
	cachedHardware    *macOSHardwareInfo
	hardwareCacheTime time.Time
	hardwareCacheTTL  = 30 * time.Minute
)

// GetHardwareInfo macOS版本的硬件信息获取
func GetHardwareInfo() (*macOSHardwareInfo, error) {
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

	info := &macOSHardwareInfo{}

	// 获取macOS硬件信息
	if err := getMacOSHardwareInfo(info); err != nil {
		// 即使采集失败，也缓存空结构，避免短时间内重复触发外部命令。
		cachedHardware = info
		hardwareCacheTime = time.Now()
		return info, err
	}

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// getMacOSHardwareInfo 获取macOS特定的硬件信息
func getMacOSHardwareInfo(info *macOSHardwareInfo) error {
	var errs []error

	// 1) system_profiler（JSON）
	if err := getSPHardwareInfo(info); err != nil {
		errs = append(errs, err)
	}
	if err := getSPStorageInfo(info); err != nil {
		errs = append(errs, err)
	}
	if err := getSPNetworkInfo(info); err != nil {
		errs = append(errs, err)
	}

	// 2) IORegistry：补充 SystemUUID / Serial / BoardSerial（部分字段在不同系统版本里位置不同）
	if err := getIORegistryInfo(info); err != nil {
		errs = append(errs, err)
	}

	// 3) Apple Silicon 特有信息（按可用性采集）
	if chip, chipType, err := getAppleSiliconInfo(); err == nil {
		if info.ChipType == "" && chipType != "" {
			info.ChipType = chipType
		}
		if info.AppleSiliconChip == "" && chip != "" {
			info.AppleSiliconChip = chip
		}
	} else {
		// 芯片检测失败不视为硬错误（可能是 Intel 或系统限制）
	}

	if seid, err := getSecureEnclaveID(); err == nil && seid != "" {
		info.SecureEnclaveID = seid
	}

	// 4) 兼容旧的 MAC 获取方式（作为兜底）
	if macInfo, err := getMACAddr(); err == nil && macInfo != nil && macInfo.Address != "" {
		if len(info.MACAddresses) == 0 {
			info.MACAddresses = []string{macInfo.Address}
		}
	}

	// 5) 基本清洗与排序，保证稳定性
	normalizeMacOSHardwareInfo(info)

	// 只要采集到任一“可用于指纹”的字段，就不返回错误；否则把错误汇总返回。
	if hasAnyMacOSIdentifier(info) {
		return nil
	}
	return errors.Join(errs...)
}

// getIORegistryInfo 使用ioreg获取IO注册表信息
func getIORegistryInfo(info *macOSHardwareInfo) error {
	// 获取平台专家设备信息
	output, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return fmt.Errorf("ioreg IOPlatformExpertDevice: %w", err)
	}
	parseIORegistryOutput(string(output), info)
	return nil
}

// parseIORegistryOutput 解析ioreg输出
func parseIORegistryOutput(output string, info *macOSHardwareInfo) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 查找IOPlatformUUID
		if strings.Contains(line, "IOPlatformUUID") {
			if parts := strings.SplitAfter(line, `" = "`); len(parts) == 2 {
				uuid := strings.TrimRight(parts[1], `"`)
				if info.SystemUUID == "" { // 如果还没有设置UUID
					info.SystemUUID = uuid
				}
			}
		} else if strings.Contains(line, "IOPlatformSerialNumber") {
			if parts := strings.SplitAfter(line, `" = "`); len(parts) == 2 {
				serial := strings.TrimRight(parts[1], `"`)
				if info.ProductSerial == "" {
					info.ProductSerial = serial
				}
			}
		} else if strings.Contains(line, "board-id") || strings.Contains(line, "board serial") || strings.Contains(line, "IOPlatformBoardSerialNumber") {
			// 不同版本/机型字段名可能不同，这里尽量覆盖常见字段。
			// 示例： "IOPlatformBoardSerialNumber" = "C0XXXXXXXXXX"
			if strings.Contains(line, `" = "`) {
				if parts := strings.SplitAfter(line, `" = "`); len(parts) == 2 {
					board := strings.TrimRight(parts[1], `"`)
					if info.BoardSerial == "" {
						info.BoardSerial = board
					}
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
		// 采集失败时仍允许基于已有字段尝试生成指纹；只有完全没有可用字段时才返回错误。
	}

	weights := collectHardwareWeights(info)
	if len(weights) == 0 {
		if err != nil {
			return nil, fmt.Errorf("no hardware identifiers available: %w", err)
		}
		return nil, fmt.Errorf("no hardware identifiers available")
	}

	sort.Slice(weights, func(i, j int) bool {
		return weights[i].Weight > weights[j].Weight
	})

	var components []string
	totalWeight := 0
	for _, w := range weights {
		if w.Value == "" {
			continue
		}
		components = append(components, fmt.Sprintf("%s:%s", w.Name, w.Value))
		totalWeight += w.Weight
		if totalWeight >= 200 {
			break
		}
	}

	if len(components) == 0 {
		if err != nil {
			return nil, fmt.Errorf("no valid hardware identifiers found: %w", err)
		}
		return nil, fmt.Errorf("no valid hardware identifiers found")
	}

	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	stable := totalWeight >= 150
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

// collectHardwareWeights 收集硬件权重信息（macOS）。
//
// 权重要求（第一阶段）：
// - ProductSerial: 100
// - SystemUUID: 95
// - DiskSerial: 80
// - ChipType: 70
// - CPUSignature: 60
func collectHardwareWeights(info *macOSHardwareInfo) []HardwareWeight {
	var weights []HardwareWeight

	// 强特征
	if info.ProductSerial != "" {
		weights = append(weights, HardwareWeight{"product_serial", info.ProductSerial, 100})
	}
	if info.SystemUUID != "" {
		weights = append(weights, HardwareWeight{"system_uuid", info.SystemUUID, 95})
	}
	if len(info.DiskSerials) > 0 && info.DiskSerials[0] != "" {
		weights = append(weights, HardwareWeight{"disk_serial", info.DiskSerials[0], 80})
	}

	// 中强特征
	if info.ChipType != "" {
		weights = append(weights, HardwareWeight{"chip_type", info.ChipType, 70})
	}
	if info.CPUSignature != "" {
		weights = append(weights, HardwareWeight{"cpu_signature", info.CPUSignature, 60})
	}

	return weights
}

func normalizeMacOSHardwareInfo(info *macOSHardwareInfo) {
	info.ProductSerial = strings.TrimSpace(info.ProductSerial)
	info.BoardSerial = strings.TrimSpace(info.BoardSerial)
	info.SystemUUID = strings.TrimSpace(info.SystemUUID)
	info.CPUSignature = strings.TrimSpace(info.CPUSignature)
	info.ChipType = strings.TrimSpace(info.ChipType)
	info.AppleSiliconChip = strings.TrimSpace(info.AppleSiliconChip)
	info.SecureEnclaveID = strings.TrimSpace(info.SecureEnclaveID)

	// 去重 + 排序，确保稳定输出
	if len(info.DiskSerials) > 0 {
		info.DiskSerials = uniqueNonEmptySorted(info.DiskSerials)
	}
	if len(info.MACAddresses) > 0 {
		info.MACAddresses = uniqueNonEmptySorted(info.MACAddresses)
	}
}

func hasAnyMacOSIdentifier(info *macOSHardwareInfo) bool {
	if info == nil {
		return false
	}
	return info.ProductSerial != "" ||
		info.SystemUUID != "" ||
		info.CPUSignature != "" ||
		len(info.DiskSerials) > 0 ||
		len(info.MACAddresses) > 0
}

func uniqueNonEmptySorted(in []string) []string {
	m := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		m[v] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ---- system_profiler JSON 解析（避免 awk/sed）----

func getSPHardwareInfo(info *macOSHardwareInfo) error {
	out, err := exec.Command("system_profiler", "SPHardwareDataType", "-json").Output()
	if err != nil {
		return fmt.Errorf("system_profiler SPHardwareDataType -json: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		return fmt.Errorf("parse SPHardwareDataType json: %w", err)
	}

	// 常见结构：{ "SPHardwareDataType": [ { ...fields... } ] }
	items, _ := payload["SPHardwareDataType"].([]any)
	if len(items) == 0 {
		return fmt.Errorf("SPHardwareDataType json: empty")
	}
	obj, _ := items[0].(map[string]any)
	if obj == nil {
		return fmt.Errorf("SPHardwareDataType json: invalid root item")
	}

	// 兼容不同字段名
	if info.ProductSerial == "" {
		info.ProductSerial = getStringFirst(obj,
			"serial_number",
			"platform_serial_number",
			"serial_number_system",
		)
	}
	if info.SystemUUID == "" {
		info.SystemUUID = getStringFirst(obj, "platform_UUID", "hardware_uuid", "uuid")
	}
	if info.CPUSignature == "" {
		info.CPUSignature = getStringFirst(obj, "chip_type", "cpu_type", "processor_name", "cpu_name")
	}

	if info.CPUCores == 0 {
		info.CPUCores = getIntFirst(obj, "number_processors", "number_cores", "total_number_cores")
	}
	if info.MemorySize == 0 {
		// system_profiler 常见输出为 "16 GB" 之类
		memStr := getStringFirst(obj, "physical_memory", "memory")
		if mem := parseMemorySize(memStr); mem > 0 {
			info.MemorySize = mem
		}
	}

	// ChipType
	if info.ChipType == "" {
		// chip_type 字段通常包含 "Apple M2" 或 "Intel" 等
		guess := guessChipTypeFromStrings(
			getStringFirst(obj, "chip_type"),
			getStringFirst(obj, "cpu_type"),
			getStringFirst(obj, "processor_name"),
			runtimeArchString(),
		)
		info.ChipType = guess
	}

	return nil
}

func getSPStorageInfo(info *macOSHardwareInfo) error {
	out, err := exec.Command("system_profiler", "SPStorageDataType", "-json").Output()
	if err != nil {
		return fmt.Errorf("system_profiler SPStorageDataType -json: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		return fmt.Errorf("parse SPStorageDataType json: %w", err)
	}

	// SPStorageDataType 的结构在系统版本间差异较大：尽量遍历所有 map/array，提取可能的序列号字段。
	serials := collectStringsDeep(payload, func(key string, _ any) bool {
		k := strings.ToLower(key)
		return k == "serial_number" || k == "device_serial" || k == "serialnumber" || k == "media_serial_number"
	})
	if len(serials) > 0 {
		info.DiskSerials = append(info.DiskSerials, serials...)
	}
	return nil
}

func getSPNetworkInfo(info *macOSHardwareInfo) error {
	out, err := exec.Command("system_profiler", "SPNetworkDataType", "-json").Output()
	if err != nil {
		return fmt.Errorf("system_profiler SPNetworkDataType -json: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		return fmt.Errorf("parse SPNetworkDataType json: %w", err)
	}

	macs := collectStringsDeep(payload, func(key string, _ any) bool {
		return strings.EqualFold(key, "spnetwork_mac_address") ||
			strings.EqualFold(key, "mac_address") ||
			strings.EqualFold(key, "ethernet_address")
	})
	if len(macs) > 0 {
		info.MACAddresses = append(info.MACAddresses, macs...)
	}
	return nil
}

func collectStringsDeep(v any, want func(key string, value any) bool) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			if want(k, vv) {
				if s, ok := vv.(string); ok {
					out = append(out, s)
				}
			}
			out = append(out, collectStringsDeep(vv, want)...)
		}
	case []any:
		for _, vv := range x {
			out = append(out, collectStringsDeep(vv, want)...)
		}
	}
	return out
}

func getStringFirst(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func getIntFirst(m map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case float64:
				return int(t)
			case int:
				return t
			case string:
				if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func parseMemorySize(s string) uint64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}
	// 典型格式："16 GB" / "8 GB" / "16384 MB"
	re := regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*(KB|MB|GB|TB)\s*$`)
	m := re.FindStringSubmatch(s)
	if len(m) != 3 {
		return 0
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil || f <= 0 {
		return 0
	}
	unit := strings.ToUpper(m[2])
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch unit {
	case "KB":
		return uint64(f * KB)
	case "MB":
		return uint64(f * MB)
	case "GB":
		return uint64(f * GB)
	case "TB":
		return uint64(f * TB)
	default:
		return 0
	}
}

func runtimeArchString() string {
	// 避免引入 runtime 仅用于 GOARCH：从环境变量兜底。
	// 在交叉编译场景里，GOARCH 是编译期常量，但这里用于运行时判断只作为辅助信息。
	if v := os.Getenv("GOARCH"); v != "" {
		return v
	}
	return ""
}

func guessChipTypeFromStrings(inputs ...string) string {
	joined := strings.ToLower(strings.Join(inputs, " "))
	if strings.Contains(joined, "apple") || strings.Contains(joined, "m1") || strings.Contains(joined, "m2") || strings.Contains(joined, "m3") || strings.Contains(joined, "arm") || strings.Contains(joined, "aarch64") {
		return chipTypeAppleSilicon
	}
	if strings.Contains(joined, "intel") || strings.Contains(joined, "x86") || strings.Contains(joined, "i7") || strings.Contains(joined, "i9") {
		return chipTypeIntel
	}
	return ""
}

// ---- Apple Silicon 相关（兼容检测）----

func getAppleSiliconInfo() (chip string, chipType string, err error) {
	// Apple Silicon 常见特征：uname -m 返回 arm64；或 sysctl machdep.cpu.brand_string 不存在/为空等。
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "", "", fmt.Errorf("uname -m: %w", err)
	}
	arch := strings.TrimSpace(string(out))
	if arch != "arm64" && arch != "aarch64" {
		// 不是 Apple Silicon
		return "", chipTypeIntel, nil
	}

	chipType = chipTypeAppleSilicon

	// 优先用 system_profiler 的 chip_type 字段推断 M1/M2/M3
	var hw macOSHardwareInfo
	_ = getSPHardwareInfo(&hw)
	if hw.CPUSignature != "" {
		if c := detectMSeries(hw.CPUSignature); c != "" {
			return c, chipType, nil
		}
	}

	// 兜底：sysctl -n machdep.cpu.brand_string 在 Apple Silicon 上可能不可用；但尝试一次不影响。
	if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
		if c := detectMSeries(string(out)); c != "" {
			return c, chipType, nil
		}
	}

	return "", chipType, nil
}

func detectMSeries(s string) string {
	s = strings.ToUpper(s)
	switch {
	case strings.Contains(s, "M1"):
		return "M1"
	case strings.Contains(s, "M2"):
		return "M2"
	case strings.Contains(s, "M3"):
		return "M3"
	default:
		return ""
	}
}

func getSecureEnclaveID() (string, error) {
	// Apple Silicon：尝试从 AppleARMPE 类读取（若不可用则返回空）。
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		arch := strings.TrimSpace(string(out))
		if arch != "arm64" && arch != "aarch64" {
			return "", nil
		}
	}

	// ioreg -rd1 -c AppleARMPE
	out, err := exec.Command("ioreg", "-rd1", "-c", "AppleARMPE").Output()
	if err != nil {
		// 该类可能不存在或权限受限：作为可选信息不抛硬错误
		return "", nil
	}

	// 常见字段并不稳定，这里只做“尽量提取”: 取第一段看起来像 ID 的字符串字段
	// 例如可能包含 "unique-chip-id" / "ecid" 等（不同系统差异大）。
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, `" = "`) {
			continue
		}
		// 尝试提取： "key" = "value"
		parts := strings.SplitAfter(line, `" = "`)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimRight(parts[1], `"`)
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		// 排除明显无关的短值
		if len(val) < 8 {
			continue
		}
		// 排除布尔等
		if val == "0" || val == "1" {
			continue
		}
		return val, nil
	}
	return "", nil
}

// ClearHardwareCache macOS版本
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}
