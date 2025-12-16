//go:build windows
// +build windows

package machineid

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// windowsHardwareInfo Windows 平台硬件信息（对齐 Linux 结构字段）。
// 注意：字段可能为空；单个查询失败不影响整体。
type windowsHardwareInfo struct {
	ProductUUID   string `json:"product_uuid,omitempty"`
	BoardSerial   string `json:"board_serial,omitempty"`
	ProductSerial string `json:"product_serial,omitempty"`
	SystemVendor  string `json:"system_vendor,omitempty"`
	ProductName   string `json:"product_name,omitempty"`

	CPUSignature string `json:"cpu_signature,omitempty"`
	CPUCores     int    `json:"cpu_cores,omitempty"`

	DiskSerials  []string `json:"disk_serials,omitempty"`
	MACAddresses []string `json:"mac_addresses,omitempty"`
	MemorySize   uint64   `json:"memory_size,omitempty"`

	BIOSSerial  string `json:"bios_serial,omitempty"`
	BIOSVersion string `json:"bios_version,omitempty"`
}

// Windows 硬件信息缓存
var (
	hardwareCacheMu   sync.RWMutex
	cachedHardware    *windowsHardwareInfo
	hardwareCacheTime time.Time
	hardwareCacheTTL  = 30 * time.Minute
)

// GetHardwareInfo 获取 Windows 硬件信息（带缓存）。
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
	getWindowsHardwareInfo(info)

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// getWindowsHardwareInfo 收集 Windows 特定硬件信息。
func getWindowsHardwareInfo(info *windowsHardwareInfo) {
	// 先尝试 WMI / WMIC（更接近硬件真实值；但可能被策略禁用）
	applyCPUInfo(info, getWMICPUInfo())
	applyBoardInfo(info, getWMIBoardInfo())
	applyBIOSInfo(info, getWMIBIOSInfo())
	if serials := getWMIDiskSerials(); len(serials) > 0 {
		info.DiskSerials = serials
	}
	if mem := getWMIMemoryInfo(); mem > 0 {
		info.MemorySize = mem
	}

	// WMI 失败时用注册表备选（Windows 7+ 可用，但字段可能较“软”）
	fillFromRegistryFallback(info)

	// 网络信息：复用现有跨平台实现（选择最稳定的 MAC）
	if macInfo, err := getMACAddr(); err == nil && macInfo != nil && macInfo.Address != "" {
		info.MACAddresses = []string{macInfo.Address}
	}

	// 统一化：排序确保输出稳定（指纹组件顺序稳定）
	if len(info.DiskSerials) > 0 {
		sort.Strings(info.DiskSerials)
	}
	if len(info.MACAddresses) > 0 {
		sort.Strings(info.MACAddresses)
	}
}

func applyCPUInfo(info *windowsHardwareInfo, cpuID, cpuName string, cpuCores int) {
	if info.CPUSignature == "" {
		// Windows 上的 CPU “签名”优先用 ProcessorId（更稳定），其次 Name。
		if cpuID != "" {
			info.CPUSignature = cpuID
		} else if cpuName != "" {
			info.CPUSignature = cpuName
		}
	}
	if info.CPUCores == 0 && cpuCores > 0 {
		info.CPUCores = cpuCores
	}
}

func applyBoardInfo(info *windowsHardwareInfo, serial, product, manufacturer string) {
	if info.BoardSerial == "" && serial != "" {
		info.BoardSerial = serial
	}
	if info.ProductName == "" && product != "" {
		info.ProductName = product
	}
	if info.SystemVendor == "" && manufacturer != "" {
		info.SystemVendor = manufacturer
	}
}

func applyBIOSInfo(info *windowsHardwareInfo, serial, version string) {
	if info.BIOSSerial == "" && serial != "" {
		info.BIOSSerial = serial
	}
	if info.BIOSVersion == "" && version != "" {
		info.BIOSVersion = version
	}
}

// fillFromRegistryFallback WMI/WMIC 失败时补全关键字段。
// 约束：只从 HKLM\\HARDWARE\\DESCRIPTION\\System 及其子键读取，避免依赖额外权限/组件。
func fillFromRegistryFallback(info *windowsHardwareInfo) {
	// 注意：MachineGuid 在某些场景更像“安装标识”，但作为 ProductUUID 备选可用。
	if info.ProductUUID == "" {
		if value := readRegistryString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid"); value != "" {
			info.ProductUUID = value
		}
	}

	// BIOS/系统信息：Windows 7+ 常见
	biosKey := `HARDWARE\DESCRIPTION\System\BIOS`
	if info.SystemVendor == "" {
		info.SystemVendor = readRegistryString(registry.LOCAL_MACHINE, biosKey, "SystemManufacturer")
	}
	if info.ProductName == "" {
		info.ProductName = readRegistryString(registry.LOCAL_MACHINE, biosKey, "SystemProductName")
	}
	if info.ProductSerial == "" {
		// 有些机器提供 SystemSerialNumber；若缺失则保持空。
		info.ProductSerial = readRegistryString(registry.LOCAL_MACHINE, biosKey, "SystemSerialNumber")
	}
	if info.BoardSerial == "" {
		// 注意：BaseBoardSerialNumber 并非所有机器都填。
		info.BoardSerial = readRegistryString(registry.LOCAL_MACHINE, biosKey, "BaseBoardSerialNumber")
		if info.BoardSerial == "" {
			// 最后备选：旧实现里用了 BaseBoardProduct，这不是序列号，但可帮助稳定性（低质量数据也要谨慎）
			info.BoardSerial = readRegistryString(registry.LOCAL_MACHINE, biosKey, "BaseBoardProduct")
		}
	}

	if info.BIOSSerial == "" {
		// BIOSSerialNumber / BIOSVersion 的命名在不同版本上可能不一致，尽量多尝试
		info.BIOSSerial = readRegistryString(registry.LOCAL_MACHINE, biosKey, "BIOSSerialNumber")
	}
	if info.BIOSVersion == "" {
		info.BIOSVersion = readRegistryString(registry.LOCAL_MACHINE, biosKey, "BIOSVersion")
	}

	// CPU 备选：CentralProcessor\\0
	if info.CPUSignature == "" {
		info.CPUSignature = readRegistryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")
	}
}

// getWMICPUInfo 通过 WMIC 查询 CPU 信息。
// 命令：wmic cpu get ProcessorId,Name,NumberOfCores
func getWMICPUInfo() (processorID string, name string, cores int) {
	out, err := runWMIC("cpu", "get", "ProcessorId,Name,NumberOfCores")
	if err != nil || out == "" {
		return "", "", 0
	}

	rows := parseWMICTable(out)
	if len(rows) == 0 {
		return "", "", 0
	}

	// 多 CPU：拼接 ProcessorId；核心数求和；Name 取第一个非空
	var ids []string
	totalCores := 0
	cpuName := ""
	for _, row := range rows {
		id := cleanWMIValue(row["ProcessorId"])
		if id != "" && !looksLikePlaceholderSerial(id) {
			ids = append(ids, id)
		}

		if cpuName == "" {
			n := cleanWMIValue(row["Name"])
			if n != "" {
				cpuName = n
			}
		}

		if c := parseInt(cleanWMIValue(row["NumberOfCores"])); c > 0 {
			totalCores += c
		}
	}

	sort.Strings(ids)
	if len(ids) > 0 {
		processorID = strings.Join(ids, "+")
	}
	name = cpuName
	cores = totalCores
	return processorID, name, cores
}

// getWMIBoardInfo 通过 WMIC 查询主板信息。
// 命令：wmic baseboard get SerialNumber,Product,Manufacturer
func getWMIBoardInfo() (serial, product, manufacturer string) {
	out, err := runWMIC("baseboard", "get", "SerialNumber,Product,Manufacturer")
	if err != nil || out == "" {
		return "", "", ""
	}
	rows := parseWMICTable(out)
	if len(rows) == 0 {
		return "", "", ""
	}

	// 只取第一行（一般只有一个 BaseBoard）
	serial = cleanWMIValue(rows[0]["SerialNumber"])
	if looksLikePlaceholderSerial(serial) {
		serial = ""
	}
	product = cleanWMIValue(rows[0]["Product"])
	manufacturer = cleanWMIValue(rows[0]["Manufacturer"])
	return serial, product, manufacturer
}

// getWMIBIOSInfo 通过 WMIC 查询 BIOS 信息。
// 命令：wmic bios get SerialNumber,Version
func getWMIBIOSInfo() (serial, version string) {
	out, err := runWMIC("bios", "get", "SerialNumber,Version")
	if err != nil || out == "" {
		return "", ""
	}
	rows := parseWMICTable(out)
	if len(rows) == 0 {
		return "", ""
	}

	serial = cleanWMIValue(rows[0]["SerialNumber"])
	if looksLikePlaceholderSerial(serial) {
		serial = ""
	}
	version = cleanWMIValue(rows[0]["Version"])
	return serial, version
}

// getWMIDiskSerials 通过 WMIC 查询磁盘序列号。
// 命令：wmic diskdrive get SerialNumber,Model,Size
func getWMIDiskSerials() []string {
	out, err := runWMIC("diskdrive", "get", "SerialNumber,Model,Size")
	if err != nil || out == "" {
		return nil
	}
	rows := parseWMICTable(out)
	if len(rows) == 0 {
		return nil
	}

	var serials []string
	for _, row := range rows {
		serial := cleanWMIValue(row["SerialNumber"])
		if serial == "" || looksLikePlaceholderSerial(serial) {
			continue
		}
		serials = append(serials, serial)
	}
	serials = uniqueStrings(serials)
	sort.Strings(serials)
	return serials
}

// getWMIMemoryInfo 通过 WMIC 汇总物理内存容量（字节）。
// 命令：wmic memorychip get Capacity
func getWMIMemoryInfo() uint64 {
	out, err := runWMIC("memorychip", "get", "Capacity")
	if err != nil || out == "" {
		return 0
	}

	// memorychip 输出往往只有一列 Capacity
	rows := parseWMICTable(out)
	if len(rows) == 0 {
		return 0
	}

	var total uint64
	for _, row := range rows {
		capStr := cleanWMIValue(row["Capacity"])
		if capStr == "" {
			// 某些系统表头可能是 Capacity，解析器也可能放在空 key；兜底扫一遍值
			for _, v := range row {
				if v != "" {
					capStr = cleanWMIValue(v)
					break
				}
			}
		}
		if capStr == "" {
			continue
		}
		if n, err := strconv.ParseUint(capStr, 10, 64); err == nil && n > 0 {
			total += n
		}
	}
	return total
}

// runWMIC 执行 wmic 并返回 stdout 文本。
// 兼容性：Windows 7+。注意：部分新系统可能移除/禁用 wmic，此时将触发注册表备选。
func runWMIC(args ...string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("wmic", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// 不把 stderr 暴露给上层（避免泄漏本地信息）；只返回错误以触发降级
		return "", err
	}
	return stdout.String(), nil
}

// parseWMICTable 解析 wmic “表格”输出为行映射。
// 约定：第一行是表头；后续每行是一条记录；字段由多个空格分隔。
// 注意：wmic 输出对齐依赖空格，不能用单纯 strings.Fields 完全可靠，但对常见 wmic 输出足够稳健。
func parseWMICTable(output string) []map[string]string {
	lines := splitNonEmptyLines(output)
	if len(lines) < 2 {
		return nil
	}

	headerLine := lines[0]
	colNames := splitWMICColumns(headerLine)
	if len(colNames) == 0 {
		return nil
	}

	var rows []map[string]string
	for _, line := range lines[1:] {
		values := splitWMICColumns(line)
		if len(values) == 0 {
			continue
		}
		row := map[string]string{}
		// 对齐列：多余的值忽略，缺失的留空
		for i, col := range colNames {
			if i < len(values) {
				row[col] = values[i]
			} else {
				row[col] = ""
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// splitWMICColumns 用“2 个以上空格”切分列，保留单词内空格（例如 CPU Name）。
func splitWMICColumns(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	parts := strings.FieldsFunc(line, func(r rune) bool {
		// 这里不能直接用 Fields，会把 Name 拆碎；因此用“连续空格分隔”的策略：
		// FieldsFunc 无法直接看连续空格个数，所以我们先把连续空格压缩成一个特殊分隔符。
		return false
	})

	// 上面故意不分割，下面手工扫描连续空格并切分
	var cols []string
	var cur strings.Builder
	spaceRun := 0
	for _, r := range line {
		if r == ' ' || r == '\t' || r == '\r' {
			spaceRun++
			if spaceRun >= 2 {
				// 达到分隔阈值：结束当前列
				if cur.Len() > 0 {
					cols = append(cols, cur.String())
					cur.Reset()
				}
				// 继续吃掉后续空白
				continue
			}
			// 单个空格视为内容（用于 Name 等字段）
			cur.WriteRune(' ')
			continue
		}
		spaceRun = 0
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		cols = append(cols, cur.String())
	}

	// 如果没有切出多列，退化为 Fields（例如只有一列 Capacity）
	if len(cols) <= 1 {
		if f := strings.Fields(line); len(f) > 0 {
			return f
		}
	}

	// 去掉每列两侧空白
	for i := range cols {
		cols[i] = strings.TrimSpace(cols[i])
	}
	return cols
}

func splitNonEmptyLines(s string) []string {
	raw := strings.Split(s, "\n")
	var out []string
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 过滤掉 wmic 可能输出的 “No Instance(s) Available.”
		if strings.Contains(strings.ToLower(line), "no instance") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func cleanWMIValue(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\u0000")
	return strings.TrimSpace(s)
}

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func looksLikePlaceholderSerial(s string) bool {
	if s == "" {
		return true
	}
	l := strings.ToLower(strings.TrimSpace(s))
	placeholders := []string{
		"none",
		"to be filled by o.e.m.",
		"to be filled by oem",
		"default string",
		"unknown",
		"not specified",
		"na",
		"n/a",
	}
	for _, p := range placeholders {
		if l == p {
			return true
		}
	}
	// 常见的全 0 / 全 F
	if strings.Trim(l, "0") == "" {
		return true
	}
	if strings.Trim(l, "f") == "" {
		return true
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// readRegistryString 读取注册表字符串值。
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

// GetHardwareFingerprint 生成硬件指纹。
func GetHardwareFingerprint() (string, error) {
	status, err := GetHardwareFingerprintStatus()
	if err != nil {
		return "", err
	}
	return status.Value, nil
}

// GetHardwareFingerprintStatus 返回指纹与稳定性（权重累计达到阈值认为稳定）。
func GetHardwareFingerprintStatus() (*FingerprintStatus, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return nil, err
	}

	weights := collectHardwareWeights(info)
	if len(weights) == 0 {
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
		return nil, fmt.Errorf("no valid hardware identifiers found")
	}

	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	stable := totalWeight >= 150
	return &FingerprintStatus{Value: fmt.Sprintf("%x", hash), Stable: stable}, nil
}

// collectHardwareWeights 收集硬件权重信息（Windows 版）。
// 权重要求：
// - ProductUUID: 100, BoardSerial: 90, BIOSSerial: 85
// - DiskSerial: 75, CPUSignature: 60, MemorySize: 40
func collectHardwareWeights(info *windowsHardwareInfo) []HardwareWeight {
	var weights []HardwareWeight

	if info.ProductUUID != "" && !looksLikePlaceholderSerial(info.ProductUUID) {
		weights = append(weights, HardwareWeight{"product_uuid", info.ProductUUID, 100})
	}
	if info.BoardSerial != "" && !looksLikePlaceholderSerial(info.BoardSerial) {
		weights = append(weights, HardwareWeight{"board_serial", info.BoardSerial, 90})
	}
	if info.BIOSSerial != "" && !looksLikePlaceholderSerial(info.BIOSSerial) {
		weights = append(weights, HardwareWeight{"bios_serial", info.BIOSSerial, 85})
	}
	if len(info.DiskSerials) > 0 {
		weights = append(weights, HardwareWeight{"disk_serial", info.DiskSerials[0], 75})
	}
	if info.CPUSignature != "" && !looksLikePlaceholderSerial(info.CPUSignature) {
		weights = append(weights, HardwareWeight{"cpu_signature", info.CPUSignature, 60})
	}
	if info.MemorySize > 0 {
		weights = append(weights, HardwareWeight{"memory_size", fmt.Sprintf("%d", info.MemorySize), 40})
	}

	return weights
}

// ProtectedIDWithHardware Windows 版本（硬件指纹 + machine id）。
func ProtectedIDWithHardware(appID string) (string, error) {
	status, err := GetHardwareFingerprintStatus()
	if err != nil {
		return "", fmt.Errorf("machineid: failed to get hardware fingerprint: %v", err)
	}

	id, err := ID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}

	combined := fmt.Sprintf("%s/%s/%s", appID, id, status.Value)
	return protect(combined, id), nil
}

// ClearHardwareCache 清理 Windows 硬件信息缓存。
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()
	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}
