//go:build linux
// +build linux

package machineid

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// linuxHardwareInfo Linux平台简化硬件信息
type linuxHardwareInfo struct {
	ProductUUID       string   `json:"product_uuid,omitempty"`
	SystemUUID        string   `json:"system_uuid,omitempty"`
	BoardSerial       string   `json:"board_serial,omitempty"`
	ProductSerial     string   `json:"product_serial,omitempty"`
	SystemVendor      string   `json:"system_vendor,omitempty"`
	ProductName       string   `json:"product_name,omitempty"`
	BoardVendor       string   `json:"board_vendor,omitempty"`
	RootPartitionUUID string   `json:"root_partition_uuid,omitempty"`
	DiskSerials       []string `json:"disk_serials,omitempty"`
	NVMeSerials       []string `json:"nvme_serials,omitempty"`
	CPUIdentifier     string   `json:"cpu_identifier,omitempty"`
	CPUSignature      string   `json:"cpu_signature,omitempty"`
	CPUCores          int      `json:"cpu_cores,omitempty"`
	MACAddresses      []string `json:"mac_addresses,omitempty"`
	MemorySize        uint64   `json:"memory_size,omitempty"`
	PCIDevices        []string `json:"pci_devices,omitempty"`
	MachineID         string   `json:"machine_id,omitempty"`
	Hostname          string   `json:"hostname,omitempty"`
	BIOSVersion       string   `json:"bios_version,omitempty"`

	// Linux 硬件增强信息（新增字段；保持对现有字段的向后兼容）
	UEFIVariables []string `json:"uefi_variables,omitempty"`
	TPMVersion    string   `json:"tpm_version,omitempty"`
	ACPITables    []string `json:"acpi_tables,omitempty"`

	// B1 扩展字段：增强硬件特征
	ChassisSerial   string   `json:"chassis_serial,omitempty"`    // 机箱序列号
	NICPCIAddresses []string `json:"nic_pci_addresses,omitempty"` // 网卡 PCI 地址
	USBControllers  []string `json:"usb_controllers,omitempty"`   // USB 控制器 ID
}

var (
	hardwareCacheMu   sync.RWMutex
	cachedHardware    *linuxHardwareInfo
	hardwareCacheTime time.Time
	hardwareCacheTTL  = 30 * time.Minute // 硬件信息缓存30分钟
)

// GetHardwareInfo 获取详细硬件信息
func GetHardwareInfo() (*linuxHardwareInfo, error) {
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

	info := &linuxHardwareInfo{}

	// 获取DMI信息
	getDMIInfo(info)

	// 获取存储信息
	getStorageInfo(info)

	// 获取CPU信息
	getCPUInfo(info)

	// 获取网络信息
	getNetworkInfo(info)

	// 获取内存信息
	getMemoryInfo(info)

	// 获取PCI设备信息
	getPCIInfo(info)

	// 获取平台标识信息
	getPlatformIdentity(info)

	// 获取UEFI变量信息（如果系统支持UEFI并暴露sysfs）
	getUEFIVariables(info)

	// 获取TPM信息（如果存在TPM设备节点）
	getTPMInfo(info)

	// 获取ACPI/SMBIOS表信息（用于补充主机级固件特征）
	getACPIInfo(info)

	// B1: 获取网卡 PCI 地址
	getNICPCIAddresses(info)

	// B1: 获取 USB 控制器信息
	getUSBControllers(info)

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
}

// getUEFIVariables 读取 UEFI 变量名列表。
//
// 用途说明（中文）：
//   - UEFI 变量来自固件层（比软件特征更稳定），通常在物理机上可用。
//   - 在容器/非 UEFI 启动/权限受限场景下可能不存在，此时应优雅降级为空。
//
// 实现策略：
//   - 同时兼容 /sys/firmware/efi/vars/ 与 /sys/firmware/efi/efivars/ 两种路径。
//   - 只收集“变量名”，不读取变量内容，避免权限/隐私与不必要的 IO 成本。
func getUEFIVariables(info *linuxHardwareInfo) {
	baseCandidates := []string{
		"/sys/firmware/efi/vars",
		"/sys/firmware/efi/efivars",
	}

	var vars []string
	for _, base := range baseCandidates {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := strings.TrimSpace(entry.Name())
			if name == "" {
				continue
			}
			// 过滤掉明显的临时/噪声项；其余保留
			vars = append(vars, name)
		}
	}

	if len(vars) == 0 {
		return
	}

	sort.Strings(vars)
	info.UEFIVariables = uniqStrings(vars)
}

// getTPMInfo 读取 TPM 设备信息。
//
// 用途说明（中文）：
//   - TPM 是硬件安全模块，作为绑定特征通常比软件信息更稳定。
//   - 这里不做复杂的用户态访问，只从 sysfs 读取描述与 PCR 摘要，避免依赖 tpm2-tools。
//
// 实现策略：
//   - description：/sys/class/tpm/tpm0/device/description（可能不存在）
//   - pcrs：优先尝试 /sys/class/tpm/tpm0/pcrs（或同目录下可能存在的 pcrs_*），不存在则跳过
//   - 读取失败一律忽略，不影响整体硬件信息采集。
func getTPMInfo(info *linuxHardwareInfo) {
	tpmBase := "/sys/class/tpm/tpm0"

	descPath := filepath.Join(tpmBase, "device", "description")
	if desc, err := readFileString(descPath); err == nil && desc != "" {
		info.TPMVersion = normalizeOneLine(desc)
	}

	// 读取 PCR 信息：不同内核/驱动可能路径不同，这里做一个温和的探测
	pcrCandidates := []string{
		filepath.Join(tpmBase, "pcrs"),
		filepath.Join(tpmBase, "pcrs_sha1"),
		filepath.Join(tpmBase, "pcrs_sha256"),
	}
	for _, p := range pcrCandidates {
		if pcrs, err := readFileString(p); err == nil && pcrs != "" {
			// PCR 作为“是否支持 TPM 的佐证”，不直接暴露到结构体字段，避免巨大字符串影响输出。
			// 但为了后续权重与指纹可用性，我们用一个轻量摘要拼入 TPMVersion。
			sum := sha256.Sum256([]byte(pcrs))
			if info.TPMVersion == "" {
				info.TPMVersion = "tpm"
			}
			info.TPMVersion = info.TPMVersion + "|pcrs:" + fmt.Sprintf("%x", sum[:8])
			break
		}
	}
}

// getACPIInfo 读取 ACPI 表信息（包含 SMBIOS 相关表）。
//
// 用途说明（中文）：
//   - 固件/平台表属于更靠近硬件的特征，理论上比主机名、machine-id 更稳定。
//   - 在容器、裁剪内核或权限受限环境下可能缺失，必须优雅降级。
//
// 实现策略：
//   - 列出 /sys/firmware/acpi/tables/ 下的表名作为特征；并优先关注 SMBIOS 相关表（如 SMBIOS/DMI）。
//   - 不读取表内容，避免权限与体积问题。
func getACPIInfo(info *linuxHardwareInfo) {
	acpiTablesPath := "/sys/firmware/acpi/tables"
	entries, err := os.ReadDir(acpiTablesPath)
	if err != nil {
		return
	}

	var tables []string
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if name == "" {
			continue
		}
		// 跳过元数据文件
		if strings.HasSuffix(name, ".aml") || strings.HasSuffix(name, ".dat") {
			// 某些发行版可能会放置额外文件；保守跳过显然不需要的扩展
			continue
		}
		tables = append(tables, name)
	}

	if len(tables) == 0 {
		return
	}

	sort.Strings(tables)
	info.ACPITables = uniqStrings(tables)
}

// getDMIInfo 获取DMI/SMBIOS信息
func getDMIInfo(info *linuxHardwareInfo) {
	dmiBasePath := "/sys/class/dmi/id"

	// 尝试读取各种DMI信息
	dmiFields := map[string]*string{
		"product_uuid":   &info.ProductUUID,
		"board_serial":   &info.BoardSerial,
		"product_serial": &info.ProductSerial,
		"sys_vendor":     &info.SystemVendor,
		"product_name":   &info.ProductName,
		"board_vendor":   &info.BoardVendor,
		"bios_version":   &info.BIOSVersion,
		"chassis_serial": &info.ChassisSerial, // B1: 机箱序列号
	}

	for file, field := range dmiFields {
		if data, err := readFileString(filepath.Join(dmiBasePath, file)); err == nil {
			*field = strings.TrimSpace(data)
		}
	}

	if info.SystemUUID == "" {
		info.SystemUUID = info.ProductUUID
	}
}

// getStorageInfo 获取存储设备信息
func getStorageInfo(info *linuxHardwareInfo) {
	// 获取根分区UUID
	if mounts, err := readFileString("/proc/mounts"); err == nil {
		lines := strings.Split(mounts, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "/" {
				// 尝试从设备名获取UUID
				if uuid := getPartitionUUID(fields[0]); uuid != "" {
					info.RootPartitionUUID = uuid
					break
				}
			}
		}
	}

	// 获取硬盘序列号
	if diskSerials := getDiskSerials(); len(diskSerials) > 0 {
		info.DiskSerials = diskSerials
	}
	if nvmeSerials := getNVMeSerials(); len(nvmeSerials) > 0 {
		info.NVMeSerials = nvmeSerials
	}
}

// getCPUInfo 获取CPU信息
func getCPUInfo(info *linuxHardwareInfo) {
	if cpuinfo, err := readFileString("/proc/cpuinfo"); err == nil {
		lines := strings.Split(cpuinfo, "\n")
		coreCount := 0
		var signatures []string
		seenSignature := make(map[string]struct{})

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := ""
			if len(parts) == 2 {
				value = strings.TrimSpace(parts[1])
			}

			if key == "processor" {
				coreCount++
				continue
			}

			switch key {
			case "Serial":
				if value != "" {
					info.CPUIdentifier = value
				}
			case "vendor_id", "model name", "cpu family", "model", "stepping", "microcode":
				if value == "" {
					continue
				}
				if _, ok := seenSignature[key+":"+value]; ok {
					continue
				}
				seenSignature[key+":"+value] = struct{}{}
				signatures = append(signatures, key+"="+value)
			}
		}

		info.CPUCores = coreCount
		if len(signatures) > 0 {
			// 将CPU特征组合成签名
			info.CPUSignature = strings.Join(signatures, "-")
		}
	}
}

// getNetworkInfo 获取网络信息
func getNetworkInfo(info *linuxHardwareInfo) {
	if interfaces, err := getNetworkInterfaces(); err == nil {
		var macs []string
		for _, iface := range interfaces {
			if iface != "" {
				macs = append(macs, iface)
			}
		}
		if len(macs) > 0 {
			sort.Strings(macs) // 确保顺序一致
			info.MACAddresses = macs
		}
	}
}

// getMemoryInfo 获取内存信息
func getMemoryInfo(info *linuxHardwareInfo) {
	if meminfo, err := readFileString("/proc/meminfo"); err == nil {
		lines := strings.Split(meminfo, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if size, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						info.MemorySize = size * 1024 // 转换为字节
					}
				}
				break
			}
		}
	}
}

// getPCIInfo 获取PCI设备信息
func getPCIInfo(info *linuxHardwareInfo) {
	pciPath := "/sys/bus/pci/devices"
	if entries, err := os.ReadDir(pciPath); err == nil {
		var devices []string
		for _, entry := range entries {
			// sysfs 下 PCI 设备通常以符号链接暴露；不能依赖 entry.IsDir()。
			vendorPath := filepath.Join(pciPath, entry.Name(), "vendor")
			devicePath := filepath.Join(pciPath, entry.Name(), "device")

			vendor, vendorErr := readFileString(vendorPath)
			device, deviceErr := readFileString(devicePath)

			if vendorErr == nil && deviceErr == nil {
				devices = append(devices, strings.TrimSpace(vendor)+":"+strings.TrimSpace(device))
			}
		}
		if len(devices) > 0 {
			sort.Strings(devices) // 确保顺序一致
			info.PCIDevices = devices
		}
	}
}

// getPlatformIdentity 收集 machine-id 与主机名等软指纹数据
func getPlatformIdentity(info *linuxHardwareInfo) {
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}
	for _, path := range paths {
		if data, err := readFileString(path); err == nil && data != "" {
			info.MachineID = data
			break
		}
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}
}

// GetHardwareFingerprint 生成硬件指纹
func GetHardwareFingerprint() (string, error) {
	status, err := GetHardwareFingerprintStatus()
	if err != nil {
		return "", err
	}
	return status.Value, nil
}

// GetHardwareFingerprintStatus 返回指纹值及稳定性
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

// collectHardwareWeights 收集硬件权重信息
func collectHardwareWeights(info *linuxHardwareInfo) []HardwareWeight {
	var weights []HardwareWeight
	seen := make(map[string]struct{})
	add := func(name, value string, weight int) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[name+":"+value]; ok {
			return
		}
		seen[name+":"+value] = struct{}{}
		weights = append(weights, HardwareWeight{name, value, weight})
	}

	// UEFI / TPM（固件/安全模块，优先于软件特征）
	// 注意：这里的权重代表“稳定/不可伪造程度”，应高于 machine-id/hostname 等软件特征。
	if len(info.UEFIVariables) > 0 {
		// 为了避免变量名列表过长，指纹权重侧只取一个摘要值
		sum := sha256.Sum256([]byte(strings.Join(info.UEFIVariables, ",")))
		add("uefi_vars", fmt.Sprintf("%x", sum[:16]), 100)
	}
	if info.TPMVersion != "" {
		add("tpm", info.TPMVersion, 95)
	}
	if len(info.ACPITables) > 0 {
		// ACPI 表名可作为固件侧的补充特征，权重略低于 TPM
		sum := sha256.Sum256([]byte(strings.Join(info.ACPITables, ",")))
		add("acpi_tables", fmt.Sprintf("%x", sum[:16]), 92)
	}

	// DMI信息（高权重）
	if info.ProductUUID != "" && info.ProductUUID != "00000000-0000-0000-0000-000000000000" {
		add("product_uuid", info.ProductUUID, 100)
	}
	if info.SystemUUID != "" && info.SystemUUID != info.ProductUUID && info.SystemUUID != "00000000-0000-0000-0000-000000000000" {
		add("system_uuid", info.SystemUUID, 95)
	}
	if info.BoardSerial != "" && info.BoardSerial != "None" && info.BoardSerial != "To be filled by O.E.M." {
		add("board_serial", info.BoardSerial, 90)
	}
	if info.ProductSerial != "" && info.ProductSerial != "None" && info.ProductSerial != "To be filled by O.E.M." {
		add("product_serial", info.ProductSerial, 85)
	}
	// B1: 机箱序列号（权重略低于产品序列号）
	if info.ChassisSerial != "" && info.ChassisSerial != "None" && info.ChassisSerial != "To be filled by O.E.M." {
		add("chassis_serial", info.ChassisSerial, 83)
	}
	if info.BIOSVersion != "" && info.BIOSVersion != "None" {
		add("bios_version", info.BIOSVersion, 40)
	}

	// 存储信息（高权重）
	if info.RootPartitionUUID != "" {
		add("root_uuid", info.RootPartitionUUID, 80)
	}
	if len(info.DiskSerials) > 0 {
		// 使用第一个磁盘序列号
		add("disk_serial", info.DiskSerials[0], 75)
	}
	if len(info.NVMeSerials) > 0 {
		add("nvme_serial", info.NVMeSerials[0], 78)
	}

	// CPU信息（中等权重）
	if info.CPUIdentifier != "" {
		add("cpu_id", info.CPUIdentifier, 70)
	}
	if info.CPUSignature != "" {
		add("cpu_signature", info.CPUSignature, 60)
	}

	// 系统信息（中等权重）
	if info.SystemVendor != "" && info.ProductName != "" {
		systemInfo := info.SystemVendor + ":" + info.ProductName
		add("system_info", systemInfo, 50)
	}

	// 内存大小（低权重）
	if info.MemorySize > 0 {
		add("memory_size", fmt.Sprintf("%d", info.MemorySize), 40)
	}

	// MAC地址（最低权重）
	if len(info.MACAddresses) > 0 {
		// 使用第一个MAC地址
		add("mac_address", info.MACAddresses[0], 30)
	}

	// B1: 网卡 PCI 地址（中等权重，比 MAC 更稳定）
	if len(info.NICPCIAddresses) > 0 {
		sum := sha256.Sum256([]byte(strings.Join(info.NICPCIAddresses, ",")))
		add("nic_pci", fmt.Sprintf("%x", sum[:16]), 65)
	}

	// B1: USB 控制器（低权重，作为辅助特征）
	if len(info.USBControllers) > 0 {
		sum := sha256.Sum256([]byte(strings.Join(info.USBControllers, ",")))
		add("usb_controllers", fmt.Sprintf("%x", sum[:16]), 50)
	}

	// 软指纹（低-中权重）
	if info.MachineID != "" {
		add("machine_id", info.MachineID, 60)
	}
	if info.Hostname != "" {
		add("hostname", info.Hostname, 20)
	}

	return weights
}

// ProtectedIDWithHardware 基于硬件指纹的保护ID
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

// 辅助函数

func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func normalizeOneLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// 将多行内容压缩到一行，避免输出中出现换行造成不稳定
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func uniqStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	var last string
	for i, v := range in {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}

func getPartitionUUID(device string) string {
	// 尝试通过blkid获取UUID（如果可用）
	if strings.HasPrefix(device, "/dev/") {
		// 检查是否有对应的UUID文件
		diskByUUID := "/dev/disk/by-uuid"
		if entries, err := os.ReadDir(diskByUUID); err == nil {
			for _, entry := range entries {
				if linkPath, err := os.Readlink(filepath.Join(diskByUUID, entry.Name())); err == nil {
					if absPath, err := filepath.Abs(filepath.Join(diskByUUID, linkPath)); err == nil {
						if absDevice, err := filepath.Abs(device); err == nil {
							if absPath == absDevice {
								return entry.Name()
							}
						}
					}
				}
			}
		}
	}
	return ""
}

func getDiskSerials() []string {
	var serials []string

	// 遍历所有块设备
	blockDevPath := "/sys/block"
	if entries, err := os.ReadDir(blockDevPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), "loop") &&
				!strings.HasPrefix(entry.Name(), "ram") {
				// 尝试读取序列号
				serialPath := filepath.Join(blockDevPath, entry.Name(), "device", "serial")
				if serial, err := readFileString(serialPath); err == nil && serial != "" {
					serials = append(serials, serial)
				}
			}
		}
	}

	// 排序以确保一致性
	sort.Strings(serials)
	return serials
}

func getNVMeSerials() []string {
	var serials []string
	nvmePath := "/sys/class/nvme"
	entries, err := os.ReadDir(nvmePath)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		serialPath := filepath.Join(nvmePath, entry.Name(), "serial")
		if serial, err := readFileString(serialPath); err == nil && serial != "" {
			serials = append(serials, serial)
		}
	}
	sort.Strings(serials)
	return serials
}

func getNetworkInterfaces() ([]string, error) {
	var addresses []string

	// 读取网络接口信息
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "lo" { // 跳过回环接口
				macPath := fmt.Sprintf("/sys/class/net/%s/address", entry.Name())
				if mac, err := readFileString(macPath); err == nil && mac != "" && mac != "00:00:00:00:00:00" {
					addresses = append(addresses, mac)
				}
			}
		}
	}

	sort.Strings(addresses)
	return addresses, nil
}

// ClearHardwareCache 清除硬件信息缓存
func ClearHardwareCache() {
	hardwareCacheMu.Lock()
	defer hardwareCacheMu.Unlock()

	cachedHardware = nil
	hardwareCacheTime = time.Time{}
}

// getNICPCIAddresses 获取网卡 PCI 地址
//
// 用途说明：
//   - 网卡 PCI 地址是硬件拓扑的一部分，比 MAC 地址更稳定
//   - 在物理机上通常不会变化，除非更换网卡或主板
//   - 在虚拟机/容器中可能不可用或为虚拟地址
func getNICPCIAddresses(info *linuxHardwareInfo) {
	netPath := "/sys/class/net"
	entries, err := os.ReadDir(netPath)
	if err != nil {
		return
	}

	var pciAddrs []string
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		// 读取设备的 PCI 地址
		devicePath := filepath.Join(netPath, name, "device")
		linkTarget, err := os.Readlink(devicePath)
		if err != nil {
			continue
		}

		// 提取 PCI 地址（格式如 0000:00:1f.6）
		pciAddr := filepath.Base(linkTarget)
		if pciAddr != "" && strings.Contains(pciAddr, ":") {
			pciAddrs = append(pciAddrs, pciAddr)
		}
	}

	if len(pciAddrs) > 0 {
		sort.Strings(pciAddrs)
		info.NICPCIAddresses = uniqStrings(pciAddrs)
	}
}

// getUSBControllers 获取 USB 控制器信息
//
// 用途说明：
//   - USB 控制器的 Vendor:Product ID 是硬件特征
//   - 在物理机上通常稳定，除非更换主板
//   - 权重较低，作为辅助特征
func getUSBControllers(info *linuxHardwareInfo) {
	usbPath := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(usbPath)
	if err != nil {
		return
	}

	var controllers []string
	for _, entry := range entries {
		name := entry.Name()
		// USB 控制器通常是 usb1, usb2 等，或者根 hub 设备
		if !strings.HasPrefix(name, "usb") {
			continue
		}

		devicePath := filepath.Join(usbPath, name)
		vendorPath := filepath.Join(devicePath, "idVendor")
		productPath := filepath.Join(devicePath, "idProduct")

		vendor, vendorErr := readFileString(vendorPath)
		product, productErr := readFileString(productPath)

		if vendorErr == nil && productErr == nil && vendor != "" && product != "" {
			controllers = append(controllers, vendor+":"+product)
		}
	}

	if len(controllers) > 0 {
		sort.Strings(controllers)
		info.USBControllers = uniqStrings(controllers)
	}
}
