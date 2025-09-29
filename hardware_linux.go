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

// HardwareWeight 硬件信息权重
type HardwareWeight struct {
	Name   string
	Value  string
	Weight int
}

// linuxHardwareInfo Linux平台简化硬件信息
type linuxHardwareInfo struct {
	ProductUUID       string   `json:"product_uuid,omitempty"`
	BoardSerial       string   `json:"board_serial,omitempty"`
	ProductSerial     string   `json:"product_serial,omitempty"`
	SystemVendor      string   `json:"system_vendor,omitempty"`
	ProductName       string   `json:"product_name,omitempty"`
	BoardVendor       string   `json:"board_vendor,omitempty"`
	RootPartitionUUID string   `json:"root_partition_uuid,omitempty"`
	DiskSerials       []string `json:"disk_serials,omitempty"`
	CPUSignature      string   `json:"cpu_signature,omitempty"`
	CPUCores          int      `json:"cpu_cores,omitempty"`
	MACAddresses      []string `json:"mac_addresses,omitempty"`
	MemorySize        uint64   `json:"memory_size,omitempty"`
	PCIDevices        []string `json:"pci_devices,omitempty"`
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

	cachedHardware = info
	hardwareCacheTime = time.Now()
	return info, nil
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
	}

	for file, field := range dmiFields {
		if data, err := readFileString(filepath.Join(dmiBasePath, file)); err == nil {
			*field = strings.TrimSpace(data)
		}
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
}

// getCPUInfo 获取CPU信息
func getCPUInfo(info *linuxHardwareInfo) {
	if cpuinfo, err := readFileString("/proc/cpuinfo"); err == nil {
		lines := strings.Split(cpuinfo, "\n")
		coreCount := 0
		var signatures []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "processor") {
				coreCount++
			} else if strings.HasPrefix(line, "cpu family") ||
				strings.HasPrefix(line, "model") ||
				strings.HasPrefix(line, "stepping") ||
				strings.HasPrefix(line, "microcode") {
				if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
					signatures = append(signatures, strings.TrimSpace(parts[1]))
				}
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
			if entry.IsDir() {
				// 读取设备和厂商ID
				vendorPath := filepath.Join(pciPath, entry.Name(), "vendor")
				devicePath := filepath.Join(pciPath, entry.Name(), "device")

				vendor, vendorErr := readFileString(vendorPath)
				device, deviceErr := readFileString(devicePath)

				if vendorErr == nil && deviceErr == nil {
					devices = append(devices, strings.TrimSpace(vendor)+":"+strings.TrimSpace(device))
				}
			}
		}
		if len(devices) > 0 {
			sort.Strings(devices) // 确保顺序一致
			info.PCIDevices = devices
		}
	}
}

// GetHardwareFingerprint 生成硬件指纹
func GetHardwareFingerprint() (string, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return "", err
	}

	// 收集所有可用的硬件标识符并按权重排序
	weights := collectHardwareWeights(info)

	if len(weights) == 0 {
		return "", fmt.Errorf("no hardware identifiers available")
	}

	// 按权重排序
	sort.Slice(weights, func(i, j int) bool {
		return weights[i].Weight > weights[j].Weight
	})

	// 选择权重最高的标识符进行组合
	var components []string
	totalWeight := 0

	for _, w := range weights {
		if w.Value != "" {
			components = append(components, fmt.Sprintf("%s:%s", w.Name, w.Value))
			totalWeight += w.Weight
			// 如果权重足够高，就可以停止添加更多组件
			if totalWeight >= 200 {
				break
			}
		}
	}

	if len(components) == 0 {
		return "", fmt.Errorf("no valid hardware identifiers found")
	}

	// 生成最终指纹
	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash), nil
}

// collectHardwareWeights 收集硬件权重信息
func collectHardwareWeights(info *linuxHardwareInfo) []HardwareWeight {
	var weights []HardwareWeight

	// DMI信息（最高权重）
	if info.ProductUUID != "" && info.ProductUUID != "00000000-0000-0000-0000-000000000000" {
		weights = append(weights, HardwareWeight{"product_uuid", info.ProductUUID, 100})
	}
	if info.BoardSerial != "" && info.BoardSerial != "None" && info.BoardSerial != "To be filled by O.E.M." {
		weights = append(weights, HardwareWeight{"board_serial", info.BoardSerial, 90})
	}
	if info.ProductSerial != "" && info.ProductSerial != "None" && info.ProductSerial != "To be filled by O.E.M." {
		weights = append(weights, HardwareWeight{"product_serial", info.ProductSerial, 85})
	}

	// 存储信息（高权重）
	if info.RootPartitionUUID != "" {
		weights = append(weights, HardwareWeight{"root_uuid", info.RootPartitionUUID, 80})
	}
	if len(info.DiskSerials) > 0 {
		// 使用第一个磁盘序列号
		weights = append(weights, HardwareWeight{"disk_serial", info.DiskSerials[0], 75})
	}

	// CPU信息（中等权重）
	if info.CPUSignature != "" {
		weights = append(weights, HardwareWeight{"cpu_signature", info.CPUSignature, 60})
	}

	// 系统信息（中等权重）
	if info.SystemVendor != "" && info.ProductName != "" {
		systemInfo := info.SystemVendor + ":" + info.ProductName
		weights = append(weights, HardwareWeight{"system_info", systemInfo, 50})
	}

	// 内存大小（低权重）
	if info.MemorySize > 0 {
		weights = append(weights, HardwareWeight{"memory_size", fmt.Sprintf("%d", info.MemorySize), 40})
	}

	// MAC地址（最低权重）
	if len(info.MACAddresses) > 0 {
		// 使用第一个MAC地址
		weights = append(weights, HardwareWeight{"mac_address", info.MACAddresses[0], 30})
	}

	return weights
}

// ProtectedIDWithHardware 基于硬件指纹的保护ID
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

// 辅助函数

func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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
