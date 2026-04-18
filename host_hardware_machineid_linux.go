//go:build linux
// +build linux

package machineid

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// getPreferredHardwareMachineID 尝试提取“宿主/VM 级”硬件机器码。
//
// 设计目标：
//   - 仅使用相对接近硬件/固件的特征，不掺入 containerID、hostname、machine-id、MAC 这类软/容器态信号；
//   - 至少拿到一个强标识（如 DMI UUID / Serial / TPM / 磁盘序列号），否则宁可返回空并回退现有 machine-id/container 逻辑；
//   - 输出为归一化哈希，避免直接暴露原始 DMI/Serial。
func getPreferredHardwareMachineID() string {
	status, err := getPreferredHardwareMachineIDStatus()
	if err != nil || status == nil || !status.Stable || status.Value == "" {
		return ""
	}
	return status.Value
}

func getPreferredHardwareMachineIDStatus() (*FingerprintStatus, error) {
	info, err := GetHardwareInfo()
	if err != nil {
		return nil, err
	}

	weights, strongCount := collectHostHardwareWeights(info)
	if len(weights) == 0 {
		return nil, fmt.Errorf("no host hardware identifiers available")
	}

	sort.Slice(weights, func(i, j int) bool {
		return weights[i].Weight > weights[j].Weight
	})

	components := make([]string, 0, len(weights))
	totalWeight := 0
	for _, w := range weights {
		if w.Value == "" {
			continue
		}
		components = append(components, fmt.Sprintf("%s:%s", w.Name, w.Value))
		totalWeight += w.Weight
		if totalWeight >= 220 {
			break
		}
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("no valid host hardware identifiers found")
	}
	if strongCount == 0 {
		return nil, fmt.Errorf("no strong host hardware identifiers available")
	}

	sum := sha256.Sum256([]byte(strings.Join(components, "|")))
	return &FingerprintStatus{
		Value:  fmt.Sprintf("%x", sum),
		Stable: totalWeight >= 140,
	}, nil
}

func collectHostHardwareWeights(info *linuxHardwareInfo) ([]HardwareWeight, int) {
	if info == nil {
		return nil, 0
	}

	var (
		weights     []HardwareWeight
		strongCount int
	)
	seen := make(map[string]struct{})
	add := func(name, value string, weight int, strong bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := name + ":" + value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		weights = append(weights, HardwareWeight{Name: name, Value: value, Weight: weight})
		if strong {
			strongCount++
		}
	}
	addDigest := func(name string, values []string, weight int, strong bool) {
		if len(values) == 0 {
			return
		}
		sum := sha256.Sum256([]byte(strings.Join(values, ",")))
		add(name, fmt.Sprintf("%x", sum[:16]), weight, strong)
	}

	// 强标识：优先使用 DMI UUID / Serial / 盘序列号 / TPM / UEFI 等宿主/固件级信号。
	if info.ProductUUID != "" && info.ProductUUID != "00000000-0000-0000-0000-000000000000" {
		add("product_uuid", info.ProductUUID, 100, true)
	}
	if info.SystemUUID != "" && info.SystemUUID != info.ProductUUID && info.SystemUUID != "00000000-0000-0000-0000-000000000000" {
		add("system_uuid", info.SystemUUID, 98, true)
	}
	if info.BoardSerial != "" && info.BoardSerial != "None" && info.BoardSerial != "To be filled by O.E.M." {
		add("board_serial", info.BoardSerial, 95, true)
	}
	if info.ProductSerial != "" && info.ProductSerial != "None" && info.ProductSerial != "To be filled by O.E.M." {
		add("product_serial", info.ProductSerial, 92, true)
	}
	if info.ChassisSerial != "" && info.ChassisSerial != "None" && info.ChassisSerial != "To be filled by O.E.M." {
		add("chassis_serial", info.ChassisSerial, 90, true)
	}
	if info.TPMVersion != "" {
		add("tpm", info.TPMVersion, 95, true)
	}
	addDigest("uefi_vars", info.UEFIVariables, 88, true)
	if len(info.DiskSerials) > 0 {
		add("disk_serial", info.DiskSerials[0], 88, true)
	}
	if len(info.NVMeSerials) > 0 {
		add("nvme_serial", info.NVMeSerials[0], 90, true)
	}
	if info.CPUIdentifier != "" {
		add("cpu_id", info.CPUIdentifier, 82, true)
	}

	// 辅助标识：增强区分度，但本身不足以单独当“硬件机器码”。
	addDigest("acpi_tables", info.ACPITables, 70, false)
	addDigest("pci_devices", info.PCIDevices, 68, false)
	addDigest("nic_pci", info.NICPCIAddresses, 66, false)
	addDigest("usb_controllers", info.USBControllers, 40, false)
	if info.CPUSignature != "" {
		add("cpu_signature", info.CPUSignature, 48, false)
	}
	if info.SystemVendor != "" || info.ProductName != "" {
		add("system_info", info.SystemVendor+":"+info.ProductName, 36, false)
	}
	if info.BIOSVersion != "" && info.BIOSVersion != "None" {
		add("bios_version", info.BIOSVersion, 24, false)
	}

	return weights, strongCount
}
