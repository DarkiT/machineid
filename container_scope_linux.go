//go:build linux
// +build linux

package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

func defaultContainerHints() []string {
	hints := []string{
		fileDigest("/proc/self/cgroup"),
		fileDigest("/proc/self/mountinfo"),
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		hints = append(hints, hostname)
	}
	return hints
}

func fileDigest(p string) string {
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// canAccessHostHardware 判断当前进程是否能访问“宿主机级”硬件特征。
//
// 在容器场景下，许多硬件/固件信息要么被隔离，要么被显式屏蔽；当能读取到这些信息时，
// 通常意味着容器拥有较高权限（例如特权容器、挂载了 /sys、或处于 host PID/NS 等配置）。
//
// 检测点：
// 1) /sys/class/dmi/id/product_uuid 是否可读（DMI/SMBIOS 级别的主机信息）；
// 2) /sys/bus/pci/devices/ 是否可访问（PCI 设备枚举，通常反映宿主机硬件视图）。
func canAccessHostHardware() bool {
	// 1) DMI product UUID
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil && len(data) > 0 {
		return true
	}

	// 2) PCI devices directory access
	if entries, err := os.ReadDir("/sys/bus/pci/devices"); err == nil {
		// 只要能列出目录即可认为具备一定的硬件可见性；不强制要求有条目。
		_ = entries
		return true
	}

	return false
}

// getContainerPersistentFeatures 收集可用于“容器级绑定”的稳定特征。
//
// 目标：在不依赖宿主机硬件信息的前提下，尽可能拿到跨进程/跨重启相对稳定的信号。
// 这些信号用于做容器 Scoped ID 的派生输入（作为 hints）。
//
// 返回值：去空、去重后的特征列表；格式使用 "key:value" 便于后续扩展与调试。
func getContainerPersistentFeatures() []string {
	features := make([]string, 0, 4)
	seen := make(map[string]struct{}, 8)
	add := func(key, value string) {
		if value == "" {
			return
		}
		item := key + ":" + value
		if _, ok := seen[item]; ok {
			return
		}
		seen[item] = struct{}{}
		features = append(features, item)
	}

	// cgroup namespace inode
	add("ns_cgroup", namespaceID("/proc/self/ns/cgroup"))
	// mount namespace inode
	add("ns_mnt", namespaceID("/proc/self/ns/mnt"))

	return features
}

// getContainerPersistentFeaturesWithConfig 在 getContainerPersistentFeatures 的基础上，
// 额外收集与业务配置有关的“持久卷特征”（如果配置了 PersistentVolume）。
//
// 说明：
// - 仅当 config.PersistentVolume 非空时启用。
// - 不读取/写入持久卷中的业务内容，只使用路径解析与文件系统元信息作为特征。
func getContainerPersistentFeaturesWithConfig(config *ContainerBindingConfig) []string {
	features := getContainerPersistentFeatures()
	seen := make(map[string]struct{}, len(features)+4)
	for _, f := range features {
		if f == "" {
			continue
		}
		seen[f] = struct{}{}
	}
	add := func(key, value string) {
		if value == "" {
			return
		}
		item := key + ":" + value
		if _, ok := seen[item]; ok {
			return
		}
		seen[item] = struct{}{}
		features = append(features, item)
	}

	if config == nil || config.PersistentVolume == "" {
		return features
	}

	p := config.PersistentVolume

	// 路径规范化：使用 EvalSymlinks 获取实际挂载点路径（如果存在）。
	if real, err := filepath.EvalSymlinks(p); err == nil && real != "" {
		add("pv_realpath", real)
	} else {
		add("pv_path", p)
	}

	// 文件系统元信息：device/inode 在同一挂载/同一卷上相对稳定。
	if fi, err := os.Stat(p); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			add("pv_dev", strconv.FormatUint(uint64(st.Dev), 10))
			add("pv_ino", strconv.FormatUint(uint64(st.Ino), 10))
		}
	}

	return features
}

func namespaceID(p string) string {
	// /proc/self/ns/* 通常是形如 "mnt:[4026531840]" 的符号链接。
	if target, err := os.Readlink(p); err == nil {
		return target
	}
	return ""
}

// selectBindingStrategy 根据配置与运行环境选择绑定策略。
//
// 返回：
// - "host_hardware"：尽量使用宿主机硬件信息派生（稳定但需要权限）。
// - "container_scoped"：只使用容器自身可见信息派生（更隔离、可移植）。
// - "hybrid"：两者结合（优先宿主机，必要时引入容器稳定特征或作为降级）。
func selectBindingStrategy(config *ContainerBindingConfig) string {
	// 兜底：配置为空时按默认自动策略。
	if config == nil {
		config = DefaultContainerBindingConfig()
	}

	hostOK := canAccessHostHardware()
	pvConfigured := config != nil && config.PersistentVolume != ""

	switch config.Mode {
	case ContainerBindingHost:
		return "host_hardware"
	case ContainerBindingContainer:
		return "container_scoped"
	case ContainerBindingAuto:
		// 自动模式：优先遵从偏好；无法满足时看是否允许降级。
		if config.PreferHostHardware {
			if hostOK {
				// 有宿主机硬件可用：如果同时配置了持久卷，则可将其作为额外稳定输入（hybrid）。
				// 否则直接走宿主机绑定，避免“混合”导致绑定语义变复杂。
				if pvConfigured {
					return "hybrid"
				}
				return "host_hardware"
			}
			if config.FallbackToContainer {
				return "container_scoped"
			}
			// 不允许降级时仍返回宿主机策略，让上层决定报错/空结果。
			return "host_hardware"
		}

		// 不偏好宿主机：能用就混合，否则容器级。
		if hostOK {
			if pvConfigured {
				return "hybrid"
			}
			return "host_hardware"
		}
		return "container_scoped"
	default:
		// 理论上 Validate 会拦住，但这里保持健壮。
		if hostOK {
			return "hybrid"
		}
		return "container_scoped"
	}
}
