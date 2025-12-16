package machineid

import (
	"errors"
	"fmt"
)

// ContainerBindingMode 表示容器绑定配置模式。
//
// 该配置用于在“宿主机级绑定”（更稳定、更贴近真实硬件）与“容器级绑定”（更适合容器镜像复制/隔离）
// 之间做选择。业务侧可通过配置控制机器码派生逻辑在容器环境下的行为。
type ContainerBindingMode int

const (
	// ContainerBindingAuto 表示自动检测：由运行时根据环境与可用硬件信息选择绑定级别。
	ContainerBindingAuto ContainerBindingMode = iota
	// ContainerBindingHost 表示强制宿主机：优先/强制使用宿主机硬件信息进行绑定。
	ContainerBindingHost
	// ContainerBindingContainer 表示强制容器级：使用容器环境内可用信息派生容器级标识。
	ContainerBindingContainer
)

func (m ContainerBindingMode) String() string {
	switch m {
	case ContainerBindingAuto:
		return "auto"
	case ContainerBindingHost:
		return "host"
	case ContainerBindingContainer:
		return "container"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// ContainerBindingConfig 描述容器绑定的策略配置。
//
// 说明：
//   - Mode 用于指定绑定模式：自动/强制宿主机/强制容器级。
//   - PreferHostHardware 用于在自动模式下表达偏好：尽可能使用宿主机硬件作为绑定依据。
//   - FallbackToContainer 用于在宿主机硬件不可用/不稳定时是否允许降级到容器级。
//   - PersistentVolume 用于指向持久卷路径：当采用容器级标识时，可用来存储/读取稳定标识，
//     以避免每次容器重建都改变绑定结果。
type ContainerBindingConfig struct {
	Mode                ContainerBindingMode
	PreferHostHardware  bool
	FallbackToContainer bool
	PersistentVolume    string
}

// DefaultContainerBindingConfig 返回默认容器绑定配置。
//
// 默认策略：
// - Mode: 自动检测
// - PreferHostHardware: true（优先使用宿主机硬件）
// - FallbackToContainer: true（宿主机硬件不可用时允许降级）
// - PersistentVolume: 空（由业务自行配置持久卷路径）
func DefaultContainerBindingConfig() *ContainerBindingConfig {
	return &ContainerBindingConfig{
		Mode:                ContainerBindingAuto,
		PreferHostHardware:  true,
		FallbackToContainer: true,
		PersistentVolume:    "",
	}
}

var (
	errContainerBindingConfigNil            = errors.New("machineid: container binding config is nil")
	errContainerBindingPersistentVolumeMode = errors.New("machineid: persistent volume only applies to container binding")
)

// Validate 校验配置是否自洽。
//
// 该方法只做“静态配置”层面的校验（例如字段组合是否合理），不做路径存在性/权限等运行时校验，
// 以避免在库初始化阶段引入文件系统副作用。
func (c *ContainerBindingConfig) Validate() error {
	if c == nil {
		return errContainerBindingConfigNil
	}
	if c.Mode < ContainerBindingAuto || c.Mode > ContainerBindingContainer {
		return fmt.Errorf("machineid: invalid container binding mode: %d", int(c.Mode))
	}

	// 强制容器级时，PreferHostHardware 不应为 true（否则语义冲突）。
	if c.Mode == ContainerBindingContainer && c.PreferHostHardware {
		return fmt.Errorf("machineid: PreferHostHardware conflicts with mode %s", c.Mode.String())
	}

	// 强制宿主机时，FallbackToContainer 为 true 会造成“强制”语义不明确：建议显式关闭。
	if c.Mode == ContainerBindingHost && c.FallbackToContainer {
		return fmt.Errorf("machineid: FallbackToContainer conflicts with mode %s", c.Mode.String())
	}

	// 自动模式允许偏好与降级同时开启；如两者都关闭，则等价于“尽量宿主机且不降级”，仍然合法。

	// PersistentVolume 仅对“容器级绑定”有意义；在非容器级强制模式下配置该字段通常是误用。
	if c.PersistentVolume != "" && c.Mode != ContainerBindingContainer {
		// 自动模式下可能最终选择容器级，但该决定发生在运行时；为了减少误用，
		// 这里要求业务在需要持久卷时明确使用容器级模式。
		return errContainerBindingPersistentVolumeMode
	}

	return nil
}
