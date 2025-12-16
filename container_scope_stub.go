//go:build !linux

package machineid

// 非 Linux 平台不支持容器绑定策略细分，提供最小 stub 保持编译通过。
func selectBindingStrategy(_ *ContainerBindingConfig) string {
	// 返回容器内更安全的默认策略，保持与 Validate 一致的兜底。
	return "container_scoped"
}

// 非 Linux 平台不做容器持久特征提取，返回空切片。
func getContainerPersistentFeaturesWithConfig(_ *ContainerBindingConfig) []string {
	return nil
}
