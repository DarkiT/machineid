package machineid

// HardwareWeight 硬件信息权重。
//
// 该类型用于在各平台按权重选择硬件指纹组件。
// 必须放在无 build tag 的文件中，避免 Windows / Linux / macOS 各自定义导致的类型缺失。
type HardwareWeight struct {
	Name   string
	Value  string
	Weight int
}

