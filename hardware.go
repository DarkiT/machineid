package machineid

// HardwareInfo 是跨平台统一的“硬件信息视图”接口。
//
// 设计目标：
//  1. 跨平台一致性：不同平台（Linux/Windows/macOS/其他）应尽量输出同一语义的字段。
//     - “同一语义”指：同一个方法在各平台返回的应是同类硬件标识（例如 ProductUUID 都是主机级 UUID）。
//  2. 稳定性优先：硬件特征优先于软件特征。硬件特征不应随重装系统/改主机名而变化。
//  3. 向后兼容：该接口是新增能力，不要求改动现有结构体字段与对外 API。
//  4. 最小依赖：实现侧应尽量使用操作系统原生信息源（sysfs/registry/ioreg 等），避免引入额外依赖。
//  5. 失败可降级：信息源缺失（例如容器、权限不足、文件不存在）时，不应导致整体失败；返回空值即可。
//
// 注意：
//   - DiskSerials 返回应尽量排序并去重，以保证指纹可重复。
//   - Fingerprint 返回的指纹值应只依赖稳定特征；IsStable 用于标识“足够稳定”的硬件组合是否可得。
type HardwareInfo interface {
	// ProductUUID 返回主机级产品 UUID（例如 SMBIOS/DMI UUID）。
	ProductUUID() string

	// BoardSerial 返回主板序列号（若可用）。
	BoardSerial() string

	// CPUSignature 返回 CPU 的可重复签名（不要求是真正的序列号；可为族/型号/步进组合）。
	CPUSignature() string

	// DiskSerials 返回磁盘序列号列表（尽量只包含物理盘，且保持顺序稳定）。
	DiskSerials() []string

	// TPMSupported 返回是否检测到 TPM（或等价硬件安全模块）可用。
	TPMSupported() bool

	// Fingerprint 返回当前平台的硬件指纹（通常为 hash），以及可能的错误。
	Fingerprint() (string, error)

	// IsStable 返回当前硬件信息是否“稳定到足以用于绑定”。
	IsStable() bool
}
