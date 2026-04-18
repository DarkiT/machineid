package machineid

// IDSource 描述当前 ID() 结果最终采用的来源。
type IDSource string

const (
	IDSourceUnknown         IDSource = "unknown"
	IDSourceMachineID       IDSource = "machine_id"
	IDSourceHostHardware    IDSource = "host_hardware"
	IDSourceContainerID     IDSource = "container_id"
	IDSourceContainerScoped IDSource = "container_scoped"
)

// IDInspection 描述当前进程调用 ID() 时会走到哪条来源链路。
type IDInspection struct {
	ID                       string     `json:"id"`
	Source                   IDSource   `json:"source"`
	IsContainer              bool       `json:"is_container"`
	ContainerID              string     `json:"container_id,omitempty"`
	HostHardwareAvailable    bool       `json:"host_hardware_available,omitempty"`
	ContainerScopedAvailable bool       `json:"container_scoped_available,omitempty"`
	FallbackChain            []IDSource `json:"fallback_chain,omitempty"`
}

// InspectID 返回当前 ID() 的来源诊断信息。
func InspectID() (*IDInspection, error) {
	return inspectID()
}
