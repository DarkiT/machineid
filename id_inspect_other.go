//go:build !linux
// +build !linux

package machineid

func inspectID() (*IDInspection, error) {
	id, err := ID()
	if err != nil {
		return nil, err
	}

	containerID := normalizeMachineIDValue(containerIDProvider())
	isContainer := IsContainer()
	source := IDSourceMachineID
	fallbackChain := []IDSource{IDSourceMachineID}

	if isContainer {
		fallbackChain = []IDSource{IDSourceContainerID, IDSourceContainerScoped, IDSourceMachineID}
		switch {
		case containerID != "" && id == containerID:
			source = IDSourceContainerID
		case containerID == "":
			source = IDSourceContainerScoped
		default:
			source = IDSourceUnknown
		}
	}

	return &IDInspection{
		ID:            id,
		Source:        source,
		IsContainer:   isContainer,
		ContainerID:   containerID,
		FallbackChain: fallbackChain,
	}, nil
}
