//go:build linux
// +build linux

package machineid

func inspectID() (*IDInspection, error) {
	containerID := normalizeMachineIDValue(containerIDProvider())
	isContainer := containerEnvDetector()

	baseID, err := readLinuxBaseMachineID()
	if err != nil {
		return nil, err
	}

	hostID := normalizeMachineIDValue(hostHardwareMachineIDProvider())
	scopedID := ""
	if isContainer {
		scopedID = normalizeMachineIDValue(containerScopedMachineIDProvider(baseID))
	}

	resolvedID, source := resolvePreferredMachineIDCandidates(baseID, hostID, containerID, scopedID, isContainer)
	if resolvedID == "" {
		resolvedID = baseID
		if source == IDSourceUnknown {
			source = IDSourceMachineID
		}
	}

	inspection := &IDInspection{
		ID:                       resolvedID,
		Source:                   source,
		IsContainer:              isContainer,
		ContainerID:              containerID,
		HostHardwareAvailable:    hostID != "",
		ContainerScopedAvailable: scopedID != "",
		FallbackChain:            []IDSource{IDSourceHostHardware, IDSourceContainerID, IDSourceContainerScoped, IDSourceMachineID},
	}
	if !isContainer {
		inspection.ContainerID = ""
		inspection.ContainerScopedAvailable = false
		inspection.FallbackChain = []IDSource{IDSourceHostHardware, IDSourceMachineID}
	}

	return inspection, nil
}
