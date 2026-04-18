//go:build linux
// +build linux

package machineid

import "testing"

func TestInspectIDUsesHostHardwareOnHost(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "host-hw-id" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "scoped-" + baseID })

	origContainerEnvDetector := containerEnvDetector
	containerEnvDetector = func() bool { return false }
	t.Cleanup(func() { containerEnvDetector = origContainerEnvDetector })

	origContainerIDProvider := containerIDProvider
	containerIDProvider = func() string { return "" }
	t.Cleanup(func() { containerIDProvider = origContainerIDProvider })

	inspection, err := inspectID()
	if err != nil {
		t.Fatalf("inspectID: %v", err)
	}
	if inspection.Source != IDSourceHostHardware {
		t.Fatalf("expected host_hardware source, got %s", inspection.Source)
	}
	if inspection.IsContainer {
		t.Fatalf("expected host inspection, got container=true")
	}
}

func TestInspectIDContainerFallbackChain(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "scoped-" + baseID })

	origContainerEnvDetector := containerEnvDetector
	containerEnvDetector = func() bool { return true }
	t.Cleanup(func() { containerEnvDetector = origContainerEnvDetector })

	origContainerIDProvider := containerIDProvider
	containerIDProvider = func() string { return "container-xyz" }
	t.Cleanup(func() { containerIDProvider = origContainerIDProvider })

	inspection, err := inspectID()
	if err != nil {
		t.Fatalf("inspectID: %v", err)
	}
	if inspection.Source != IDSourceContainerID {
		t.Fatalf("expected container_id source, got %s", inspection.Source)
	}
	if !inspection.IsContainer {
		t.Fatalf("expected container inspection")
	}
	if len(inspection.FallbackChain) != 4 {
		t.Fatalf("expected 4-stage fallback chain, got %v", inspection.FallbackChain)
	}
}
