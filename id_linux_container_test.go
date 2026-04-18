//go:build linux
// +build linux

package machineid

import "testing"

func stubContainerHostMachineIDProvider(t *testing.T, fn func() string) {
	t.Helper()
	orig := hostHardwareMachineIDProvider
	hostHardwareMachineIDProvider = fn
	t.Cleanup(func() { hostHardwareMachineIDProvider = orig })
}

func stubContainerScopedMachineIDProvider(t *testing.T, fn func(string) string) {
	t.Helper()
	orig := containerScopedMachineIDProvider
	containerScopedMachineIDProvider = fn
	t.Cleanup(func() { containerScopedMachineIDProvider = orig })
}

func TestResolvePreferredMachineIDPrefersHostHardware(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "host-hw-id" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "scoped-" + baseID })

	got, source := resolvePreferredMachineID("machine-123", "container-xyz", true)
	if got != "HOST-HW-ID" || source != IDSourceHostHardware {
		t.Fatalf("expected host hardware ID first, got %q (%s)", got, source)
	}
}

func TestResolvePreferredMachineIDFallsBackToContainerID(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "scoped-" + baseID })

	got, source := resolvePreferredMachineID("machine-123", "container-xyz", true)
	if got != "CONTAINER-XYZ" || source != IDSourceContainerID {
		t.Fatalf("expected container ID fallback, got %q (%s)", got, source)
	}
}

func TestResolvePreferredMachineIDFallsBackToScopedID(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "scoped-" + baseID })

	got, source := resolvePreferredMachineID("machine-123", "", true)
	if got != "SCOPED-MACHINE-123" || source != IDSourceContainerScoped {
		t.Fatalf("expected scoped ID fallback, got %q (%s)", got, source)
	}
}

func TestResolvePreferredMachineIDFallsBackToBaseIDInContainer(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "" })

	got, source := resolvePreferredMachineID("machine-123", "", true)
	if got != "MACHINE-123" || source != IDSourceMachineID {
		t.Fatalf("expected base ID fallback, got %q (%s)", got, source)
	}
}

func TestResolvePreferredMachineIDFallsBackToBaseIDOnHost(t *testing.T) {
	stubContainerHostMachineIDProvider(t, func() string { return "" })
	stubContainerScopedMachineIDProvider(t, func(baseID string) string { return "scoped-" + baseID })

	got, source := resolvePreferredMachineID("machine-123", "container-xyz", false)
	if got != "MACHINE-123" || source != IDSourceMachineID {
		t.Fatalf("expected host fallback to base ID, got %q (%s)", got, source)
	}
}

func TestCollectHostHardwareWeightsRequiresStrongSignals(t *testing.T) {
	weights, strongCount := collectHostHardwareWeights(&linuxHardwareInfo{
		SystemVendor: "Tencent Cloud",
		ProductName:  "CVM",
		BIOSVersion:  "seabios",
		CPUSignature: "vendor=amd|family=26",
	})

	if strongCount != 0 {
		t.Fatalf("expected no strong signals, got %d", strongCount)
	}
	if len(weights) == 0 {
		t.Fatalf("expected auxiliary weights to be collected")
	}
}

func TestCollectHostHardwareWeightsUsesProductUUID(t *testing.T) {
	weights, strongCount := collectHostHardwareWeights(&linuxHardwareInfo{
		ProductUUID:  "2dde0871-5840-43e1-8661-2318a5f3b9a9",
		SystemVendor: "Tencent Cloud",
		ProductName:  "CVM",
		BIOSVersion:  "seabios",
	})

	if strongCount == 0 {
		t.Fatalf("expected product UUID to count as strong signal")
	}
	if len(weights) == 0 {
		t.Fatalf("expected non-empty weights")
	}
}
