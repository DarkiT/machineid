package machineid

import (
	"fmt"
	"testing"
)

func TestContainerHintsIncludeK8sEnv(t *testing.T) {
	orig := allowK8sEnvHint
	t.Cleanup(func() { allowK8sEnvHint = orig })
	allowK8sEnvHint = func() bool { return true }

	t.Setenv("POD_UID", "pod-123")
	t.Setenv("POD_NAME", "demo-pod")
	t.Setenv("POD_NAMESPACE", "default")
	t.Setenv("NODE_NAME", "node-1")

	hints := collectContainerHints()
	if len(hints) == 0 {
		t.Fatalf("expected k8s hints")
	}
}

func TestProtectedIDResultUsesFingerprint(t *testing.T) {
	stubIDProvider(t, func() (string, error) {
		return "machine-123", nil
	})
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp-abc", Stable: true}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return nil, nil
	})

	result, err := ProtectedIDResult("app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != BindingModeFingerprint {
		t.Fatalf("expected fingerprint mode, got %s", result.Mode)
	}
	expected := protect("app/machine-123/fp-abc", "machine-123")
	if result.Hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", result.Hash, expected)
	}
}

func TestProtectedIDResultFallsBackToMAC(t *testing.T) {
	stubIDProvider(t, func() (string, error) {
		return "machine-123", nil
	})
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb:cc:dd:ee:ff", Stable: true}, nil
	})

	result, err := ProtectedIDResult("app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != BindingModeMAC {
		t.Fatalf("expected MAC mode, got %s", result.Mode)
	}
	expected := protect("app/aa:bb:cc:dd:ee:ff", "machine-123")
	if result.Hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", result.Hash, expected)
	}
}

func TestProtectedIDResultFallsBackToMachineID(t *testing.T) {
	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "00:00", Stable: false}, nil
	})

	result, err := ProtectedIDResult("app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != BindingModeMachineID {
		t.Fatalf("expected machine id mode, got %s", result.Mode)
	}
	expected := protect("app", "machine-123")
	if result.Hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", result.Hash, expected)
	}
	if result.MACError == nil {
		t.Fatalf("expected MAC error recorded")
	}
}

func TestProtectedIDWithMACResultRequiresStableMAC(t *testing.T) {
	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})

	_, err := ProtectedIDWithMACResult("app")
	if err == nil {
		t.Fatalf("expected error when MAC unstable")
	}
}

func TestProtectedIDResultUsesCustomProviderWhenBuiltinsUnavailable(t *testing.T) {
	resetBindingProviders(t)
	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})
	RegisterBindingProvider("protected-custom", func(appID, machineID string) (string, bool, error) {
		return "custom-value", true, nil
	})

	result, err := ProtectedIDResult("app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != BindingModeCustom {
		t.Fatalf("expected custom mode, got %s", result.Mode)
	}
	if result.Provider != "protected-custom" {
		t.Fatalf("expected protected-custom provider, got %s", result.Provider)
	}
	expected := protect("app/machine-123/custom-value", "machine-123")
	if result.Hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", result.Hash, expected)
	}
	if result.MACError == nil {
		t.Fatalf("expected MAC error recorded before custom fallback")
	}
}

func TestUniqueIDResultUsesCustomProvider(t *testing.T) {
	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})
	RegisterBindingProvider("custom", func(appID, machineID string) (string, bool, error) {
		return "custom-value", true, nil
	})

	result, err := UniqueIDResult("app", &UniqueIDOptions{
		EnableContainer:       false,
		Mode:                  UniqueIDModeContainer,
		EnableCustomProviders: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != BindingModeCustom {
		t.Fatalf("expected custom mode, got %s", result.Mode)
	}
	if result.Provider != "custom" {
		t.Fatalf("expected custom provider, got %s", result.Provider)
	}
	expected := protect("app/machine-123/custom-value", "machine-123")
	if result.Hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", result.Hash, expected)
	}
}

func TestUniqueIDResultDisablesCustomProvider(t *testing.T) {
	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})
	RegisterBindingProvider("custom-disabled", func(appID, machineID string) (string, bool, error) {
		return "custom-value", true, nil
	})

	result, err := UniqueIDResult("app", &UniqueIDOptions{
		EnableContainer:       false,
		Mode:                  UniqueIDModeContainer,
		EnableCustomProviders: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != BindingModeMachineID {
		t.Fatalf("expected machine id mode, got %s", result.Mode)
	}
	expected := protect("app", "machine-123")
	if result.Hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", result.Hash, expected)
	}
}

func TestUniqueIDResultUsesContainerWhenAvailable(t *testing.T) {
	result, ok, err := uniqueIDFromContainer("app", "machine-123", "container_scoped", nil, "container-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected container binding to succeed; ok=false")
	}
	if result.Mode != BindingModeCustom {
		t.Fatalf("expected custom mode, got %s", result.Mode)
	}
	if result.Provider != "container_scoped" {
		t.Fatalf("expected container_scoped provider, got %s", result.Provider)
	}
}

func TestUniqueIDModeOverridesContainerConfig(t *testing.T) {
	cfg := &ContainerBindingConfig{
		Mode:                ContainerBindingHost,
		PreferHostHardware:  true,
		FallbackToContainer: false,
	}

	options := normalizeUniqueIDOptions(&UniqueIDOptions{
		EnableContainer: true,
		ContainerConfig: cfg,
		Mode:            UniqueIDModeContainer,
	})

	if options.ContainerConfig == nil {
		t.Fatalf("expected container config to be preserved")
	}
	if options.Mode != UniqueIDModeContainer {
		t.Fatalf("expected mode to be container")
	}
}

func TestProtectedIDFallbackChain(t *testing.T) {
	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb:cc:dd:ee:ff", Stable: true}, nil
	})

	hash, err := ProtectedID("app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := protect("app/aa:bb:cc:dd:ee:ff", "machine-123")
	if hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", hash, expected)
	}
}

func TestIDUsesCachedValue(t *testing.T) {
	ClearCache()
	calls := 0
	origMachineID := machineIDProvider
	origIDProvider := idProvider
	idProvider = ID
	t.Cleanup(func() { idProvider = origIDProvider })
	machineIDProvider = func() (string, error) {
		calls++
		return "machine-123", nil
	}
	t.Cleanup(func() { machineIDProvider = origMachineID })

	id1, err := ID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id2, err := ID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 != "MACHINE-123" || id2 != "MACHINE-123" {
		t.Fatalf("unexpected id values: %s %s", id1, id2)
	}
	if calls != 1 {
		t.Fatalf("expected cached ID, calls=%d", calls)
	}
}

func TestUniqueIDResultDoesNotMutateContainerConfig(t *testing.T) {
	cfg := &ContainerBindingConfig{
		Mode:                ContainerBindingHost,
		PreferHostHardware:  true,
		FallbackToContainer: false,
	}

	origIsContainer := containerEnvDetector
	containerEnvDetector = func() bool { return true }
	t.Cleanup(func() { containerEnvDetector = origIsContainer })
	origGetContainerID := containerIDProvider
	containerIDProvider = func() string { return "container-xyz" }
	t.Cleanup(func() { containerIDProvider = origGetContainerID })

	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp", Stable: false}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})

	_, _ = UniqueIDResult("app", &UniqueIDOptions{
		EnableContainer:       true,
		ContainerConfig:       cfg,
		Mode:                  UniqueIDModeContainer,
		EnableCustomProviders: false,
	})

	if cfg.Mode != ContainerBindingHost {
		t.Fatalf("expected container config mode to remain host, got %v", cfg.Mode)
	}
	if !cfg.PreferHostHardware {
		t.Fatalf("expected PreferHostHardware to remain true")
	}
	if cfg.FallbackToContainer {
		t.Fatalf("expected FallbackToContainer to remain false")
	}
}

func TestGetMACAddressRejectsUnstable(t *testing.T) {
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})

	if _, err := GetMACAddress(); err == nil {
		t.Fatalf("expected error for unstable MAC")
	}
}

func TestProtectedIDWithContainerAwarePreservesContainerMetadataWhenConfigNil(t *testing.T) {
	resetContainerHintProviders(t)
	origIsContainer := containerEnvDetector
	containerEnvDetector = func() bool { return true }
	t.Cleanup(func() { containerEnvDetector = origIsContainer })
	origGetContainerID := containerIDProvider
	containerIDProvider = func() string { return "container-xyz" }
	t.Cleanup(func() { containerIDProvider = origGetContainerID })

	stubIDProvider(t, func() (string, error) { return "machine-123", nil })
	stubFingerprint(t, func() (*FingerprintStatus, error) {
		return &FingerprintStatus{Value: "fp-container", Stable: true}, nil
	})
	stubMACResolver(t, func() (*MACInfo, error) {
		return nil, nil
	})

	result, err := ProtectedIDWithContainerAware("app", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ContainerMode != "none" {
		t.Fatalf("expected container mode none, got %s", result.ContainerMode)
	}
	if result.ContainerID != "container-xyz" {
		t.Fatalf("expected container id preserved, got %s", result.ContainerID)
	}
	if result.Mode != BindingModeFingerprint {
		t.Fatalf("expected fingerprint mode, got %s", result.Mode)
	}
}

func TestUnregisterBindingProviderRemovesProvider(t *testing.T) {
	resetBindingProviders(t)
	RegisterBindingProvider("disk", func(appID, machineID string) (string, bool, error) {
		return "disk-a", true, nil
	})
	RegisterBindingProvider("meta", func(appID, machineID string) (string, bool, error) {
		return "meta-a", true, nil
	})

	if !UnregisterBindingProvider("disk") {
		t.Fatalf("expected disk provider to be removed")
	}
	if UnregisterBindingProvider("disk") {
		t.Fatalf("expected duplicate unregister to report false")
	}

	providers := listBindingProviders()
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider left, got %d", len(providers))
	}
	if providers[0].name != "meta" {
		t.Fatalf("expected meta provider to remain, got %s", providers[0].name)
	}
}

func TestResetBindingProvidersClearsRegistry(t *testing.T) {
	resetBindingProviders(t)
	RegisterBindingProvider("disk", func(appID, machineID string) (string, bool, error) {
		return "disk-a", true, nil
	})
	RegisterBindingProvider("meta", func(appID, machineID string) (string, bool, error) {
		return "meta-a", true, nil
	})

	ResetBindingProviders()

	if providers := listBindingProviders(); len(providers) != 0 {
		t.Fatalf("expected provider registry empty, got %d", len(providers))
	}
}

func TestNamedContainerHintProviderLifecycle(t *testing.T) {
	resetContainerHintProviders(t)
	RegisterContainerHintProvider(func() []string { return []string{"anon-a"} })
	RegisterNamedContainerHintProvider("pod", func() []string { return []string{"pod-a"} })
	RegisterNamedContainerHintProvider("node", func() []string { return []string{"node-a"} })
	RegisterNamedContainerHintProvider("pod", func() []string { return []string{"pod-b"} })

	hints := collectContainerHints()
	if !containsString(hints, "anon-a") {
		t.Fatalf("expected anonymous hint provider output, got %v", hints)
	}
	if !containsString(hints, "pod-b") {
		t.Fatalf("expected named provider update output, got %v", hints)
	}
	if containsString(hints, "pod-a") {
		t.Fatalf("expected named provider to be replaced, got %v", hints)
	}
	if !containsString(hints, "node-a") {
		t.Fatalf("expected second named provider output, got %v", hints)
	}

	if !UnregisterContainerHintProvider("pod") {
		t.Fatalf("expected named container hint provider removal")
	}
	if UnregisterContainerHintProvider("pod") {
		t.Fatalf("expected duplicate named removal to report false")
	}

	hints = collectContainerHints()
	if containsString(hints, "pod-b") {
		t.Fatalf("expected pod hint removed, got %v", hints)
	}
	if !containsString(hints, "anon-a") || !containsString(hints, "node-a") {
		t.Fatalf("expected remaining providers preserved, got %v", hints)
	}
}

func TestResetContainerHintProvidersClearsAllRegistries(t *testing.T) {
	resetContainerHintProviders(t)
	RegisterContainerHintProvider(func() []string { return []string{"anon-a"} })
	RegisterNamedContainerHintProvider("pod", func() []string { return []string{"pod-a"} })

	ResetContainerHintProviders()

	hints := collectContainerHints()
	if containsString(hints, "anon-a") || containsString(hints, "pod-a") {
		t.Fatalf("expected custom container hints reset, got %v", hints)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestContainerHintCombineModeLifecycle(t *testing.T) {
	prev := GetContainerHintCombineMode()
	t.Cleanup(func() {
		if err := SetContainerHintCombineMode(prev); err != nil {
			t.Fatalf("restore combine mode: %v", err)
		}
	})

	if GetContainerHintCombineMode() != ContainerHintCombineFirst {
		t.Fatalf("expected default combine mode first, got %s", GetContainerHintCombineMode())
	}

	if err := SetContainerHintCombineMode(ContainerHintCombineAll); err != nil {
		t.Fatalf("set combine mode all: %v", err)
	}
	if got := GetContainerHintCombineMode(); got != ContainerHintCombineAll {
		t.Fatalf("expected combine mode all, got %s", got)
	}

	if err := SetContainerHintCombineMode(ContainerHintCombineMode(99)); err == nil {
		t.Fatalf("expected invalid combine mode error")
	}
	if got := GetContainerHintCombineMode(); got != ContainerHintCombineAll {
		t.Fatalf("invalid set should not change mode, got %s", got)
	}
}

func TestSetContainerHintCombineModeClearsIDCache(t *testing.T) {
	ClearCache()
	prevMode := GetContainerHintCombineMode()
	t.Cleanup(func() {
		if err := SetContainerHintCombineMode(prevMode); err != nil {
			t.Fatalf("restore combine mode: %v", err)
		}
		ClearCache()
	})

	origMachineIDProvider := machineIDProvider
	calls := 0
	machineIDProvider = func() (string, error) {
		calls++
		return fmt.Sprintf("machine-%d", calls), nil
	}
	t.Cleanup(func() { machineIDProvider = origMachineIDProvider })

	first, err := ID()
	if err != nil {
		t.Fatalf("first ID call failed: %v", err)
	}
	second, err := ID()
	if err != nil {
		t.Fatalf("second ID call failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected cached ID before mode switch, got %s and %s", first, second)
	}
	if calls != 1 {
		t.Fatalf("expected one machineIDProvider call before mode switch, got %d", calls)
	}

	if err := SetContainerHintCombineMode(ContainerHintCombineAll); err != nil {
		t.Fatalf("switch combine mode failed: %v", err)
	}

	third, err := ID()
	if err != nil {
		t.Fatalf("third ID call failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected cache clear after mode switch, got %d provider calls", calls)
	}
	if third == first {
		t.Fatalf("expected refreshed ID after cache clear, got same value %s", third)
	}
}

func TestContainerBindingConfigValidateRejectsInvalidHintCombineMode(t *testing.T) {
	invalidMode := ContainerHintCombineMode(99)
	cfg := &ContainerBindingConfig{
		Mode:                ContainerBindingContainer,
		PreferHostHardware:  false,
		FallbackToContainer: true,
		HintCombineMode:     &invalidMode,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid hint combine mode validation error")
	}
}
