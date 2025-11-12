package machineid

import "testing"

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

func TestGetMACAddressRejectsUnstable(t *testing.T) {
	stubMACResolver(t, func() (*MACInfo, error) {
		return &MACInfo{Address: "aa:bb", Stable: false}, nil
	})

	if _, err := GetMACAddress(); err == nil {
		t.Fatalf("expected error for unstable MAC")
	}
}
