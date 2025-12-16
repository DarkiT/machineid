package cert

import (
	"testing"
	"time"

	machineid "github.com/darkit/machineid"
)

func TestLicense_IssueAndValidate(t *testing.T) {
	t.Parallel()

	appID := "example.app"

	pubPEM, privPEM, err := GenerateLicenseKeyPairPEM()
	if err != nil {
		t.Fatalf("GenerateLicenseKeyPairPEM: %v", err)
	}
	pub, err := ParseEd25519PublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyPEM: %v", err)
	}
	priv, err := ParseEd25519PrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKeyPEM: %v", err)
	}

	// machineID 使用 ProtectedIDResult(appID).Hash（推荐）
	binding, err := machineid.ProtectedIDResult(appID)
	if err != nil {
		t.Fatalf("ProtectedIDResult: %v", err)
	}

	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID: "lic-001",
		IssuedAt:  now,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
		MachineID: binding.Hash,
		Features: map[string]any{
			"plan": "pro",
		},
	}

	licJSON, err := IssueLicense(payload, priv)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	got, err := ValidateLicenseJSONWithAppID(licJSON, pub, appID, now)
	if err != nil {
		t.Fatalf("ValidateLicenseJSON: %v", err)
	}
	if got.LicenseID != payload.LicenseID {
		t.Fatalf("license id mismatch: got %q want %q", got.LicenseID, payload.LicenseID)
	}
}

func TestLicense_RejectsWrongMachine(t *testing.T) {
	t.Parallel()

	appID := "example.app"

	_, privPEM, err := GenerateLicenseKeyPairPEM()
	if err != nil {
		t.Fatalf("GenerateLicenseKeyPairPEM: %v", err)
	}
	// Generate a second pair for pub mismatch checks too
	pubPEM2, _, err := GenerateLicenseKeyPairPEM()
	if err != nil {
		t.Fatalf("GenerateLicenseKeyPairPEM: %v", err)
	}
	pub2, err := ParseEd25519PublicKeyPEM(pubPEM2)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyPEM: %v", err)
	}
	priv, err := ParseEd25519PrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKeyPEM: %v", err)
	}

	binding, err := machineid.ProtectedIDResult(appID)
	if err != nil {
		t.Fatalf("ProtectedIDResult: %v", err)
	}

	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID: "lic-002",
		IssuedAt:  now,
		NotAfter:  now.Add(time.Hour),
		MachineID: binding.Hash,
	}
	licJSON, err := IssueLicense(payload, priv)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	// Wrong machine id
	if _, err := ValidateLicenseJSONWithAppID(licJSON, pub2, "other.app", now); err == nil {
		t.Fatalf("expected error for wrong machine and/or key")
	}
}
