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

// TestLicensePayload_HasFeature 测试 HasFeature 方法
func TestLicensePayload_HasFeature(t *testing.T) {
	payload := LicensePayload{
		Features: map[string]any{
			"plan": "pro",
			"modules": map[string]any{
				"report": map[string]any{
					"enabled": true,
					"quota":   100,
				},
				"export": map[string]any{
					"enabled": false,
				},
			},
			"max_users": 50,
		},
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"顶级字符串", "plan", true},
		{"顶级数字", "max_users", true},
		{"嵌套布尔值 true", "modules.report.enabled", true},
		{"嵌套布尔值 false", "modules.export.enabled", false},
		{"嵌套数字", "modules.report.quota", true},
		{"不存在的路径", "modules.unknown", false},
		{"不存在的顶级", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := payload.HasFeature(tt.path); got != tt.expected {
				t.Errorf("HasFeature(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// TestLicensePayload_GetFeatureValue 测试 GetFeatureValue 方法
func TestLicensePayload_GetFeatureValue(t *testing.T) {
	payload := LicensePayload{
		Features: map[string]any{
			"plan": "pro",
			"modules": map[string]any{
				"report": map[string]any{
					"enabled": true,
					"quota":   float64(100),
				},
			},
		},
	}

	tests := []struct {
		name     string
		path     string
		expected any
		ok       bool
	}{
		{"顶级字符串", "plan", "pro", true},
		{"嵌套布尔值", "modules.report.enabled", true, true},
		{"嵌套数字", "modules.report.quota", float64(100), true},
		{"不存在的路径", "modules.unknown", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := payload.GetFeatureValue(tt.path)
			if ok != tt.ok {
				t.Errorf("GetFeatureValue(%q) ok = %v, want %v", tt.path, ok, tt.ok)
			}
			if ok && val != tt.expected {
				t.Errorf("GetFeatureValue(%q) = %v, want %v", tt.path, val, tt.expected)
			}
		})
	}
}

// TestLicensePayload_GetModuleConfig 测试 GetModuleConfig 方法
func TestLicensePayload_GetModuleConfig(t *testing.T) {
	payload := LicensePayload{
		Features: map[string]any{
			"modules": map[string]any{
				"report": map[string]any{
					"enabled":   true,
					"quota":     float64(100),
					"not_after": "2025-12-31",
				},
				"export": map[string]any{
					"enabled": false,
				},
			},
		},
	}

	// 测试存在的模块
	config, ok := payload.GetModuleConfig("report")
	if !ok {
		t.Fatal("GetModuleConfig(report) ok = false, want true")
	}
	if config.Name != "report" {
		t.Errorf("config.Name = %q, want %q", config.Name, "report")
	}
	if !config.Enabled {
		t.Error("config.Enabled = false, want true")
	}
	if config.Quota != 100 {
		t.Errorf("config.Quota = %d, want 100", config.Quota)
	}
	if config.NotAfter.IsZero() {
		t.Error("config.NotAfter is zero, want 2025-12-31")
	}

	// 测试禁用的模块
	config, ok = payload.GetModuleConfig("export")
	if !ok {
		t.Fatal("GetModuleConfig(export) ok = false, want true")
	}
	if config.Enabled {
		t.Error("config.Enabled = true, want false")
	}

	// 测试不存在的模块
	_, ok = payload.GetModuleConfig("unknown")
	if ok {
		t.Error("GetModuleConfig(unknown) ok = true, want false")
	}
}

// TestLicensePayload_ValidateModuleAccess 测试 ValidateModuleAccess 方法
func TestLicensePayload_ValidateModuleAccess(t *testing.T) {
	now := time.Now()
	payload := LicensePayload{
		Features: map[string]any{
			"modules": map[string]any{
				"report": map[string]any{
					"enabled": true,
				},
				"export": map[string]any{
					"enabled": false,
				},
				"expired": map[string]any{
					"enabled":   true,
					"not_after": now.Add(-24 * time.Hour).Format("2006-01-02"),
				},
			},
		},
	}

	tests := []struct {
		name      string
		module    string
		expectErr bool
		errCode   ErrorCode
	}{
		{"启用的模块", "report", false, ""},
		{"禁用的模块", "export", true, ErrModuleNotAuthorized},
		{"过期的模块", "expired", true, ErrModuleExpired},
		{"不存在的模块", "unknown", true, ErrModuleNotAuthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := payload.ValidateModuleAccess(tt.module, now)
			if tt.expectErr {
				if err == nil {
					t.Errorf("ValidateModuleAccess(%q) expected error, got nil", tt.module)
					return
				}
				if certErr, ok := err.(*CertError); ok {
					if certErr.Code != tt.errCode {
						t.Errorf("ValidateModuleAccess(%q) error code = %v, want %v", tt.module, certErr.Code, tt.errCode)
					}
				}
			} else {
				if err != nil {
					t.Errorf("ValidateModuleAccess(%q) unexpected error: %v", tt.module, err)
				}
			}
		})
	}
}

// TestLicensePayload_NilFeatures 测试 Features 为 nil 的情况
func TestLicensePayload_NilFeatures(t *testing.T) {
	payload := LicensePayload{}

	if payload.HasFeature("any") {
		t.Error("HasFeature should return false for nil Features")
	}

	_, ok := payload.GetFeatureValue("any")
	if ok {
		t.Error("GetFeatureValue should return false for nil Features")
	}

	_, ok = payload.GetModuleConfig("any")
	if ok {
		t.Error("GetModuleConfig should return false for nil Features")
	}

	err := payload.ValidateModuleAccess("any", time.Now())
	if err == nil {
		t.Error("ValidateModuleAccess should return error for nil Features")
	}
}
