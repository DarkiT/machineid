package cert

import (
	"testing"
	"time"
)

// TestAuthorization_Interface 测试 Authorization 接口实现
func TestAuthorization_Interface(t *testing.T) {
	// 确保两种实现都满足接口
	var _ Authorization = (*CertAuthorization)(nil)
	var _ Authorization = (*LicenseAuthorization)(nil)
}

// TestCertAuthorization 测试证书授权
func TestCertAuthorization(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "test-machine-001"
	expiryDate := time.Now().AddDate(1, 0, 0)

	// 创建带模块授权的证书
	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(expiryDate).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		WithModules(
			Module("report").WithQuota(100),
			Module("export").Enabled(),
			Module("api").Disabled(),
		).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 创建 CertAuthorization
	certAuth, err := NewCertAuthorization(cert.CertPEM, auth)
	if err != nil {
		t.Fatalf("创建 CertAuthorization 失败: %v", err)
	}

	// 测试类型
	if certAuth.Type() != AuthTypeCertificate {
		t.Errorf("Type() = %v, want %v", certAuth.Type(), AuthTypeCertificate)
	}

	// 测试过期时间
	if certAuth.ExpiresAt().IsZero() {
		t.Error("ExpiresAt() is zero")
	}

	// 测试机器码
	machineIDs := certAuth.MachineIDs()
	if len(machineIDs) == 0 {
		t.Error("MachineIDs() is empty")
	}
	if machineIDs[0] != machineID {
		t.Errorf("MachineIDs()[0] = %v, want %v", machineIDs[0], machineID)
	}

	// 测试模块权限
	if !certAuth.HasModule("report") {
		t.Error("HasModule(report) = false, want true")
	}
	if !certAuth.HasModule("export") {
		t.Error("HasModule(export) = false, want true")
	}
	if certAuth.HasModule("api") {
		t.Error("HasModule(api) = true, want false (disabled)")
	}
	if certAuth.HasModule("unknown") {
		t.Error("HasModule(unknown) = true, want false")
	}

	// 测试配额
	if quota := certAuth.GetModuleQuota("report"); quota != 100 {
		t.Errorf("GetModuleQuota(report) = %d, want 100", quota)
	}

	// 测试模块验证
	if err := certAuth.ValidateModule("report"); err != nil {
		t.Errorf("ValidateModule(report) error: %v", err)
	}
	if err := certAuth.ValidateModule("api"); err == nil {
		t.Error("ValidateModule(api) expected error for disabled module")
	}

	// 测试元数据（证书不支持）
	if meta := certAuth.GetMeta("key"); meta != "" {
		t.Errorf("GetMeta(key) = %q, want empty", meta)
	}

	// 测试验证
	if err := certAuth.Validate(machineID); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

// TestLicenseAuthorization 测试 License 授权
func TestLicenseAuthorization(t *testing.T) {
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

	machineID := "test-machine-001"
	now := time.Now().UTC()

	payload := LicensePayload{
		LicenseID: "lic-001",
		IssuedAt:  now,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
		MachineID: machineID,
		Features: map[string]any{
			"modules": map[string]any{
				"report": map[string]any{
					"enabled": true,
					"quota":   float64(100),
				},
				"export": map[string]any{
					"enabled": true,
				},
				"api": map[string]any{
					"enabled": false,
				},
			},
			"tier": "enterprise",
		},
		Meta: map[string]string{
			"customer": "Acme Corp",
			"plan":     "enterprise",
		},
	}

	// 签发 License
	licJSON, err := IssueLicense(payload, priv)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	// 验证并获取 payload
	validatedPayload, err := ValidateLicenseJSON(licJSON, pub, machineID, now)
	if err != nil {
		t.Fatalf("ValidateLicenseJSON: %v", err)
	}

	// 创建 LicenseAuthorization
	licAuth := NewLicenseAuthorization(validatedPayload, pub)

	// 测试类型
	if licAuth.Type() != AuthTypeLicense {
		t.Errorf("Type() = %v, want %v", licAuth.Type(), AuthTypeLicense)
	}

	// 测试过期时间
	if licAuth.ExpiresAt().IsZero() {
		t.Error("ExpiresAt() is zero")
	}

	// 测试机器码
	machineIDs := licAuth.MachineIDs()
	if len(machineIDs) == 0 {
		t.Error("MachineIDs() is empty")
	}
	if machineIDs[0] != machineID {
		t.Errorf("MachineIDs()[0] = %v, want %v", machineIDs[0], machineID)
	}

	// 测试模块权限
	if !licAuth.HasModule("report") {
		t.Error("HasModule(report) = false, want true")
	}
	if !licAuth.HasModule("export") {
		t.Error("HasModule(export) = false, want true")
	}
	if licAuth.HasModule("api") {
		t.Error("HasModule(api) = true, want false (disabled)")
	}

	// 测试配额
	if quota := licAuth.GetModuleQuota("report"); quota != 100 {
		t.Errorf("GetModuleQuota(report) = %d, want 100", quota)
	}

	// 测试模块验证
	if err := licAuth.ValidateModule("report"); err != nil {
		t.Errorf("ValidateModule(report) error: %v", err)
	}
	if err := licAuth.ValidateModule("api"); err == nil {
		t.Error("ValidateModule(api) expected error for disabled module")
	}

	// 测试元数据
	if meta := licAuth.GetMeta("customer"); meta != "Acme Corp" {
		t.Errorf("GetMeta(customer) = %q, want %q", meta, "Acme Corp")
	}
	if meta := licAuth.GetMeta("unknown"); meta != "" {
		t.Errorf("GetMeta(unknown) = %q, want empty", meta)
	}

	// 测试 HasFeature
	if !licAuth.HasFeature("tier") {
		t.Error("HasFeature(tier) = false, want true")
	}
	if !licAuth.HasFeature("modules.report.enabled") {
		t.Error("HasFeature(modules.report.enabled) = false, want true")
	}

	// 测试验证
	if err := licAuth.Validate(machineID); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

// TestParseAuthorization_Certificate 测试自动识别证书
func TestParseAuthorization_Certificate(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "test-machine-001"
	expiryDate := time.Now().AddDate(1, 0, 0)

	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(expiryDate).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		WithModules(Module("report").Enabled()).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 使用 ParseAuthorization 自动识别
	authorization, err := auth.ParseAuthorization(cert.CertPEM, nil)
	if err != nil {
		t.Fatalf("ParseAuthorization error: %v", err)
	}

	if authorization.Type() != AuthTypeCertificate {
		t.Errorf("Type() = %v, want %v", authorization.Type(), AuthTypeCertificate)
	}

	if !authorization.HasModule("report") {
		t.Error("HasModule(report) = false, want true")
	}
}

// TestParseAuthorization_License 测试自动识别 License
func TestParseAuthorization_License(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

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

	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID: "lic-001",
		NotAfter:  now.Add(24 * time.Hour),
		Features: map[string]any{
			"modules": map[string]any{
				"report": map[string]any{"enabled": true},
			},
		},
	}

	licJSON, err := IssueLicense(payload, priv)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	// 使用 ParseAuthorization 自动识别
	authorization, err := auth.ParseAuthorization(licJSON, pub)
	if err != nil {
		t.Fatalf("ParseAuthorization error: %v", err)
	}

	if authorization.Type() != AuthTypeLicense {
		t.Errorf("Type() = %v, want %v", authorization.Type(), AuthTypeLicense)
	}

	if !authorization.HasModule("report") {
		t.Error("HasModule(report) = false, want true")
	}
}

// TestValidateWithModules 测试带模块验证的完整验证
func TestValidateWithModules(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "test-machine-001"
	expiryDate := time.Now().AddDate(1, 0, 0)

	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(expiryDate).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		WithModules(
			Module("report").Enabled(),
			Module("export").Enabled(),
			Module("api").Disabled(),
		).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 测试有权限的模块
	err = auth.ValidateWithModules(cert.CertPEM, machineID, []string{"report", "export"}, nil)
	if err != nil {
		t.Errorf("ValidateWithModules(report, export) error: %v", err)
	}

	// 测试无权限的模块
	err = auth.ValidateWithModules(cert.CertPEM, machineID, []string{"report", "api"}, nil)
	if err == nil {
		t.Error("ValidateWithModules(report, api) expected error for disabled module")
	}

	// 测试不存在的模块
	err = auth.ValidateWithModules(cert.CertPEM, machineID, []string{"unknown"}, nil)
	if err == nil {
		t.Error("ValidateWithModules(unknown) expected error for non-existent module")
	}
}

// TestParseAuthorization_InvalidData 测试无效数据
func TestParseAuthorization_InvalidData(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"空数据", []byte{}},
		{"随机数据", []byte("random data")},
		{"无效 JSON", []byte(`{"invalid": "json"`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := auth.ParseAuthorization(tt.data, nil)
			if err == nil {
				t.Error("ParseAuthorization expected error for invalid data")
			}
		})
	}
}

// TestAuthorizationPolymorphism 测试多态使用
func TestAuthorizationPolymorphism(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "test-machine-001"
	expiryDate := time.Now().AddDate(1, 0, 0)

	// 创建证书授权
	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(expiryDate).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		WithModules(Module("report").WithQuota(100)).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	certAuth, _ := NewCertAuthorization(cert.CertPEM, auth)

	// 创建 License 授权
	pubPEM, privPEM, _ := GenerateLicenseKeyPairPEM()
	pub, _ := ParseEd25519PublicKeyPEM(pubPEM)
	priv, _ := ParseEd25519PrivateKeyPEM(privPEM)

	payload := LicensePayload{
		LicenseID: "lic-001",
		MachineID: machineID,
		NotAfter:  time.Now().Add(24 * time.Hour),
		Features: map[string]any{
			"modules": map[string]any{
				"report": map[string]any{"enabled": true, "quota": float64(200)},
			},
		},
	}
	licJSON, _ := IssueLicense(payload, priv)
	validatedPayload, _ := ValidateLicenseJSON(licJSON, pub, machineID, time.Now())
	licAuth := NewLicenseAuthorization(validatedPayload, pub)

	// 多态使用
	authorizations := []Authorization{certAuth, licAuth}

	for _, authorization := range authorizations {
		t.Run(string(authorization.Type()), func(t *testing.T) {
			// 所有授权都应该有 report 模块
			if !authorization.HasModule("report") {
				t.Error("HasModule(report) = false, want true")
			}

			// 所有授权都应该有配额
			quota := authorization.GetModuleQuota("report")
			if quota == 0 {
				t.Error("GetModuleQuota(report) = 0, want > 0")
			}

			// 所有授权都应该有过期时间
			if authorization.ExpiresAt().IsZero() {
				t.Error("ExpiresAt() is zero")
			}

			// 所有授权都应该有机器码
			if len(authorization.MachineIDs()) == 0 {
				t.Error("MachineIDs() is empty")
			}
		})
	}
}
