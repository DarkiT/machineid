package cert

import (
	"testing"
	"time"
)

// TestModuleBuilder 测试模块配置构建器
func TestModuleBuilder(t *testing.T) {
	tests := []struct {
		name     string
		build    func() ModuleConfig
		expected ModuleConfig
	}{
		{
			name: "基本模块配置",
			build: func() ModuleConfig {
				return Module("report").Build()
			},
			expected: ModuleConfig{
				Name:    "report",
				Enabled: true,
			},
		},
		{
			name: "禁用模块",
			build: func() ModuleConfig {
				return Module("api").Disabled().Build()
			},
			expected: ModuleConfig{
				Name:    "api",
				Enabled: false,
			},
		},
		{
			name: "带配额的模块",
			build: func() ModuleConfig {
				return Module("export").WithQuota(100).Build()
			},
			expected: ModuleConfig{
				Name:    "export",
				Enabled: true,
				Quota:   100,
			},
		},
		{
			name: "带扩展数据的模块",
			build: func() ModuleConfig {
				return Module("custom").WithExtra(`{"key":"value"}`).Build()
			},
			expected: ModuleConfig{
				Name:    "custom",
				Enabled: true,
				Extra:   `{"key":"value"}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.build()
			if config.Name != tt.expected.Name {
				t.Errorf("Name = %v, want %v", config.Name, tt.expected.Name)
			}
			if config.Enabled != tt.expected.Enabled {
				t.Errorf("Enabled = %v, want %v", config.Enabled, tt.expected.Enabled)
			}
			if config.Quota != tt.expected.Quota {
				t.Errorf("Quota = %v, want %v", config.Quota, tt.expected.Quota)
			}
			if config.Extra != tt.expected.Extra {
				t.Errorf("Extra = %v, want %v", config.Extra, tt.expected.Extra)
			}
		})
	}
}

// TestModuleValidFor 测试模块有效期设置
func TestModuleValidFor(t *testing.T) {
	config := Module("report").ValidFor(30).Build()

	if config.NotAfter.IsZero() {
		t.Error("NotAfter should not be zero")
	}

	// 检查有效期大约是 30 天
	expectedDuration := 30 * 24 * time.Hour
	actualDuration := time.Until(config.NotAfter)
	if actualDuration < expectedDuration-time.Hour || actualDuration > expectedDuration+time.Hour {
		t.Errorf("ValidFor duration = %v, want approximately %v", actualDuration, expectedDuration)
	}
}

// TestModuleValidBetween 测试模块有效期范围设置
func TestModuleValidBetween(t *testing.T) {
	from := time.Now().Add(24 * time.Hour)
	to := time.Now().Add(30 * 24 * time.Hour)

	config := Module("report").ValidBetween(from, to).Build()

	if !config.NotBefore.Equal(from) {
		t.Errorf("NotBefore = %v, want %v", config.NotBefore, from)
	}
	if !config.NotAfter.Equal(to) {
		t.Errorf("NotAfter = %v, want %v", config.NotAfter, to)
	}
}

// TestFeaturesConfig 测试模块授权配置
func TestFeaturesConfig(t *testing.T) {
	features := &FeaturesConfig{}
	features.AddModule(Module("report").WithQuota(100).Build())
	features.AddModule(Module("export").Disabled().Build())

	if len(features.Modules) != 2 {
		t.Errorf("Modules count = %d, want 2", len(features.Modules))
	}

	info := features.ToFeaturesInfo()
	if info == nil {
		t.Fatal("ToFeaturesInfo returned nil")
	}

	if len(info.Modules) != 2 {
		t.Errorf("FeaturesInfo.Modules count = %d, want 2", len(info.Modules))
	}
}

// TestFeaturesInfoHasModule 测试模块权限检查
func TestFeaturesInfoHasModule(t *testing.T) {
	features := &FeaturesConfig{}
	features.AddModule(Module("report").Build())
	features.AddModule(Module("export").Disabled().Build())

	info := features.ToFeaturesInfo()

	tests := []struct {
		name     string
		module   string
		expected bool
	}{
		{"启用的模块", "report", true},
		{"禁用的模块", "export", false},
		{"不存在的模块", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := info.HasModule(tt.module); got != tt.expected {
				t.Errorf("HasModule(%q) = %v, want %v", tt.module, got, tt.expected)
			}
		})
	}
}

// TestFeaturesInfoValidateModule 测试模块权限验证
func TestFeaturesInfoValidateModule(t *testing.T) {
	now := time.Now()
	features := &FeaturesConfig{}
	features.AddModule(Module("report").Build())
	features.AddModule(Module("export").Disabled().Build())
	features.AddModule(Module("expired").ValidUntil(now.Add(-24 * time.Hour)).Build())
	features.AddModule(Module("future").ValidFrom(now.Add(24 * time.Hour)).Build())

	info := features.ToFeaturesInfo()

	tests := []struct {
		name      string
		module    string
		expectErr bool
		errCode   ErrorCode
	}{
		{"启用的模块", "report", false, ""},
		{"禁用的模块", "export", true, ErrModuleNotAuthorized},
		{"过期的模块", "expired", true, ErrModuleExpired},
		{"未生效的模块", "future", true, ErrModuleExpired},
		{"不存在的模块", "unknown", true, ErrModuleNotAuthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := info.ValidateModule(tt.module, now)
			if tt.expectErr {
				if err == nil {
					t.Errorf("ValidateModule(%q) expected error, got nil", tt.module)
					return
				}
				if certErr, ok := err.(*CertError); ok {
					if certErr.Code != tt.errCode {
						t.Errorf("ValidateModule(%q) error code = %v, want %v", tt.module, certErr.Code, tt.errCode)
					}
				}
			} else {
				if err != nil {
					t.Errorf("ValidateModule(%q) unexpected error: %v", tt.module, err)
				}
			}
		})
	}
}

// TestModulePermissionIsValid 测试模块权限有效性检查
func TestModulePermissionIsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		perm     ModulePermission
		expected bool
	}{
		{
			name:     "启用且无时间限制",
			perm:     ModulePermission{Name: "test", Enabled: true},
			expected: true,
		},
		{
			name:     "禁用",
			perm:     ModulePermission{Name: "test", Enabled: false},
			expected: false,
		},
		{
			name: "在有效期内",
			perm: ModulePermission{
				Name:      "test",
				Enabled:   true,
				NotBefore: now.Add(-24 * time.Hour).Unix(),
				NotAfter:  now.Add(24 * time.Hour).Unix(),
			},
			expected: true,
		},
		{
			name: "已过期",
			perm: ModulePermission{
				Name:     "test",
				Enabled:  true,
				NotAfter: now.Add(-24 * time.Hour).Unix(),
			},
			expected: false,
		},
		{
			name: "未生效",
			perm: ModulePermission{
				Name:      "test",
				Enabled:   true,
				NotBefore: now.Add(24 * time.Hour).Unix(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.perm.IsValid(now); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestCertificateWithModules 测试带模块授权的证书签发和验证
func TestCertificateWithModules(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "test-machine-001"
	expiryDate := time.Now().AddDate(1, 0, 0)

	// 创建带模块授权的证书请求
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

	// 签发证书
	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 提取模块权限
	features, err := auth.ExtractModules(cert.CertPEM)
	if err != nil {
		t.Fatalf("提取模块权限失败: %v", err)
	}

	if features == nil {
		t.Fatal("模块权限为 nil")
	}

	// 验证模块数量
	if len(features.Modules) != 3 {
		t.Errorf("模块数量 = %d, want 3", len(features.Modules))
	}

	// 验证 HasModule
	if !features.HasModule("report") {
		t.Error("HasModule(report) = false, want true")
	}
	if !features.HasModule("export") {
		t.Error("HasModule(export) = false, want true")
	}
	if features.HasModule("api") {
		t.Error("HasModule(api) = true, want false (disabled)")
	}

	// 验证配额
	reportModule := features.GetModule("report")
	if reportModule == nil {
		t.Fatal("GetModule(report) = nil")
	}
	if reportModule.Quota != 100 {
		t.Errorf("report.Quota = %d, want 100", reportModule.Quota)
	}
}

// TestAuthorizerHasModule 测试 Authorizer.HasModule
func TestAuthorizerHasModule(t *testing.T) {
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

	tests := []struct {
		name     string
		module   string
		expected bool
	}{
		{"启用的模块", "report", true},
		{"禁用的模块", "api", false},
		{"不存在的模块", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, err := auth.HasModule(cert.CertPEM, tt.module)
			if err != nil {
				t.Fatalf("HasModule error: %v", err)
			}
			if has != tt.expected {
				t.Errorf("HasModule(%q) = %v, want %v", tt.module, has, tt.expected)
			}
		})
	}
}

// TestAuthorizerGetModuleQuota 测试 Authorizer.GetModuleQuota
func TestAuthorizerGetModuleQuota(t *testing.T) {
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
			Module("report").WithQuota(100),
			Module("export").WithQuota(0), // 无限制
		).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 测试有配额的模块
	quota, err := auth.GetModuleQuota(cert.CertPEM, "report")
	if err != nil {
		t.Fatalf("GetModuleQuota(report) error: %v", err)
	}
	if quota != 100 {
		t.Errorf("GetModuleQuota(report) = %d, want 100", quota)
	}

	// 测试无限制配额的模块
	quota, err = auth.GetModuleQuota(cert.CertPEM, "export")
	if err != nil {
		t.Fatalf("GetModuleQuota(export) error: %v", err)
	}
	if quota != 0 {
		t.Errorf("GetModuleQuota(export) = %d, want 0", quota)
	}

	// 测试不存在的模块
	_, err = auth.GetModuleQuota(cert.CertPEM, "unknown")
	if err == nil {
		t.Error("GetModuleQuota(unknown) expected error, got nil")
	}
}

// TestExtractClientInfoWithFeatures 测试 ExtractClientInfo 包含模块权限
func TestExtractClientInfoWithFeatures(t *testing.T) {
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
			Module("report").WithQuota(100),
		).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 提取客户端信息
	clientInfo, err := auth.ExtractClientInfo(cert.CertPEM)
	if err != nil {
		t.Fatalf("ExtractClientInfo error: %v", err)
	}

	if clientInfo.Features == nil {
		t.Fatal("ClientInfo.Features is nil")
	}

	if !clientInfo.Features.HasModule("report") {
		t.Error("ClientInfo.Features.HasModule(report) = false, want true")
	}
}

// TestCertificateWithoutModules 测试无模块授权的证书（向后兼容）
func TestCertificateWithoutModules(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "test-machine-001"
	expiryDate := time.Now().AddDate(1, 0, 0)

	// 创建不带模块授权的证书请求
	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(expiryDate).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 提取模块权限应返回 nil（向后兼容）
	features, err := auth.ExtractModules(cert.CertPEM)
	if err != nil {
		t.Fatalf("ExtractModules error: %v", err)
	}

	if features != nil {
		t.Errorf("ExtractModules = %v, want nil for certificate without modules", features)
	}

	// HasModule 应返回 false
	has, err := auth.HasModule(cert.CertPEM, "report")
	if err != nil {
		t.Fatalf("HasModule error: %v", err)
	}
	if has {
		t.Error("HasModule(report) = true, want false for certificate without modules")
	}
}
