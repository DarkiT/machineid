package cert

import (
	"testing"
	"time"
)

// TestNewAuthorizer 测试创建授权管理器构建器
func TestNewAuthorizer(t *testing.T) {
	t.Parallel()

	builder := NewAuthorizer()
	if builder == nil {
		t.Fatal("构建器不应为 nil")
	}

	// 验证默认配置
	if builder.config.RuntimeVersion != "" {
		t.Error("默认运行版本应为空")
	}

	if len(builder.config.CACert) == 0 {
		t.Error("默认 CA 证书不应为空")
	}

	if len(builder.config.CAKey) == 0 {
		t.Error("默认 CA 私钥不应为空")
	}

	if builder.config.EnterpriseID == 0 {
		t.Error("默认企业 ID 不应为 0")
	}
}

// TestAuthorizerBuilder_WithRuntimeVersion 测试设置运行版本
func TestAuthorizerBuilder_WithRuntimeVersion(t *testing.T) {
	t.Parallel()

	builder := NewAuthorizer().WithRuntimeVersion("2.0.0")
	if builder.config.RuntimeVersion != "2.0.0" {
		t.Errorf("运行版本设置失败: 期望 2.0.0, 实际 %s", builder.config.RuntimeVersion)
	}
}

// TestAuthorizerBuilder_WithCA 测试设置自定义 CA
func TestAuthorizerBuilder_WithCA(t *testing.T) {
	t.Parallel()

	customCert := []byte("custom cert")
	customKey := []byte("custom key")

	builder := NewAuthorizer().WithCA(customCert, customKey)

	if string(builder.config.CACert) != string(customCert) {
		t.Error("CA 证书设置失败")
	}

	if string(builder.config.CAKey) != string(customKey) {
		t.Error("CA 私钥设置失败")
	}
}

// TestAuthorizerBuilder_WithEnterpriseID 测试设置企业 ID
func TestAuthorizerBuilder_WithEnterpriseID(t *testing.T) {
	t.Parallel()

	enterpriseID := 12345
	builder := NewAuthorizer().WithEnterpriseID(enterpriseID)

	if builder.config.EnterpriseID != enterpriseID {
		t.Errorf("企业 ID 设置失败: 期望 %d, 实际 %d", enterpriseID, builder.config.EnterpriseID)
	}
}

// TestAuthorizerBuilder_WithMaxClockSkew 测试设置最大时钟偏差
func TestAuthorizerBuilder_WithMaxClockSkew(t *testing.T) {
	t.Parallel()

	skew := 10 * time.Minute
	builder := NewAuthorizer().WithMaxClockSkew(skew)

	if builder.config.Security.MaxClockSkew != skew {
		t.Errorf("时钟偏差设置失败: 期望 %v, 实际 %v", skew, builder.config.Security.MaxClockSkew)
	}
}

// TestAuthorizerBuilder_WithSecurityLevel 测试设置安全级别
func TestAuthorizerBuilder_WithSecurityLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		level int
	}{
		{"级别0", 0},
		{"级别1", 1},
		{"级别2", 2},
		{"级别3", 3},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builder := NewAuthorizer().WithSecurityLevel(tt.level)
			level, ok := builder.config.Security.EffectiveSecurityLevel()

			if !ok {
				t.Error("安全级别未设置")
			}

			if level != tt.level {
				t.Errorf("安全级别不匹配: 期望 %d, 实际 %d", tt.level, level)
			}
		})
	}
}

// TestAuthorizerBuilder_WithCacheTTL 测试设置缓存 TTL
func TestAuthorizerBuilder_WithCacheTTL(t *testing.T) {
	t.Parallel()

	ttl := 15 * time.Minute
	builder := NewAuthorizer().WithCacheTTL(ttl)

	if builder.config.Cache.TTL != ttl {
		t.Errorf("缓存 TTL 设置失败: 期望 %v, 实际 %v", ttl, builder.config.Cache.TTL)
	}
}

// TestAuthorizerBuilder_WithCacheSize 测试设置缓存大小
func TestAuthorizerBuilder_WithCacheSize(t *testing.T) {
	t.Parallel()

	size := 2000
	builder := NewAuthorizer().WithCacheSize(size)

	if builder.config.Cache.MaxSize != size {
		t.Errorf("缓存大小设置失败: 期望 %d, 实际 %d", size, builder.config.Cache.MaxSize)
	}
}

// TestAuthorizerBuilder_UseDefaultCA 测试使用默认 CA
func TestAuthorizerBuilder_UseDefaultCA(t *testing.T) {
	t.Parallel()

	builder := NewAuthorizer().UseDefaultCA()

	if len(builder.config.CACert) == 0 {
		t.Error("默认 CA 证书不应为空")
	}

	if len(builder.config.CAKey) == 0 {
		t.Error("默认 CA 私钥不应为空")
	}
}

// TestAuthorizerBuilder_Build 测试构建授权管理器
func TestAuthorizerBuilder_Build(t *testing.T) {
	t.Parallel()

	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("构建授权管理器失败: %v", err)
	}

	if auth == nil {
		t.Fatal("授权管理器不应为 nil")
	}
}

// TestAuthorizerBuilder_BuildWithInvalidCA 测试使用无效 CA 构建
func TestAuthorizerBuilder_BuildWithInvalidCA(t *testing.T) {
	t.Parallel()

	// 使用空的 CA 证书和私钥
	_, err := NewAuthorizer().
		WithCA([]byte{}, []byte{}).
		Build()

	if err == nil {
		t.Error("期望构建失败（无效的 CA），但成功了")
	}
}

// TestAuthorizerBuilder_ChainedCalls 测试链式调用
func TestAuthorizerBuilder_ChainedCalls(t *testing.T) {
	t.Parallel()

	version := "2.5.0"
	enterpriseID := 99999
	skew := 20 * time.Minute
	ttl := 30 * time.Minute
	cacheSize := 5000

	builder := NewAuthorizer().
		WithRuntimeVersion(version).
		WithEnterpriseID(enterpriseID).
		WithMaxClockSkew(skew).
		WithCacheTTL(ttl).
		WithCacheSize(cacheSize).
		WithSecurityLevel(2)

	// 验证所有配置
	if builder.config.RuntimeVersion != version {
		t.Errorf("运行版本不匹配: 期望 %s, 实际 %s", version, builder.config.RuntimeVersion)
	}

	if builder.config.EnterpriseID != enterpriseID {
		t.Errorf("企业 ID 不匹配: 期望 %d, 实际 %d", enterpriseID, builder.config.EnterpriseID)
	}

	if builder.config.Security.MaxClockSkew != skew {
		t.Errorf("时钟偏差不匹配: 期望 %v, 实际 %v", skew, builder.config.Security.MaxClockSkew)
	}

	if builder.config.Cache.TTL != ttl {
		t.Errorf("缓存 TTL 不匹配: 期望 %v, 实际 %v", ttl, builder.config.Cache.TTL)
	}

	if builder.config.Cache.MaxSize != cacheSize {
		t.Errorf("缓存大小不匹配: 期望 %d, 实际 %d", cacheSize, builder.config.Cache.MaxSize)
	}

	level, ok := builder.config.Security.EffectiveSecurityLevel()
	if !ok {
		t.Error("安全级别未设置")
	}
	if level != 2 {
		t.Errorf("安全级别不匹配: 期望 2, 实际 %d", level)
	}
}

// TestSecurityConfig_GetSetSecurityLevel 测试安全级别的获取和设置
func TestSecurityConfig_GetSetSecurityLevel(t *testing.T) {
	t.Parallel()

	config := SecurityConfig{}

	// 初始状态：未设置
	_, ok := config.EffectiveSecurityLevel()
	if ok {
		t.Error("初始状态应该没有安全级别")
	}

	// 设置安全级别
	config.SetSecurityLevel(3)
	level, ok := config.EffectiveSecurityLevel()
	if !ok {
		t.Error("安全级别应该已设置")
	}
	if level != 3 {
		t.Errorf("安全级别不匹配: 期望 3, 实际 %d", level)
	}
}

// TestAuthorizerBuilder_DefaultSecurityConfig 测试默认安全配置
func TestAuthorizerBuilder_DefaultSecurityConfig(t *testing.T) {
	t.Parallel()

	builder := NewAuthorizer()

	// 验证默认安全配置
	if builder.config.Security.EnableAntiDebug {
		t.Error("默认应禁用反调试")
	}

	if builder.config.Security.EnableTimeValidation {
		t.Error("默认应禁用时间验证")
	}

	if builder.config.Security.RequireHardwareBinding {
		t.Error("默认应不要求硬件绑定")
	}

	if builder.config.Security.MaxClockSkew == 0 {
		t.Error("默认时钟偏差不应为 0")
	}
}

// TestAuthorizerBuilder_DefaultCacheConfig 测试默认缓存配置
func TestAuthorizerBuilder_DefaultCacheConfig(t *testing.T) {
	t.Parallel()

	builder := NewAuthorizer()

	// 验证默认缓存配置
	if builder.config.Cache.TTL == 0 {
		t.Error("默认缓存 TTL 不应为 0")
	}

	if builder.config.Cache.MaxSize == 0 {
		t.Error("默认缓存大小不应为 0")
	}

	if builder.config.Cache.CleanupInterval == 0 {
		t.Error("默认清理间隔不应为 0")
	}
}

// TestAuthorizerConcurrentBuild 测试并发构建授权管理器
func TestAuthorizerConcurrentBuild(t *testing.T) {
	t.Parallel()

	concurrency := 10
	done := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			_, err := newTestAuthorizerBuilder(t).
				WithRuntimeVersion("1.0.0").
				Build()
			done <- err
		}()
	}

	// 等待所有 goroutine 完成
	for i := 0; i < concurrency; i++ {
		if err := <-done; err != nil {
			t.Errorf("并发构建授权管理器失败: %v", err)
		}
	}
}

// TestAuthorizerBuilder_MultipleBuilds 测试多次构建
func TestAuthorizerBuilder_MultipleBuilds(t *testing.T) {
	t.Parallel()

	builder := NewAuthorizer().UseDefaultCA()

	// 第一次构建
	auth1, err := builder.Build()
	if err != nil {
		t.Fatalf("第一次构建失败: %v", err)
	}

	// 第二次构建
	auth2, err := builder.Build()
	if err != nil {
		t.Fatalf("第二次构建失败: %v", err)
	}

	// 验证两次构建的实例不同
	if auth1 == auth2 {
		t.Error("多次构建应该返回不同的实例")
	}
}

// TestAuthorizerConfig 测试配置结构
func TestAuthorizerConfig(t *testing.T) {
	t.Parallel()

	config := AuthorizerConfig{
		RuntimeVersion: "1.0.0",
		CACert:         []byte("cert"),
		CAKey:          []byte("key"),
		EnterpriseID:   123,
		Security: SecurityConfig{
			EnableAntiDebug:      true,
			EnableTimeValidation: true,
			MaxClockSkew:         5 * time.Minute,
		},
		Cache: CacheConfig{
			TTL:             10 * time.Minute,
			MaxSize:         100,
			CleanupInterval: 5 * time.Minute,
		},
	}

	// 验证配置字段
	if config.RuntimeVersion != "1.0.0" {
		t.Error("运行版本字段错误")
	}

	if string(config.CACert) != "cert" {
		t.Error("CA 证书字段错误")
	}

	if string(config.CAKey) != "key" {
		t.Error("CA 私钥字段错误")
	}

	if config.EnterpriseID != 123 {
		t.Error("企业 ID 字段错误")
	}

	if !config.Security.EnableAntiDebug {
		t.Error("安全配置字段错误")
	}

	if config.Cache.TTL != 10*time.Minute {
		t.Error("缓存配置字段错误")
	}
}
