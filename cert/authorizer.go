package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"
)

// SecurityConfig 安全配置
type SecurityConfig struct {
	EnableAntiDebug        bool          // 启用反调试
	EnableTimeValidation   bool          // 启用时间验证
	RequireHardwareBinding bool          // 要求硬件绑定
	MaxClockSkew           time.Duration // 最大时钟偏差
	SecurityLevel          *int          // 显式安全级别（可选，优先级最高）
}

// GetSecurityLevel 获取安全级别
func (sc *SecurityConfig) GetSecurityLevel() (int, bool) {
	if sc.SecurityLevel != nil {
		return *sc.SecurityLevel, true
	}
	return 0, false
}

// SetSecurityLevel 设置安全级别
func (sc *SecurityConfig) SetSecurityLevel(level int) {
	sc.SecurityLevel = &level
}

// CacheConfig 缓存配置
type CacheConfig struct {
	TTL             time.Duration // 缓存有效期
	MaxSize         int           // 最大缓存大小
	CleanupInterval time.Duration // 清理间隔
}

// AuthorizerConfig 授权管理器配置
type AuthorizerConfig struct {
	Version      string         // 当前版本
	CACert       []byte         // CA证书
	CAKey        []byte         // CA私钥
	EnterpriseID int            // 企业标识符
	Security     SecurityConfig // 安全配置
	Cache        CacheConfig    // 缓存配置
}

// AuthorizerBuilder 授权管理器构建器
type AuthorizerBuilder struct {
	config AuthorizerConfig
}

// NewAuthorizer 创建新的授权管理器构建器
func NewAuthorizer() *AuthorizerBuilder {
	return &AuthorizerBuilder{
		config: AuthorizerConfig{
			Version:      "1.0.0",
			CACert:       defaultCACert,
			CAKey:        defaultCAKey,
			EnterpriseID: defaultEnterpriseID,
			Security: SecurityConfig{
				EnableAntiDebug:        false, // 默认禁用反调试
				EnableTimeValidation:   false, // 默认禁用时间验证
				RequireHardwareBinding: false, // 默认不要求硬件绑定
				MaxClockSkew:           5 * time.Minute,
				SecurityLevel:          nil, // 不设置默认安全级别，由配置推断
			},
			Cache: CacheConfig{
				TTL:             5 * time.Minute,
				MaxSize:         1000,
				CleanupInterval: 10 * time.Minute,
			},
		},
	}
}

// WithVersion 设置版本号
func (b *AuthorizerBuilder) WithVersion(version string) *AuthorizerBuilder {
	b.config.Version = version
	return b
}

// WithCA 设置自定义CA证书和私钥
func (b *AuthorizerBuilder) WithCA(cert, key []byte) *AuthorizerBuilder {
	if cert != nil {
		b.config.CACert = cert
	}
	if key != nil {
		b.config.CAKey = key
	}
	return b
}

// WithEnterpriseID 设置企业标识符
func (b *AuthorizerBuilder) WithEnterpriseID(id int) *AuthorizerBuilder {
	b.config.EnterpriseID = id
	return b
}

// WithSecurity 设置安全配置
func (b *AuthorizerBuilder) WithSecurity(security SecurityConfig) *AuthorizerBuilder {
	b.config.Security = security
	return b
}

// WithCache 设置缓存配置
func (b *AuthorizerBuilder) WithCache(cache CacheConfig) *AuthorizerBuilder {
	b.config.Cache = cache
	return b
}

// EnableAntiDebug 启用反调试
func (b *AuthorizerBuilder) EnableAntiDebug(enable bool) *AuthorizerBuilder {
	b.config.Security.EnableAntiDebug = enable
	return b
}

// EnableTimeValidation 启用时间验证
func (b *AuthorizerBuilder) EnableTimeValidation(enable bool) *AuthorizerBuilder {
	b.config.Security.EnableTimeValidation = enable
	return b
}

// RequireHardwareBinding 要求硬件绑定
func (b *AuthorizerBuilder) RequireHardwareBinding(require bool) *AuthorizerBuilder {
	b.config.Security.RequireHardwareBinding = require
	return b
}

// WithMaxClockSkew 设置最大时钟偏差
func (b *AuthorizerBuilder) WithMaxClockSkew(skew time.Duration) *AuthorizerBuilder {
	b.config.Security.MaxClockSkew = skew
	return b
}

// WithSecurityLevel 设置安全级别（0=禁用，1=基础，2=高级，3=关键）
func (b *AuthorizerBuilder) WithSecurityLevel(level int) *AuthorizerBuilder {
	b.config.Security.SetSecurityLevel(level)
	return b
}

// WithCacheTTL 设置缓存有效期
func (b *AuthorizerBuilder) WithCacheTTL(ttl time.Duration) *AuthorizerBuilder {
	b.config.Cache.TTL = ttl
	return b
}

// WithCacheSize 设置缓存大小
func (b *AuthorizerBuilder) WithCacheSize(size int) *AuthorizerBuilder {
	b.config.Cache.MaxSize = size
	return b
}

// Build 构建授权管理器
func (b *AuthorizerBuilder) Build() (*Authorizer, error) {
	// 验证配置
	if err := b.validateConfig(); err != nil {
		return nil, err
	}

	// 创建授权管理器
	auth := &Authorizer{
		config:         b.config,
		currentVersion: b.config.Version,
		enterpriseID:   b.config.EnterpriseID,
		caCertPEM:      b.config.CACert,
		caKeyPEM:       b.config.CAKey,
	}

	// 创建吊销管理器
	rm, err := NewRevokeManager(b.config.Version)
	if err != nil {
		return nil, NewConfigError(ErrInvalidCAConfig, "failed to create revoke manager", err)
	}
	auth.revokeManager = rm

	// 初始化CA
	if err := auth.initCA(); err != nil {
		return nil, err
	}

	return auth, nil
}

// validateConfig 验证配置
func (b *AuthorizerBuilder) validateConfig() error {
	if b.config.Version == "" {
		return NewConfigError(ErrInvalidCAConfig, "version cannot be empty", nil)
	}

	if len(b.config.CACert) == 0 {
		return NewConfigError(ErrMissingCA, "CA certificate cannot be empty", nil)
	}

	if len(b.config.CAKey) == 0 {
		return NewConfigError(ErrMissingCA, "CA private key cannot be empty", nil)
	}

	if b.config.EnterpriseID <= 0 {
		return NewConfigError(ErrInvalidCAConfig, "enterprise ID must be positive", nil)
	}

	if b.config.Cache.MaxSize <= 0 {
		return NewConfigError(ErrInvalidCAConfig, "cache size must be positive", nil)
	}

	if b.config.Cache.TTL <= 0 {
		return NewConfigError(ErrInvalidCAConfig, "cache TTL must be positive", nil)
	}

	return nil
}

// 重新定义 Authorizer 结构体
type Authorizer struct {
	mu             sync.RWMutex
	config         AuthorizerConfig
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	caCertPEM      []byte
	caKeyPEM       []byte
	initialized    bool
	revokeManager  *RevokeManager
	currentVersion string
	enterpriseID   int
}

// 预设配置函数

// ForDevelopment 开发环境预设（完全禁用安全检查）
func ForDevelopment() *AuthorizerBuilder {
	return NewAuthorizer().
		WithVersion("dev").
		WithSecurityLevel(0). // 完全禁用安全检查
		WithMaxClockSkew(time.Hour).
		WithCacheTTL(1 * time.Minute).
		WithCacheSize(100)
}

// ForProduction 生产环境预设（基础安全检查）
func ForProduction() *AuthorizerBuilder {
	return NewAuthorizer().
		WithSecurityLevel(1). // 基础安全级别（仅简单调试器检测）
		EnableTimeValidation(true).
		RequireHardwareBinding(true).
		WithMaxClockSkew(30 * time.Second).
		WithCacheTTL(10 * time.Minute).
		WithCacheSize(5000)
}

// ForTesting 测试环境预设（禁用安全检查）
func ForTesting() *AuthorizerBuilder {
	return NewAuthorizer().
		WithVersion("test").
		WithSecurityLevel(0). // 禁用安全检查
		WithMaxClockSkew(24 * time.Hour).
		WithCacheTTL(10 * time.Second).
		WithCacheSize(50)
}

// UseDefaultCA 使用默认CA配置
func (b *AuthorizerBuilder) UseDefaultCA() *AuthorizerBuilder {
	return b.WithCA(defaultCACert, defaultCAKey)
}

// UseCustomCA 使用自定义CA配置
func (b *AuthorizerBuilder) UseCustomCA(cert, key []byte) *AuthorizerBuilder {
	return b.WithCA(cert, key)
}

// WithSecureDefaults 使用安全默认配置（高级安全级别）
func (b *AuthorizerBuilder) WithSecureDefaults() *AuthorizerBuilder {
	return b.
		WithSecurityLevel(2). // 高级安全级别
		EnableTimeValidation(true).
		RequireHardwareBinding(true).
		WithMaxClockSkew(1 * time.Minute)
}

// WithCriticalSecurity 使用关键安全配置（最高安全级别）
func (b *AuthorizerBuilder) WithCriticalSecurity() *AuthorizerBuilder {
	return b.
		WithSecurityLevel(3). // 关键安全级别
		EnableTimeValidation(true).
		RequireHardwareBinding(true).
		WithMaxClockSkew(30 * time.Second)
}

// DisableSecurity 完全禁用安全检查
func (b *AuthorizerBuilder) DisableSecurity() *AuthorizerBuilder {
	return b.WithSecurityLevel(0)
}

// WithBasicSecurity 使用基础安全配置
func (b *AuthorizerBuilder) WithBasicSecurity() *AuthorizerBuilder {
	return b.WithSecurityLevel(1)
}

// WithRelaxedSecurity 使用宽松安全配置（禁用安全检查）
func (b *AuthorizerBuilder) WithRelaxedSecurity() *AuthorizerBuilder {
	return b.
		WithSecurityLevel(0). // 禁用安全检查
		WithMaxClockSkew(24 * time.Hour)
}

// GetConfig 获取配置（用于调试和监控）
func (a *Authorizer) GetConfig() AuthorizerConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}
