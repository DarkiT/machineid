package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

// Authorization 统一授权接口
// 提供证书和 License 的统一访问方式
type Authorization interface {
	// Type 返回授权类型
	Type() AuthorizationType

	// Validate 验证授权（包含机器码验证）
	Validate(machineID string) error

	// HasModule 检查是否有模块权限
	HasModule(name string) bool

	// GetModuleQuota 获取模块配额（0=无限制）
	GetModuleQuota(name string) int

	// ValidateModule 验证模块权限（权限+时间）
	ValidateModule(name string) error

	// GetMeta 获取元数据
	GetMeta(key string) string

	// ExpiresAt 返回过期时间
	ExpiresAt() time.Time

	// MachineIDs 返回授权的机器码列表
	MachineIDs() []string
}

// AuthorizationType 授权类型
type AuthorizationType string

const (
	AuthTypeCertificate AuthorizationType = "certificate"
	AuthTypeLicense     AuthorizationType = "license"
)

// CertAuthorization 证书授权实现
type CertAuthorization struct {
	cert       *x509.Certificate
	certPEM    []byte
	features   *FeaturesInfo
	machineID  string
	authorizer *Authorizer
}

// NewCertAuthorization 从证书 PEM 创建授权对象
func NewCertAuthorization(certPEM []byte, authorizer *Authorizer) (*CertAuthorization, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to decode certificate PEM", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to parse certificate", err)
	}

	auth := &CertAuthorization{
		cert:       cert,
		certPEM:    certPEM,
		authorizer: authorizer,
	}

	// 提取模块权限
	if authorizer != nil {
		auth.features, _ = authorizer.extractFeaturesFromCert(cert)
		// 提取机器码
		auth.machineID = auth.extractMachineID()
	}

	return auth, nil
}

// Type 返回授权类型
func (a *CertAuthorization) Type() AuthorizationType {
	return AuthTypeCertificate
}

// Validate 验证授权
func (a *CertAuthorization) Validate(machineID string) error {
	if a.authorizer == nil {
		return NewConfigError(ErrMissingCA, "authorizer not set", nil)
	}
	return a.authorizer.ValidateCert(a.certPEM, machineID)
}

// HasModule 检查是否有模块权限
func (a *CertAuthorization) HasModule(name string) bool {
	if a.features == nil {
		return false
	}
	return a.features.HasModule(name)
}

// GetModuleQuota 获取模块配额
func (a *CertAuthorization) GetModuleQuota(name string) int {
	if a.features == nil {
		return 0
	}
	module := a.features.GetModule(name)
	if module == nil {
		return 0
	}
	return module.Quota
}

// ValidateModule 验证模块权限
func (a *CertAuthorization) ValidateModule(name string) error {
	if a.features == nil {
		return NewValidationError(ErrModuleNotAuthorized, "no module authorization in certificate", nil).
			WithDetail("module", name)
	}
	return a.features.ValidateModule(name, time.Now())
}

// GetMeta 获取元数据（证书不支持，返回空）
func (a *CertAuthorization) GetMeta(_ string) string {
	return ""
}

// ExpiresAt 返回过期时间
func (a *CertAuthorization) ExpiresAt() time.Time {
	return a.cert.NotAfter
}

// MachineIDs 返回授权的机器码列表
func (a *CertAuthorization) MachineIDs() []string {
	if a.machineID == "" {
		return nil
	}
	return splitCSV(a.machineID)
}

// extractMachineID 从证书中提取机器码
func (a *CertAuthorization) extractMachineID() string {
	if a.authorizer == nil {
		return ""
	}
	for _, ext := range a.cert.Extensions {
		if ext.Id.Equal(a.authorizer.getOID(1)) {
			var machineID string
			if _, err := asn1Unmarshal(ext.Value, &machineID); err == nil {
				return machineID
			}
		}
	}
	return ""
}

// Certificate 返回底层证书
func (a *CertAuthorization) Certificate() *x509.Certificate {
	return a.cert
}

// Features 返回模块权限信息
func (a *CertAuthorization) Features() *FeaturesInfo {
	return a.features
}

// LicenseAuthorization License 授权实现
type LicenseAuthorization struct {
	payload   *LicensePayload
	publicKey ed25519.PublicKey
}

// NewLicenseAuthorization 从 License payload 创建授权对象
func NewLicenseAuthorization(payload *LicensePayload, publicKey ed25519.PublicKey) *LicenseAuthorization {
	return &LicenseAuthorization{
		payload:   payload,
		publicKey: publicKey,
	}
}

// Type 返回授权类型
func (a *LicenseAuthorization) Type() AuthorizationType {
	return AuthTypeLicense
}

// Validate 验证授权
func (a *LicenseAuthorization) Validate(machineID string) error {
	return a.payload.validate(time.Now(), machineID)
}

// HasModule 检查是否有模块权限
func (a *LicenseAuthorization) HasModule(name string) bool {
	config, ok := a.payload.GetModuleConfig(name)
	if !ok {
		return false
	}
	return config.Enabled
}

// GetModuleQuota 获取模块配额
func (a *LicenseAuthorization) GetModuleQuota(name string) int {
	config, ok := a.payload.GetModuleConfig(name)
	if !ok {
		return 0
	}
	return config.Quota
}

// ValidateModule 验证模块权限
func (a *LicenseAuthorization) ValidateModule(name string) error {
	return a.payload.ValidateModuleAccess(name, time.Now())
}

// GetMeta 获取元数据
func (a *LicenseAuthorization) GetMeta(key string) string {
	if a.payload.Meta == nil {
		return ""
	}
	return a.payload.Meta[key]
}

// ExpiresAt 返回过期时间
func (a *LicenseAuthorization) ExpiresAt() time.Time {
	return a.payload.NotAfter
}

// MachineIDs 返回授权的机器码列表
func (a *LicenseAuthorization) MachineIDs() []string {
	if a.payload.MachineID == "" {
		return nil
	}
	return splitCSV(a.payload.MachineID)
}

// Payload 返回底层 License payload
func (a *LicenseAuthorization) Payload() *LicensePayload {
	return a.payload
}

// HasFeature 检查是否有功能（支持点分路径）
func (a *LicenseAuthorization) HasFeature(path string) bool {
	return a.payload.HasFeature(path)
}

// GetFeatureValue 获取功能值
func (a *LicenseAuthorization) GetFeatureValue(path string) (any, bool) {
	return a.payload.GetFeatureValue(path)
}

// ParseAuthorization 解析授权数据（自动识别证书或 License）
func (a *Authorizer) ParseAuthorization(data []byte, publicKey ed25519.PublicKey) (Authorization, error) {
	// 尝试解析为证书
	if isCertificatePEM(data) {
		return NewCertAuthorization(data, a)
	}

	// 尝试解析为 License JSON
	if isLicenseJSON(data) {
		payload, err := ValidateLicenseJSON(data, publicKey, "", time.Now())
		if err != nil {
			return nil, err
		}
		return NewLicenseAuthorization(payload, publicKey), nil
	}

	return nil, NewValidationError(ErrInvalidRequest, "unrecognized authorization format", nil)
}

// ValidateWithModules 带模块验证的完整验证
func (a *Authorizer) ValidateWithModules(data []byte, machineID string, requiredModules []string, publicKey ed25519.PublicKey) error {
	auth, err := a.ParseAuthorization(data, publicKey)
	if err != nil {
		return err
	}

	// 验证基础授权
	if err := auth.Validate(machineID); err != nil {
		return err
	}

	// 验证所有必需模块
	for _, module := range requiredModules {
		if err := auth.ValidateModule(module); err != nil {
			return err
		}
	}

	return nil
}

// isCertificatePEM 检查数据是否为证书 PEM 格式
func isCertificatePEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----"))
}

// isLicenseJSON 检查数据是否为 License JSON 格式
func isLicenseJSON(data []byte) bool {
	// 简单检查是否包含 License 特征字段
	return bytes.Contains(data, []byte(`"payload"`)) && bytes.Contains(data, []byte(`"signature"`))
}

// asn1Unmarshal 是 encoding/asn1.Unmarshal 的包装
func asn1Unmarshal(data []byte, val any) ([]byte, error) {
	return asn1UnmarshalReal(data, val)
}

// asn1UnmarshalReal 实际的 ASN.1 解码实现
func asn1UnmarshalReal(data []byte, val any) ([]byte, error) {
	return asn1.Unmarshal(data, val)
}
