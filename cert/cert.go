package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 默认企业标识符
const defaultEnterpriseID = 62996

// 定义包级变量
var (
	// defaultCertVersion 默认证书格式版本
	defaultCertVersion = "1.0.0"

	defaultCACert = []byte(`-----BEGIN CERTIFICATE-----
MIIBzjCCAYCgAwIBAgIIGIG9ZoHvfOgwBQYDK2VwMGoxCzAJBgNVBAYTAkNOMRIw
EAYDVQQIEwlHdWFuZ2RvbmcxEjAQBgNVBAcTCUd1YW5nemhvdTEYMBYGA1UECgwP
5a2Q6K+05bel5L2c5a6kMRkwFwYDVQQDExBaU3R1ZGlvIFNvZnR3YXJlMCAXDTI1
MTIxNjE1NTkzNloYDzIxMjUxMTIyMTU1OTM2WjBqMQswCQYDVQQGEwJDTjESMBAG
A1UECBMJR3Vhbmdkb25nMRIwEAYDVQQHEwlHdWFuZ3pob3UxGDAWBgNVBAoMD+Wt
kOivtOW3peS9nOWupDEZMBcGA1UEAxMQWlN0dWRpbyBTb2Z0d2FyZTAqMAUGAytl
cAMhANd2vylnZ+HNmrtc9BiJzMqf06uuLFALFnJd9omGE3Vno0IwQDAOBgNVHQ8B
Af8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUvMcU5fbpAYu7i2LZ
SDdY/KP1xhwwBQYDK2VwA0EAOb/HhW7RntRIdqH8kneJRV0wnhsSWKMdiY2cDEEe
FNhRWm+Z+MnJgYdbwDJ5nAI8C5L6hUXVPpn9occfyBcjCQ==
-----END CERTIFICATE-----`)

	defaultCAKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILGtcOPZc6Lsro1OvVDb/P65tRAB6PjuWPRwtLScm+Cf
-----END PRIVATE KEY-----`)
)

// New 创建新的授权管理器（向后兼容）
// Deprecated: 使用 NewAuthorizer().Build() 代替
func New(opts ...func(*Authorizer) error) (*Authorizer, error) {
	// 兼容旧API，但使用新的构建器
	builder := NewAuthorizer()

	// 应用旧的选项（这里可以添加转换逻辑）
	auth, err := builder.Build()
	if err != nil {
		return nil, err
	}

	// 应用旧选项
	for _, opt := range opts {
		if err := opt(auth); err != nil {
			return nil, err
		}
	}

	return auth, nil
}

// SetCurrentCertVersion 设置当前证书格式版本
func (a *Authorizer) SetCurrentCertVersion(version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.certVersion = version
}

// GetCurrentCertVersion 获取当前证书格式版本
func (a *Authorizer) GetCurrentCertVersion() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.certVersion == "" {
		return defaultCertVersion
	}
	return a.certVersion
}

// getOID 生成指定用途的 OID
func (a *Authorizer) getOID(purpose int) asn1.ObjectIdentifier {
	enterpriseID := a.enterpriseID
	if enterpriseID == 0 {
		enterpriseID = defaultEnterpriseID
	}
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, enterpriseID, 1, purpose}
}

// IssueClientCert 签发客户端证书
func (a *Authorizer) IssueClientCert(req *ClientCertRequest) (*Certificate, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.initialized {
		return nil, NewConfigError(ErrMissingCA, "authorizer not initialized", nil)
	}

	// 验证请求
	if err := req.Validate(); err != nil {
		return nil, NewValidationError(ErrInvalidVersion, "invalid client certificate request", err)
	}

	// 应用默认值
	req.SetDefaults()

	// 生成新的客户端密钥对：
	// - 切换为 Ed25519，避免 RSA keygen 在部分运行时/实验 GC 下的稳定性问题
	// - 不改变现有证书扩展/校验逻辑（机器码、版本、绑定信息等均不依赖密钥算法）
	// - KeyPEM 继续返回 PEM，改为 PKCS#8（标准且适配 Ed25519）
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, NewSystemError(ErrSystemClockSkew, "failed to generate private key", err)
	}

	// 创建证书模板
	template := a.createCertificateTemplate(req, nil)

	// 添加扩展信息
	if err := a.addCertificateExtensions(template, req); err != nil {
		return nil, err
	}

	// 签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, a.caCert, publicKey, a.caKey)
	if err != nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to create certificate", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, NewSystemError(ErrSystemClockSkew, "failed to marshal private key", err)
	}

	return &Certificate{
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		MachineID: req.Identity.MachineID,
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
	}, nil
}

// ValidateCert 验证客户端证书
func (a *Authorizer) ValidateCert(certPEM []byte, machineID string) error {
	// 执行完整的安全检查（如果启用）
	if err := a.PerformSecurityCheck(); err != nil {
		return err
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.initialized {
		return NewConfigError(ErrMissingCA, "authorizer not initialized", nil)
	}

	// 解析证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return NewCertificateError(ErrInvalidCertificate, "failed to decode certificate PEM", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return NewCertificateError(ErrInvalidCertificate, "failed to parse certificate", err)
	}

	// 验证证书链
	roots := x509.NewCertPool()
	roots.AddCert(a.caCert)

	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err = cert.Verify(opts); err != nil {
		return NewCertificateError(ErrInvalidCertificate, "certificate verification failed", err)
	}

	// 检查证书有效性
	if err = a.validateCertificateValidity(cert); err != nil {
		return err
	}

	// 检查版本信息
	if err = a.validateVersionInfo(cert); err != nil {
		return err
	}

	// 验证机器ID
	if err = a.validateMachineID(cert, machineID); err != nil {
		return err
	}

	return nil
}

// ExtractClientInfo 从证书中提取客户信息
func (a *Authorizer) ExtractClientInfo(certPEM []byte) (*ClientInfo, error) {
	// 解析证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to decode certificate PEM", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to parse certificate", err)
	}

	clientInfo := &ClientInfo{
		// 从证书基本信息中提取
		ExpiryDate: cert.NotAfter,
	}

	// 从证书主题中提取公司信息
	if len(cert.Subject.Organization) > 0 {
		clientInfo.CompanyName = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		clientInfo.Department = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Country) > 0 {
		clientInfo.Country = cert.Subject.Country[0]
	}
	if len(cert.Subject.Province) > 0 {
		clientInfo.Province = cert.Subject.Province[0]
	}
	if len(cert.Subject.Locality) > 0 {
		clientInfo.City = cert.Subject.Locality[0]
	}

	// 从扩展字段中提取详细信息
	for _, ext := range cert.Extensions {
		// 提取机器ID (OID: 1)
		if ext.Id.Equal(a.getOID(1)) {
			var machineID string
			if _, err := asn1.Unmarshal(ext.Value, &machineID); err == nil {
				clientInfo.MachineID = machineID
			}
		}

		// 提取联系信息 (OID: 2)
		if ext.Id.Equal(a.getOID(2)) {
			var contact Contact
			if _, err := asn1.Unmarshal(ext.Value, &contact); err == nil {
				clientInfo.ContactPerson = contact.Person
				clientInfo.ContactPhone = contact.Phone
				clientInfo.ContactEmail = contact.Email
			}
		}

		// 提取版本信息 (OID: 3)
		if ext.Id.Equal(a.getOID(3)) {
			var versionInfo VersionInfo
			if _, err := asn1.Unmarshal(ext.Value, &versionInfo); err == nil {
				clientInfo.MinClientVersion = versionInfo.MinClientVersion
				clientInfo.ValidityPeriodDays = versionInfo.MaxValidDays
			}
		}

		// 提取绑定信息 (OID: 4)
		if ext.Id.Equal(a.getOID(4)) {
			var bindingInfo BindingInfo
			if _, err := asn1.Unmarshal(ext.Value, &bindingInfo); err == nil {
				clientInfo.BindingMode = bindingInfo.Mode
				clientInfo.BindingProvider = bindingInfo.Provider
			}
		}
	}

	return clientInfo, nil
}

// validateCertificateValidity 检查证书的有效期
func (a *Authorizer) validateCertificateValidity(cert *x509.Certificate) error {
	now := time.Now()

	// 时间验证
	if a.config.Security.EnableTimeValidation {
		bootTime := getSystemBootTime()

		// 如果当前时间早于系统启动时间，说明系统时间被篡改
		if now.Before(bootTime) {
			return NewSecurityError(ErrTimeManipulation, "system time appears to be manipulated", nil).
				WithDetail("current_time", now).
				WithDetail("boot_time", bootTime)
		}

		// 检查时钟偏差
		if a.config.Security.MaxClockSkew > 0 {
			// 这里可以与网络时间服务器对比，简化实现假设系统时间准确
			maxSkew := a.config.Security.MaxClockSkew
			if now.Before(cert.NotBefore.Add(-maxSkew)) || now.After(cert.NotAfter.Add(maxSkew)) {
				return NewSecurityError(ErrSystemClockSkew, "certificate time validation failed with clock skew check", nil).
					WithDetail("current_time", now).
					WithDetail("cert_not_before", cert.NotBefore).
					WithDetail("cert_not_after", cert.NotAfter).
					WithDetail("max_skew", maxSkew)
			}
		}
	}

	// 检查证书基本有效期
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return NewCertificateError(ErrExpiredCertificate, "certificate is not valid at current time", nil).
			WithDetail("current_time", now).
			WithDetail("cert_not_before", cert.NotBefore).
			WithDetail("cert_not_after", cert.NotAfter)
	}

	// 检查证书是否被吊销
	if revoked, reason := a.revokeManager.IsRevoked(cert.SerialNumber.String()); revoked {
		return NewSecurityError(ErrCertificateRevoked, "certificate has been revoked", nil).
			WithDetail("serial_number", cert.SerialNumber.String()).
			WithDetail("revoke_reason", reason)
	}

	return nil
}

// validateVersionInfo 检查版本信息
func (a *Authorizer) validateVersionInfo(cert *x509.Certificate) error {
	var versionInfo VersionInfo
	found := false

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(a.getOID(3)) {
			if _, err := asn1.Unmarshal(ext.Value, &versionInfo); err != nil {
				return NewCertificateError(ErrInvalidCertificate, "failed to unmarshal version info", err)
			}
			found = true
			break
		}
	}

	if !found {
		return NewValidationError(ErrMissingRequiredField, "version information extension not found in certificate", nil)
	}

	// 检查程序版本是否满足要求
	if a.runtimeVersion != "" && a.runtimeVersion != "0.0.0" && a.runtimeVersion != "dev" && a.runtimeVersion != "test" {
		if versionInfo.MinClientVersion == "" {
			return NewValidationError(ErrInvalidVersion, "version information is missing in the certificate", nil)
		}

		// 验证版本格式
		if _, err := parse(versionInfo.MinClientVersion); err != nil {
			return NewValidationError(ErrInvalidVersion, "invalid version format in certificate", err).
				WithDetail("certificate_min_client_version", versionInfo.MinClientVersion)
		}

		// 比较版本
		ok, err := compare(a.runtimeVersion, "<", versionInfo.MinClientVersion)
		if err != nil {
			return NewValidationError(ErrInvalidVersion, "version comparison error", err).
				WithDetail("runtime_version", a.runtimeVersion).
				WithDetail("required_min_client_version", versionInfo.MinClientVersion)
		}
		if ok {
			return NewValidationError(ErrInvalidVersion, "program version is too old", nil).
				WithDetail("runtime_version", a.runtimeVersion).
				WithDetail("required_min_client_version", versionInfo.MinClientVersion).
				WithSuggestion("请更新程序到最新版本")
		}
	}

	// 证书格式版本检查
	expectedVersion := a.GetCurrentCertVersion()
	if versionInfo.LicenseSchemaVersion != expectedVersion {
		return NewCertificateError(ErrInvalidCertificate, "certificate format version mismatch", nil).
			WithDetail("certificate_version", versionInfo.LicenseSchemaVersion).
			WithDetail("current_version", expectedVersion).
			WithSuggestion("请使用匹配的证书格式版本")
	}

	// 检查证书是否超过最大有效期
	if versionInfo.MaxValidDays > 0 {
		maxValidDuration := time.Duration(versionInfo.MaxValidDays) * 24 * time.Hour
		if time.Since(cert.NotBefore) > maxValidDuration {
			return NewCertificateError(ErrExpiredCertificate, "certificate has exceeded maximum valid duration", nil).
				WithDetail("cert_age", time.Since(cert.NotBefore)).
				WithDetail("max_valid_duration", maxValidDuration)
		}
	}

	return nil
}

// validateMachineID 验证机器ID
func (a *Authorizer) validateMachineID(cert *x509.Certificate, machineID string) error {
	if machineID == "" {
		return NewValidationError(ErrInvalidMachineID, "machine ID cannot be empty", nil)
	}

	// 查找机器ID扩展
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(a.getOID(1)) {
			var certMachineID string
			if _, err := asn1.Unmarshal(ext.Value, &certMachineID); err != nil {
				return NewCertificateError(ErrInvalidCertificate, "failed to unmarshal machine ID from certificate", err)
			}

			// 分割证书中的机器码列表并验证
			authorizedIDs := strings.Split(strings.TrimSpace(certMachineID), ",")
			for _, id := range authorizedIDs {
				if strings.TrimSpace(id) == machineID {
					return nil // 找到匹配的机器ID
				}
			}

			// 未找到匹配的机器ID
			return NewSecurityError(ErrUnauthorizedAccess, "machine ID not authorized for this certificate", nil).
				WithDetail("provided_machine_id", machineID).
				WithDetail("authorized_machine_ids", authorizedIDs).
				WithSuggestion("确认机器码是否正确，或联系管理员重新签发证书")
		}
	}

	return NewCertificateError(ErrInvalidCertificate, "machine ID extension not found in certificate", nil)
}

// GenerateCA 生成新的CA证书和私钥，并更新授权管理器
func (a *Authorizer) GenerateCA(info CAInfo) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 设置默认值
	if info.ValidDays == 0 {
		info.ValidDays = 3650
	}

	// 生成 Ed25519 私钥
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %v", err)
	}

	// 创建证书模板
	template := createCertificateTemplate(info)

	// 自签名CA证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// 编码为PEM格式
	a.caCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %v", err)
	}
	a.caKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	// 更新授权管理器的证书和私钥
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %v", err)
	}

	a.caCert = cert
	a.caKey = privateKey
	a.initialized = true

	return nil
}

// SaveCA 保存CA证书到指定目录，如果不指定目录则使用当前工作目录
func (a *Authorizer) SaveCA(dirPath ...string) error {
	// 获取保存目录
	saveDir := "." // 默认为当前目录
	if len(dirPath) > 0 && dirPath[0] != "" {
		saveDir = dirPath[0]
	}

	// 创建目录（如果不存在）
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// 构建文件路径
	certPath := filepath.Join(saveDir, "ca.crt")
	keyPath := filepath.Join(saveDir, "ca.key")

	// 保存证书
	if err := os.WriteFile(certPath, a.caCertPEM, 0o644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %v", err)
	}

	// 保存私钥
	if err := os.WriteFile(keyPath, a.caKeyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to save CA private key: %v", err)
	}

	return nil
}

// SaveClientCert 保存客户端证书到指定目录，如果不指定目录则使用当前工作目录
// 证书文件格式：{机器码}-{生效时间}-{结束时间}.crt
func (a *Authorizer) SaveClientCert(cert *Certificate, dirPath ...string) error {
	// 获取保存目录
	saveDir := "." // 默认为当前目录
	if len(dirPath) > 0 && dirPath[0] != "" {
		saveDir = dirPath[0]
	}

	// 创建目录（如果不存在）
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// 格式化时间，使用紧凑格式 (YYYYMMDD)
	startTime := cert.NotBefore.Format("20060102")
	endTime := cert.NotAfter.Format("20060102")

	// 构建文件名
	certFileName := fmt.Sprintf("%s-%s-%s.crt", cert.MachineID, startTime, endTime)
	// keyFileName := fmt.Sprintf("%s-%s-%s.key", cert.MachineID, startTime, endTime)

	// 构建完整路径
	certPath := filepath.Join(saveDir, certFileName)
	// keyPath := filepath.Join(saveDir, keyFileName)

	// 保存证书
	if err := os.WriteFile(certPath, cert.CertPEM, 0o644); err != nil {
		return fmt.Errorf("failed to save client certificate: %v", err)
	}

	// 保存私钥
	//if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
	//	return fmt.Errorf("failed to save client private key: %v", err)
	//}

	return nil
}

// CACertPEM 获取PEM格式的CA证书
func (a *Authorizer) CACertPEM() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.caCertPEM
}

// initCA 初始化CA证书和私钥
func (a *Authorizer) initCA() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 解析CA证书
	block, _ := pem.Decode(a.caCertPEM)
	if block == nil {
		return errors.New("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}
	a.caCert = cert

	// 解析CA私钥
	block, _ = pem.Decode(a.caKeyPEM)
	if block == nil {
		return errors.New("failed to decode CA private key PEM")
	}

	// 只支持 PKCS#8（Ed25519 / ECDSA / RSA 等都可用，但本包默认 Ed25519）
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %v", err)
	}
	a.caKey = key

	a.initialized = true
	return nil
}

// createCertificateTemplate 创建证书模板
func createCertificateTemplate(info CAInfo) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   info.CommonName,
			Organization: []string{info.Organization},
			Country:      []string{info.Country},
			Province:     []string{info.Province},
			Locality:     []string{info.Locality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, info.ValidDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		// SubjectKeyId 可选；这里不做 RSA-specific 的 SKI 计算，避免引入 sha1/rsa 依赖。
	}
}

// createCertificateTemplate 创建证书模板
func (a *Authorizer) createCertificateTemplate(req *ClientCertRequest, _ any) *x509.Certificate {
	// 构建主体信息
	subject := pkix.Name{
		CommonName:   req.Company.Name,
		Organization: []string{req.Company.Name},
	}

	if req.Company.Department != "" {
		subject.OrganizationalUnit = []string{req.Company.Department}
	}

	if req.Company.Address != nil {
		if req.Company.Address.Country != "" {
			subject.Country = []string{req.Company.Address.Country}
		}
		if req.Company.Address.Province != "" {
			subject.Province = []string{req.Company.Address.Province}
		}
		if req.Company.Address.City != "" {
			subject.Locality = []string{req.Company.Address.City}
		}
		if req.Company.Address.Street != "" {
			subject.StreetAddress = []string{req.Company.Address.Street}
		}
	}

	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              req.Identity.ExpiryDate,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
}

// addCertificateExtensions 添加证书扩展
func (a *Authorizer) addCertificateExtensions(template *x509.Certificate, req *ClientCertRequest) error {
	var extensions []pkix.Extension

	// 添加机器码扩展
	machineIDValue, err := asn1.Marshal(req.Identity.MachineID)
	if err != nil {
		return NewCertificateError(ErrInvalidCertificate, "failed to marshal machine ID", err)
	}
	extensions = append(extensions, pkix.Extension{
		Id:       a.getOID(1), // 1: machineID
		Critical: false,
		Value:    machineIDValue,
	})

	// 添加联系信息扩展（如果提供）
	if req.Contact != nil {
		// 直接存储结构化的联系信息
		contactValue, err := asn1.Marshal(*req.Contact)
		if err != nil {
			return NewCertificateError(ErrInvalidCertificate, "failed to marshal contact info", err)
		}
		extensions = append(extensions, pkix.Extension{
			Id:       a.getOID(2), // 2: contact
			Critical: false,
			Value:    contactValue,
		})
	}

	// 添加版本信息扩展
	versionInfo := VersionInfo{
		MinClientVersion:     req.Technical.MinClientVersion,
		LicenseSchemaVersion: a.GetCurrentCertVersion(),
		MaxValidDays:         req.Technical.ValidityPeriodDays,
	}
	versionValue, err := asn1.Marshal(versionInfo)
	if err != nil {
		return NewCertificateError(ErrInvalidCertificate, "failed to marshal version info", err)
	}
	extensions = append(extensions, pkix.Extension{
		Id:       a.getOID(3), // 3: version
		Critical: false,
		Value:    versionValue,
	})

	if extensions, err = a.appendBindingExtension(extensions, req); err != nil {
		return err
	}
	template.ExtraExtensions = extensions
	return nil
}

func (a *Authorizer) appendBindingExtension(extensions []pkix.Extension, req *ClientCertRequest) ([]pkix.Extension, error) {
	if req.Identity == nil {
		return extensions, nil
	}
	if req.Identity.BindingMode == "" && req.Identity.BindingProvider == "" {
		return extensions, nil
	}
	bindingValue, err := asn1.Marshal(BindingInfo{
		Mode:     req.Identity.BindingMode,
		Provider: req.Identity.BindingProvider,
	})
	if err != nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to marshal binding info", err)
	}
	return append(extensions, pkix.Extension{
		Id:       a.getOID(4),
		Critical: false,
		Value:    bindingValue,
	}), nil
}
