package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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
	// currentCertVersion 当前证书格式版本
	currentCertVersion = "1.0.0"

	// 默认的内置CA证书和私钥
	defaultCACert = []byte(`-----BEGIN CERTIFICATE-----
MIIFoDCCA4igAwIBAgIIGBxYISs1axgwDQYJKoZIhvcNAQELBQAwbTELMAkGA1UE
BhMCQ04xEjAQBgNVBAgTCUd1YW5nZG9uZzESMBAGA1UEBxMJR3Vhbmd6aG91MRgw
FgYDVQQKDA/lrZDor7Tlt6XkvZzlrqQxHDAaBgNVBAMTE1pTdHVkaW8gU29mdHdh
cmUgQ0EwIBcNMjUwMTIwMDgwNzM1WhgPMjEyNDEyMjcwODA3MzVaMG0xCzAJBgNV
BAYTAkNOMRIwEAYDVQQIEwlHdWFuZ2RvbmcxEjAQBgNVBAcTCUd1YW5nemhvdTEY
MBYGA1UECgwP5a2Q6K+05bel5L2c5a6kMRwwGgYDVQQDExNaU3R1ZGlvIFNvZnR3
YXJlIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw17CSfhk2REC
1b5A0nmH04ho+/pyEIFB1u5DVISQWOIRWNquInIjb74XqLZIjRUptnp+C+KnN0vr
7RspSvrN3Y68l8quG9AK83WaiG6iifcutopYKQQeJRcmu2e5iC0OWult/nM6hb5T
0vR+FOyDNyz+AIcQpr9URCm772Xr59lp86W5sZxv+Uqxx76YUQVyEUPHJxwkLrDR
Mx2tP8uNFHun4UW5V8DWk4itLKc7oJMcnnTX0pEumRyYyA++gBW615g3h17fBNuU
MR8cos1JUremunoTUFdkZNYTzPSVN7Oq2S8W6xZFwRrYCYCpW150TI1BAhjBN1vj
WtkeGFWEAd4uUTjyr6fYwTfx7PKT/Z5iXAiIyXzMTukuiMjdyRCi/BVCIsMx7GJh
yfYEyjYdZgOHiMV/+hL5K4lmsCtHzEhkNOOmNhVlYaDpIhIZE/AZBvhYdHjUcc8G
JnxJMM5/eHHn4W0185BuXVy4e+3tRWnk2UH7vYhydNyy0U8NwIk01GIJZSMJFgbP
kHvYXtSsVSIh69YuY22hsVxA50EDkser4//YZu/qn+y1eB+jCSc++Ie+6EuWiSlY
3wkQainoFFecXtyVCs8mFW+/k7Nd48/j0tBM18RJ94al7uVX2JcXIPPpAUbXe7GF
zIAudbqrIuq9hTS573Y9CsiwhAw+dncCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgGG
MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFBS9Rp64gpZgceG0imEJLvXAvkmQ
MA0GCSqGSIb3DQEBCwUAA4ICAQCSLre1PdvmEm/yhKI4gK6Wo2bZZspSxaSjsdLN
026XnIBw5WFDpXdAWXO5IgKbPTJeAxxfK3ochEmPmzhUJUOj+HGLyHAW+yUBkQJ8
b8G55kuaaXgvw6l8BdRTvJRoTdVm+h5GNxnWypXw3dUTvvzhbSwMvUlMQJRYql1f
SID/y/6p3cy/EaoMJijFrfOM+6eRYZGT0OpQywqnYzAm6MCI+xSzu7veB09c9cg1
kwZ7MbMuLMFSdXQ2mM/OZUSxeBk/228rMaUADpnTrKqGmLYLH5348REj3R2GbYuN
we2fsH4/ZG7bM3ngyUjcLcxO1U1XVste7cCv9jSo7QBLcDy3/fHeJSxenpT4OmJJ
75ZhLsJsigfurgJUNsU+cJEfreZka8wI5YtGenSlYkY0SIXQbA3l92W/M67P+0Qi
lC+lLSkKOU773FuEZSgV+APDE43Okwx7lnYFFdcof7dIV5eW2Keb3EYTeXHcr5lJ
MGKxbJkFo32PZ67wKzvGktPPPmAuyLeHjj0xni8meNsL0qhIahuhqIxtKuZhUcUR
9FMfJAFX4bfDPEa5NgQtHdIxMuS8k0z3CRigjy2rxGb1PkGtsRIuXFC+hebAXNvY
zMYYzQteh2YszCfHi8O9jKMdiTpb/PNd1ydB9BT3SAGWkLKkfJlbp16KOodB9cnW
cDXyGQ==
-----END CERTIFICATE-----`)

	defaultCAKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
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
	currentCertVersion = version
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

	// 生成新的RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, NewSystemError(ErrSystemClockSkew, "failed to generate private key", err)
	}

	// 创建证书模板
	template := a.createCertificateTemplate(req, privateKey)

	// 添加扩展信息
	if err := a.addCertificateExtensions(template, req); err != nil {
		return nil, err
	}

	// 签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, a.caCert, &privateKey.PublicKey, a.caKey)
	if err != nil {
		return nil, NewCertificateError(ErrInvalidCertificate, "failed to create certificate", err)
	}

	return &Certificate{
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
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
				clientInfo.Version = versionInfo.MinRequiredVersion
				clientInfo.ValidityPeriodDays = versionInfo.MaxValidDays
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
	if a.currentVersion != "0.0.0" && a.currentVersion != "dev" && a.currentVersion != "test" {
		if versionInfo.MinRequiredVersion == "" {
			return NewValidationError(ErrInvalidVersion, "version information is missing in the certificate", nil)
		}

		// 验证版本格式
		if _, err := parse(versionInfo.MinRequiredVersion); err != nil {
			return NewValidationError(ErrInvalidVersion, "invalid version format in certificate", err).
				WithDetail("certificate_version", versionInfo.MinRequiredVersion)
		}

		// 比较版本
		ok, err := compare(a.currentVersion, "<", versionInfo.MinRequiredVersion)
		if err != nil {
			return NewValidationError(ErrInvalidVersion, "version comparison error", err).
				WithDetail("current_version", a.currentVersion).
				WithDetail("required_version", versionInfo.MinRequiredVersion)
		}
		if ok {
			return NewValidationError(ErrInvalidVersion, "program version is too old", nil).
				WithDetail("current_version", a.currentVersion).
				WithDetail("required_version", versionInfo.MinRequiredVersion).
				WithSuggestion("请更新程序到最新版本")
		}
	}

	// 证书格式版本检查
	if versionInfo.CertVersion != currentCertVersion {
		return NewCertificateError(ErrInvalidCertificate, "certificate format version mismatch", nil).
			WithDetail("certificate_version", versionInfo.CertVersion).
			WithDetail("current_version", currentCertVersion).
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
	if info.KeySize == 0 {
		info.KeySize = 4096
	}
	if info.ValidDays == 0 {
		info.ValidDays = 3650
	}

	// 生成RSA私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, info.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %v", err)
	}

	// 创建证书模板
	template := createCertificateTemplate(info, privateKey)

	// 自签名CA证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// 编码为PEM格式
	a.caCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	a.caKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
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

// GetCACertPEM 获取PEM格式的CA证书
func (a *Authorizer) GetCACertPEM() []byte {
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

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 尝试解析 PKCS8 格式
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("failed to parse CA private key: %v", err)
		}
		var ok bool
		key, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("CA private key is not RSA key")
		}
	}
	a.caKey = key

	a.initialized = true
	return nil
}

// createCertificateTemplate 创建证书模板
func createCertificateTemplate(info CAInfo, privateKey *rsa.PrivateKey) *x509.Certificate {
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
		SubjectKeyId:          generateSKI(&privateKey.PublicKey),
	}
}

// 生成主体密钥标识符(Subject Key Identifier)
func generateSKI(pubKey *rsa.PublicKey) []byte {
	// 使用公钥的SHA-1哈希作为SKI
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil
	}

	h := sha1.New()
	h.Write(pubKeyDER)
	return h.Sum(nil)
}

// createCertificateTemplate 创建证书模板
func (a *Authorizer) createCertificateTemplate(req *ClientCertRequest, _ *rsa.PrivateKey) *x509.Certificate {
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
		MinRequiredVersion: req.Technical.Version,
		CertVersion:        currentCertVersion,
		MaxValidDays:       req.Technical.ValidityPeriodDays,
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

	template.ExtraExtensions = extensions
	return nil
}
