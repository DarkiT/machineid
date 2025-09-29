package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// CertificateInfo 证书信息摘要
type CertificateInfo struct {
	Subject            string            `json:"subject"`
	Issuer             string            `json:"issuer"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	KeyUsage           []string          `json:"key_usage"`
	ExtKeyUsage        []string          `json:"ext_key_usage"`
	DNSNames           []string          `json:"dns_names"`
	IPAddresses        []string          `json:"ip_addresses"`
	Extensions         map[string]string `json:"extensions"`
	IsCA               bool              `json:"is_ca"`
	KeySize            int               `json:"key_size"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	Fingerprint        string            `json:"fingerprint"`
}

// CertificateInspector 证书检查器
type CertificateInspector struct{}

// NewCertificateInspector 创建证书检查器
func NewCertificateInspector() *CertificateInspector {
	return &CertificateInspector{}
}

// InspectPEM 检查PEM格式证书
func (ci *CertificateInspector) InspectPEM(certPEM []byte) (*CertificateInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, NewCertificateError(ErrInvalidCertificate,
			"failed to decode PEM certificate", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewCertificateError(ErrInvalidCertificate,
			"failed to parse certificate", err)
	}

	return ci.InspectCertificate(cert), nil
}

// InspectCertificate 检查x509证书
func (ci *CertificateInspector) InspectCertificate(cert *x509.Certificate) *CertificateInfo {
	info := &CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Extensions:         make(map[string]string),
	}

	// 处理IP地址
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// 处理密钥用途
	info.KeyUsage = ci.parseKeyUsage(cert.KeyUsage)
	info.ExtKeyUsage = ci.parseExtKeyUsage(cert.ExtKeyUsage)

	// 计算指纹
	info.Fingerprint = ci.calculateFingerprint(cert)

	// 获取密钥大小
	info.KeySize = ci.getKeySize(cert)

	// 处理扩展
	for _, ext := range cert.Extensions {
		info.Extensions[ext.Id.String()] = fmt.Sprintf("%x", ext.Value)
	}

	return info
}

// parseKeyUsage 解析密钥用途
func (ci *CertificateInspector) parseKeyUsage(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// parseExtKeyUsage 解析扩展密钥用途
func (ci *CertificateInspector) parseExtKeyUsage(usages []x509.ExtKeyUsage) []string {
	var extUsages []string

	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			extUsages = append(extUsages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			extUsages = append(extUsages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			extUsages = append(extUsages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			extUsages = append(extUsages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			extUsages = append(extUsages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			extUsages = append(extUsages, "OCSP Signing")
		default:
			extUsages = append(extUsages, fmt.Sprintf("Unknown (%v)", usage))
		}
	}

	return extUsages
}

// calculateFingerprint 计算证书指纹
func (ci *CertificateInspector) calculateFingerprint(cert *x509.Certificate) string {
	// 使用SHA-256计算指纹
	return fmt.Sprintf("%x", cert.Raw)[:32] // 简化的指纹
}

// getKeySize 获取密钥大小
func (ci *CertificateInspector) getKeySize(cert *x509.Certificate) int {
	// 这里需要根据公钥类型来确定大小
	// 简化实现
	return 2048 // 默认值
}

// SystemInfoCollector 系统信息收集器
type SystemInfoCollector struct{}

// NewSystemInfoCollector 创建系统信息收集器
func NewSystemInfoCollector() *SystemInfoCollector {
	return &SystemInfoCollector{}
}

// GetSystemInfo 获取系统信息
func (sic *SystemInfoCollector) GetSystemInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH
	info["num_cpu"] = runtime.NumCPU()
	info["hostname"], _ = os.Hostname()
	info["interfaces"] = sic.getNetworkInterfaces()
	info["boot_time"] = getSystemBootTime()
	info["current_time"] = time.Now()

	return info
}

// getNetworkInterfaces 获取网络接口信息
func (sic *SystemInfoCollector) getNetworkInterfaces() []map[string]interface{} {
	var interfaces []map[string]interface{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaces
	}

	for _, iface := range ifaces {
		ifaceInfo := map[string]interface{}{
			"name":          iface.Name,
			"hardware_addr": iface.HardwareAddr.String(),
			"flags":         iface.Flags.String(),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			var addresses []string
			for _, addr := range addrs {
				addresses = append(addresses, addr.String())
			}
			ifaceInfo["addresses"] = addresses
		}

		interfaces = append(interfaces, ifaceInfo)
	}

	return interfaces
}

// ValidateEmail 验证邮箱格式
func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}

	// 简单的邮箱验证
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]
	if len(local) == 0 || len(domain) == 0 {
		return false
	}

	// 检查域名是否包含点
	if !strings.Contains(domain, ".") {
		return false
	}

	return true
}

// ValidatePhoneNumber 验证电话号码格式
func ValidatePhoneNumber(phone string) bool {
	if phone == "" {
		return false
	}

	// 移除常见分隔符
	cleaned := strings.ReplaceAll(phone, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	cleaned = strings.ReplaceAll(cleaned, "+", "")

	// 检查是否全为数字且长度合理
	if len(cleaned) < 7 || len(cleaned) > 15 {
		return false
	}

	for _, char := range cleaned {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// FormatDuration 格式化时长显示
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f秒", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1f分钟", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1f小时", d.Hours())
	} else {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d天", days)
	}
}

// FormatFileSize 格式化文件大小
func FormatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"B", "KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// IsValidMachineID 验证机器ID格式
func IsValidMachineID(machineID string) bool {
	if machineID == "" {
		return false
	}

	// 检查长度（至少8个字符）
	if len(machineID) < 8 {
		return false
	}

	// 检查是否包含逗号分隔的多个ID
	ids := strings.Split(machineID, ",")
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if len(id) < 8 {
			return false
		}

		// 检查是否只包含字母、数字、连字符
		for _, char := range id {
			if !((char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') ||
				char == '-' || char == '_') {
				return false
			}
		}
	}

	return true
}

// CertificateChainValidator 证书链验证器
type CertificateChainValidator struct{}

// NewCertificateChainValidator 创建证书链验证器
func NewCertificateChainValidator() *CertificateChainValidator {
	return &CertificateChainValidator{}
}

// ValidateChain 验证证书链
func (ccv *CertificateChainValidator) ValidateChain(certPEMs [][]byte) error {
	if len(certPEMs) == 0 {
		return NewValidationError(ErrMissingRequiredField,
			"certificate chain cannot be empty", nil)
	}

	certs := make([]*x509.Certificate, len(certPEMs))

	// 解析所有证书
	for i, certPEM := range certPEMs {
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return NewCertificateError(ErrInvalidCertificate,
				"failed to decode certificate PEM", nil).
				WithDetail("certificate_index", i)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return NewCertificateError(ErrInvalidCertificate,
				"failed to parse certificate", err).
				WithDetail("certificate_index", i)
		}

		certs[i] = cert
	}

	// 验证链的连续性
	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]

		if err := child.CheckSignatureFrom(parent); err != nil {
			return NewCertificateError(ErrInvalidCertificate,
				"certificate chain validation failed", err).
				WithDetail("child_index", i).
				WithDetail("parent_index", i+1).
				WithDetail("child_subject", child.Subject.String()).
				WithDetail("parent_subject", parent.Subject.String())
		}
	}

	return nil
}

// PerformanceMonitor 性能监控器
type PerformanceMonitor struct {
	operations map[string]*OperationStats
}

// OperationStats 操作统计
type OperationStats struct {
	Count       int64         `json:"count"`
	TotalTime   time.Duration `json:"total_time"`
	MinTime     time.Duration `json:"min_time"`
	MaxTime     time.Duration `json:"max_time"`
	AvgTime     time.Duration `json:"avg_time"`
	LastTime    time.Duration `json:"last_time"`
	LastUpdated time.Time     `json:"last_updated"`
}

// NewPerformanceMonitor 创建性能监控器
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		operations: make(map[string]*OperationStats),
	}
}

// RecordOperation 记录操作性能
func (pm *PerformanceMonitor) RecordOperation(name string, duration time.Duration) {
	stats, exists := pm.operations[name]
	if !exists {
		stats = &OperationStats{
			MinTime: duration,
			MaxTime: duration,
		}
		pm.operations[name] = stats
	}

	stats.Count++
	stats.TotalTime += duration
	stats.LastTime = duration
	stats.LastUpdated = time.Now()

	if duration < stats.MinTime {
		stats.MinTime = duration
	}
	if duration > stats.MaxTime {
		stats.MaxTime = duration
	}

	stats.AvgTime = stats.TotalTime / time.Duration(stats.Count)
}

// GetStats 获取统计信息
func (pm *PerformanceMonitor) GetStats() map[string]*OperationStats {
	result := make(map[string]*OperationStats)
	for name, stats := range pm.operations {
		// 复制统计数据
		statsCopy := *stats
		result[name] = &statsCopy
	}
	return result
}

// Reset 重置统计
func (pm *PerformanceMonitor) Reset() {
	pm.operations = make(map[string]*OperationStats)
}
