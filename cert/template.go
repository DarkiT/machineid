package cert

import (
	"crypto/x509"
	"time"
)

// CertTemplate 证书模板
type CertTemplate struct {
	Name             string                // 模板名称
	Description      string                // 模板描述
	ValidityDays     int                   // 有效期天数
	KeyUsages        []x509.KeyUsage       // 密钥用途
	ExtKeyUsages     []x509.ExtKeyUsage    // 扩展密钥用途
	CustomExtensions map[string]string     // 自定义扩展
	SecurityLevel    TemplateSecurityLevel // 安全级别
	RequiredFields   []string              // 必填字段
	OptionalFields   []string              // 可选字段
}

// TemplateSecurityLevel 模板安全级别
type TemplateSecurityLevel int

const (
	TemplateSecurityLevelLow TemplateSecurityLevel = iota
	TemplateSecurityLevelMedium
	TemplateSecurityLevelHigh
	TemplateSecurityLevelCritical
)

// TemplateManager 模板管理器
type TemplateManager struct {
	templates map[string]*CertTemplate
}

// NewTemplateManager 创建模板管理器
func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]*CertTemplate),
	}
	tm.loadDefaultTemplates()
	return tm
}

// loadDefaultTemplates 加载默认模板
func (tm *TemplateManager) loadDefaultTemplates() {
	// 标准客户端证书模板
	tm.templates["client"] = &CertTemplate{
		Name:           "标准客户端证书",
		Description:    "适用于一般客户端认证的证书模板",
		ValidityDays:   365,
		KeyUsages:      []x509.KeyUsage{x509.KeyUsageDigitalSignature},
		ExtKeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SecurityLevel:  TemplateSecurityLevelMedium,
		RequiredFields: []string{"MachineID", "CompanyName", "MinClientVersion"},
		OptionalFields: []string{"ContactPerson", "ContactEmail", "Department"},
	}

	// 长期客户端证书模板
	tm.templates["client-long"] = &CertTemplate{
		Name:           "长期客户端证书",
		Description:    "适用于长期使用的客户端证书模板",
		ValidityDays:   1095, // 3年
		KeyUsages:      []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment},
		ExtKeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SecurityLevel:  TemplateSecurityLevelHigh,
		RequiredFields: []string{"MachineID", "CompanyName", "MinClientVersion", "ContactPerson", "ContactEmail"},
		OptionalFields: []string{"Department", "ContactPhone"},
	}

	// 试用版证书模板
	tm.templates["trial"] = &CertTemplate{
		Name:           "试用版证书",
		Description:    "适用于试用期间的短期证书模板",
		ValidityDays:   30,
		KeyUsages:      []x509.KeyUsage{x509.KeyUsageDigitalSignature},
		ExtKeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SecurityLevel:  TemplateSecurityLevelLow,
		RequiredFields: []string{"MachineID", "CompanyName"},
		OptionalFields: []string{"ContactEmail", "MinClientVersion"},
	}

	// 企业级证书模板
	tm.templates["enterprise"] = &CertTemplate{
		Name:         "企业级证书",
		Description:  "适用于企业级应用的高安全证书模板",
		ValidityDays: 730, // 2年
		KeyUsages: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
			x509.KeyUsageDataEncipherment,
		},
		ExtKeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
		},
		SecurityLevel: TemplateSecurityLevelCritical,
		RequiredFields: []string{
			"MachineID", "CompanyName", "Department", "ContactPerson",
			"ContactEmail", "ContactPhone", "MinClientVersion", "Country", "Province", "City",
		},
		OptionalFields: []string{"Address"},
	}
}

// Template 获取模板
func (tm *TemplateManager) Template(name string) (*CertTemplate, error) {
	template, exists := tm.templates[name]
	if !exists {
		return nil, NewValidationError(ErrMissingRequiredField,
			"certificate template not found", nil).
			WithDetail("template_name", name).
			WithSuggestion("可用模板: client, client-long, trial, enterprise")
	}
	return template, nil
}

// AddTemplate 添加自定义模板
func (tm *TemplateManager) AddTemplate(name string, template *CertTemplate) error {
	if name == "" {
		return NewValidationError(ErrMissingRequiredField,
			"template name cannot be empty", nil)
	}

	if template == nil {
		return NewValidationError(ErrMissingRequiredField,
			"template cannot be nil", nil)
	}

	tm.templates[name] = template
	return nil
}

// ListTemplates 列出所有可用模板
func (tm *TemplateManager) ListTemplates() map[string]*CertTemplate {
	result := make(map[string]*CertTemplate)
	for name, template := range tm.templates {
		result[name] = template
	}
	return result
}

// ValidateRequestWithTemplate 使用模板验证请求
func (tm *TemplateManager) ValidateRequestWithTemplate(req *ClientCertRequest, templateName string) error {
	template, err := tm.Template(templateName)
	if err != nil {
		return err
	}

	return tm.validateRequest(req, template)
}

// validateRequest 验证请求是否符合模板要求
func (tm *TemplateManager) validateRequest(req *ClientCertRequest, template *CertTemplate) error {
	// 验证必填字段
	for _, field := range template.RequiredFields {
		if err := tm.validateRequiredField(req, field); err != nil {
			return err
		}
	}

	// 应用模板安全级别要求
	if err := tm.validateSecurityLevel(req, template.SecurityLevel); err != nil {
		return err
	}

	return nil
}

// validateRequiredField 验证必填字段
func (tm *TemplateManager) validateRequiredField(req *ClientCertRequest, field string) error {
	switch field {
	case "MachineID":
		if req.Identity == nil || req.Identity.MachineID == "" {
			return NewValidationError(ErrMissingRequiredField,
				"machine ID is required", nil)
		}
	case "CompanyName":
		if req.Company == nil || req.Company.Name == "" {
			return NewValidationError(ErrMissingRequiredField,
				"company name is required", nil)
		}
	case "Department":
		if req.Company == nil || req.Company.Department == "" {
			return NewValidationError(ErrMissingRequiredField,
				"department is required", nil)
		}
	case "ContactPerson":
		if req.Contact == nil || req.Contact.Person == "" {
			return NewValidationError(ErrMissingRequiredField,
				"contact person is required", nil)
		}
	case "ContactEmail":
		if req.Contact == nil || req.Contact.Email == "" {
			return NewValidationError(ErrMissingRequiredField,
				"contact email is required", nil)
		}
	case "ContactPhone":
		if req.Contact == nil || req.Contact.Phone == "" {
			return NewValidationError(ErrMissingRequiredField,
				"contact phone is required", nil)
		}
	case "MinClientVersion":
		if req.Technical == nil || req.Technical.MinClientVersion == "" {
			return NewValidationError(ErrMissingRequiredField,
				"minimum client version is required", nil)
		}
	case "Country":
		if req.Company == nil || req.Company.Address == nil || req.Company.Address.Country == "" {
			return NewValidationError(ErrMissingRequiredField,
				"country is required", nil)
		}
	case "Province":
		if req.Company == nil || req.Company.Address == nil || req.Company.Address.Province == "" {
			return NewValidationError(ErrMissingRequiredField,
				"province is required", nil)
		}
	case "City":
		if req.Company == nil || req.Company.Address == nil || req.Company.Address.City == "" {
			return NewValidationError(ErrMissingRequiredField,
				"city is required", nil)
		}
	}
	return nil
}

// validateSecurityLevel 验证安全级别要求
func (tm *TemplateManager) validateSecurityLevel(req *ClientCertRequest, level TemplateSecurityLevel) error {
	switch level {
	case TemplateSecurityLevelCritical:
		// 关键级别需要所有联系信息
		if req.Contact == nil {
			return NewSecurityError(ErrUnauthorizedAccess,
				"critical security level requires complete contact information", nil)
		}
		if req.Contact.Person == "" || req.Contact.Email == "" || req.Contact.Phone == "" {
			return NewSecurityError(ErrUnauthorizedAccess,
				"critical security level requires person, email and phone", nil)
		}
		fallthrough
	case TemplateSecurityLevelHigh:
		// 高级别需要版本信息
		if req.Technical == nil || req.Technical.MinClientVersion == "" {
			return NewSecurityError(ErrUnauthorizedAccess,
				"high security level requires minimum client version information", nil)
		}
		fallthrough
	case TemplateSecurityLevelMedium:
		// 中级别需要公司信息
		if req.Company == nil || req.Company.Name == "" {
			return NewSecurityError(ErrUnauthorizedAccess,
				"medium security level requires company information", nil)
		}
		fallthrough
	case TemplateSecurityLevelLow:
		// 低级别只需要机器ID
		if req.Identity == nil || req.Identity.MachineID == "" {
			return NewSecurityError(ErrUnauthorizedAccess,
				"all security levels require machine ID", nil)
		}
	}
	return nil
}

// ApplyTemplate 应用模板到请求
func (tm *TemplateManager) ApplyTemplate(req *ClientCertRequest, templateName string) error {
	template, err := tm.Template(templateName)
	if err != nil {
		return err
	}

	// 设置有效期
	if req.Identity != nil && req.Identity.ExpiryDate.IsZero() {
		req.Identity.ExpiryDate = time.Now().AddDate(0, 0, template.ValidityDays)
	}

	// 设置技术信息中的有效期天数
	if req.Technical != nil {
		req.Technical.ValidityPeriodDays = template.ValidityDays
	}

	return nil
}

// ApplyTemplateToRequest 将模板应用到证书请求
func ApplyTemplateToRequest(req *ClientCertRequest, templateName string) error {
	templateMgr := NewTemplateManager()
	return templateMgr.ApplyTemplate(req, templateName)
}

// ValidateRequestWithGlobalTemplate 使用全局模板验证请求
func ValidateRequestWithGlobalTemplate(req *ClientCertRequest, templateName string) error {
	templateMgr := NewTemplateManager()
	return templateMgr.ValidateRequestWithTemplate(req, templateName)
}
