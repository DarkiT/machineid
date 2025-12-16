package cert

import (
	"errors"
	"fmt"
	"strings"
	"time"

	machineid "github.com/darkit/machineid"
)

// Identity 身份标识信息
type Identity struct {
	MachineID       string    // 机器码（可以是多个，用逗号分隔）
	ExpiryDate      time.Time // 授权过期日期
	BindingMode     string    // 绑定模式
	BindingProvider string    // 绑定提供者
}

// Company 公司信息
type Company struct {
	Name       string   // 公司名称
	Department string   // 部门名称
	Address    *Address // 地址信息（可选）
}

// Address 地址信息
type Address struct {
	Country  string // 国家
	Province string // 省份
	City     string // 城市
	Street   string // 详细地址
}

// Contact 联系信息
type Contact struct {
	Person string // 联系人
	Phone  string // 联系电话
	Email  string // 联系邮箱
}

// Technical 技术信息
type Technical struct {
	MinClientVersion   string // 最低客户端版本要求
	ValidityPeriodDays int    // 证书有效期天数
}

// ClientCertRequest 客户端证书请求
type ClientCertRequest struct {
	Identity  *Identity  // 身份标识（必需）
	Company   *Company   // 公司信息（必需）
	Contact   *Contact   // 联系信息（可选）
	Technical *Technical // 技术信息（必需）
}

// NewClientRequest 创建新的客户端证书请求构建器
func NewClientRequest() *ClientCertRequestBuilder {
	return &ClientCertRequestBuilder{
		req: &ClientCertRequest{},
	}
}

// ClientCertRequestBuilder 客户端证书请求构建器
type ClientCertRequestBuilder struct {
	req          *ClientCertRequest
	templateName string
}

// WithMachineID 设置机器码
func (b *ClientCertRequestBuilder) WithMachineID(machineID string) *ClientCertRequestBuilder {
	if b.req.Identity == nil {
		b.req.Identity = &Identity{}
	}
	b.req.Identity.MachineID = machineID
	return b
}

// WithBindingInfo 设置机器码绑定信息
func (b *ClientCertRequestBuilder) WithBindingInfo(mode, provider string) *ClientCertRequestBuilder {
	if b.req.Identity == nil {
		b.req.Identity = &Identity{}
	}
	b.req.Identity.BindingMode = mode
	b.req.Identity.BindingProvider = provider
	return b
}

// WithBindingResult 直接使用 machineid 包返回的绑定结果
func (b *ClientCertRequestBuilder) WithBindingResult(result *machineid.BindingResult) *ClientCertRequestBuilder {
	if result == nil {
		return b
	}
	return b.WithBindingInfo(string(result.Mode), result.Provider)
}

// WithExpiry 设置过期时间
func (b *ClientCertRequestBuilder) WithExpiry(expiryDate time.Time) *ClientCertRequestBuilder {
	if b.req.Identity == nil {
		b.req.Identity = &Identity{}
	}
	b.req.Identity.ExpiryDate = expiryDate
	return b
}

// WithCompany 设置公司信息
func (b *ClientCertRequestBuilder) WithCompany(name, department string) *ClientCertRequestBuilder {
	b.req.Company = &Company{
		Name:       name,
		Department: department,
	}
	return b
}

// WithAddress 设置地址信息
func (b *ClientCertRequestBuilder) WithAddress(country, province, city, street string) *ClientCertRequestBuilder {
	if b.req.Company == nil {
		b.req.Company = &Company{}
	}
	b.req.Company.Address = &Address{
		Country:  country,
		Province: province,
		City:     city,
		Street:   street,
	}
	return b
}

// WithContact 设置联系信息
func (b *ClientCertRequestBuilder) WithContact(person, phone, email string) *ClientCertRequestBuilder {
	b.req.Contact = &Contact{
		Person: person,
		Phone:  phone,
		Email:  email,
	}
	return b
}

// WithMinClientVersion 设置最低客户端版本
func (b *ClientCertRequestBuilder) WithMinClientVersion(version string) *ClientCertRequestBuilder {
	if b.req.Technical == nil {
		b.req.Technical = &Technical{}
	}
	b.req.Technical.MinClientVersion = version
	return b
}

// WithValidityDays 设置证书有效期天数
func (b *ClientCertRequestBuilder) WithValidityDays(days int) *ClientCertRequestBuilder {
	if b.req.Technical == nil {
		b.req.Technical = &Technical{}
	}
	b.req.Technical.ValidityPeriodDays = days
	return b
}

// WithTemplate 使用模板
func (b *ClientCertRequestBuilder) WithTemplate(templateName string) *ClientCertRequestBuilder {
	b.templateName = templateName
	return b
}

// Build 构建证书请求
func (b *ClientCertRequestBuilder) Build() (*ClientCertRequest, error) {
	// 如果指定了模板，应用模板设置
	if b.templateName != "" {
		if err := ApplyTemplateToRequest(b.req, b.templateName); err != nil {
			return nil, err
		}

		// 验证模板要求
		if err := ValidateRequestWithGlobalTemplate(b.req, b.templateName); err != nil {
			return nil, err
		}
	}

	if err := b.req.Validate(); err != nil {
		return nil, err
	}
	b.req.SetDefaults()
	return b.req, nil
}

// Validate 验证请求参数
func (req *ClientCertRequest) Validate() error {
	if req.Identity == nil {
		return errors.New("identity information is required")
	}

	if req.Identity.MachineID == "" {
		return errors.New("machine ID is required")
	}

	if req.Identity.ExpiryDate.IsZero() {
		return errors.New("expiry date is required")
	}

	if req.Identity.ExpiryDate.Before(time.Now()) {
		return errors.New("expiry date cannot be in the past")
	}

	if req.Company == nil {
		return errors.New("company information is required")
	}

	if req.Company.Name == "" {
		return errors.New("company name is required")
	}

	if req.Technical == nil {
		return errors.New("technical information is required")
	}

	if req.Technical.MinClientVersion == "" {
		return errors.New("minimum client version is required")
	}

	// 验证机器码格式（可以是多个，用逗号分隔）
	machineIDs := strings.Split(req.Identity.MachineID, ",")
	for _, id := range machineIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return errors.New("empty machine ID found in machine ID list")
		}
		if len(id) < 8 {
			return fmt.Errorf("machine ID '%s' is too short (minimum 8 characters)", id)
		}
	}

	return nil
}

// MachineIDs 获取所有机器码列表
func (req *ClientCertRequest) MachineIDs() []string {
	if req.Identity == nil || req.Identity.MachineID == "" {
		return nil
	}

	var result []string
	machineIDs := strings.Split(req.Identity.MachineID, ",")
	for _, id := range machineIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			result = append(result, id)
		}
	}
	return result
}

// SetDefaults 设置默认值
func (req *ClientCertRequest) SetDefaults() {
	if req.Identity != nil && req.Identity.ExpiryDate.IsZero() {
		req.Identity.ExpiryDate = time.Now().AddDate(1, 0, 0) // 默认1年
	}

	if req.Technical != nil && req.Technical.ValidityPeriodDays == 0 {
		if req.Identity != nil && !req.Identity.ExpiryDate.IsZero() {
			req.Technical.ValidityPeriodDays = int(time.Until(req.Identity.ExpiryDate).Hours() / 24)
		} else {
			req.Technical.ValidityPeriodDays = 365 // 默认365天
		}
	}

	if req.Company != nil && req.Company.Department == "" {
		req.Company.Department = "技术部" // 默认部门
	}
}
