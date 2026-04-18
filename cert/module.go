package cert

import "time"

// ModuleConfig 模块配置（用于证书请求）
type ModuleConfig struct {
	Name      string
	Enabled   bool
	Quota     int
	NotBefore time.Time
	NotAfter  time.Time
	Extra     string
}

// ModuleBuilder 模块配置构建器
type ModuleBuilder struct {
	config ModuleConfig
}

// Module 创建模块配置构建器
func Module(name string) *ModuleBuilder {
	return &ModuleBuilder{
		config: ModuleConfig{
			Name:    name,
			Enabled: true, // 默认启用
		},
	}
}

// Enabled 启用模块
func (b *ModuleBuilder) Enabled() *ModuleBuilder {
	b.config.Enabled = true
	return b
}

// Disabled 禁用模块
func (b *ModuleBuilder) Disabled() *ModuleBuilder {
	b.config.Enabled = false
	return b
}

// WithQuota 设置配额限制
func (b *ModuleBuilder) WithQuota(quota int) *ModuleBuilder {
	b.config.Quota = quota
	return b
}

// ValidFor 设置有效天数（相对于证书生效时间）
func (b *ModuleBuilder) ValidFor(days int) *ModuleBuilder {
	b.config.NotAfter = time.Now().AddDate(0, 0, days)
	return b
}

// ValidUntil 设置过期时间
func (b *ModuleBuilder) ValidUntil(t time.Time) *ModuleBuilder {
	b.config.NotAfter = t
	return b
}

// ValidFrom 设置生效时间
func (b *ModuleBuilder) ValidFrom(t time.Time) *ModuleBuilder {
	b.config.NotBefore = t
	return b
}

// ValidBetween 设置有效期范围
func (b *ModuleBuilder) ValidBetween(from, to time.Time) *ModuleBuilder {
	b.config.NotBefore = from
	b.config.NotAfter = to
	return b
}

// WithExtra 设置扩展数据
func (b *ModuleBuilder) WithExtra(extra string) *ModuleBuilder {
	b.config.Extra = extra
	return b
}

// Build 构建模块配置
func (b *ModuleBuilder) Build() ModuleConfig {
	return b.config
}

// ToPermission 转换为 ModulePermission（用于证书扩展）
func (c *ModuleConfig) ToPermission() ModulePermission {
	perm := ModulePermission{
		Name:    c.Name,
		Enabled: c.Enabled,
		Quota:   c.Quota,
		Extra:   c.Extra,
	}
	if !c.NotBefore.IsZero() {
		perm.NotBefore = c.NotBefore.Unix()
	}
	if !c.NotAfter.IsZero() {
		perm.NotAfter = c.NotAfter.Unix()
	}
	return perm
}

// FeaturesConfig 模块授权配置（用于证书请求）
type FeaturesConfig struct {
	Modules []ModuleConfig
}

// AddModule 添加模块配置
func (f *FeaturesConfig) AddModule(config ModuleConfig) {
	f.Modules = append(f.Modules, config)
}

// ToFeaturesInfo 转换为 FeaturesInfo（用于证书扩展）
func (f *FeaturesConfig) ToFeaturesInfo() *FeaturesInfo {
	if f == nil || len(f.Modules) == 0 {
		return nil
	}
	info := &FeaturesInfo{
		Modules: make([]ModulePermission, len(f.Modules)),
	}
	for i, m := range f.Modules {
		info.Modules[i] = m.ToPermission()
	}
	return info
}

// HasModule 检查是否包含指定模块
func (f *FeaturesInfo) HasModule(name string) bool {
	if f == nil {
		return false
	}
	for _, m := range f.Modules {
		if m.Name == name {
			return m.Enabled
		}
	}
	return false
}

// GetModule 获取指定模块权限
func (f *FeaturesInfo) GetModule(name string) *ModulePermission {
	if f == nil {
		return nil
	}
	for i := range f.Modules {
		if f.Modules[i].Name == name {
			return &f.Modules[i]
		}
	}
	return nil
}

// ValidateModule 验证模块权限（检查启用状态和有效期）
func (f *FeaturesInfo) ValidateModule(name string, now time.Time) error {
	if f == nil {
		return NewValidationError(ErrModuleNotAuthorized, "no module authorization in certificate", nil).
			WithDetail("module", name)
	}

	module := f.GetModule(name)
	if module == nil {
		return NewValidationError(ErrModuleNotAuthorized, "module not found in certificate", nil).
			WithDetail("module", name)
	}

	if !module.Enabled {
		return NewValidationError(ErrModuleNotAuthorized, "module is disabled", nil).
			WithDetail("module", name)
	}

	if !module.IsValid(now) {
		return NewValidationError(ErrModuleExpired, "module authorization expired or not yet valid", nil).
			WithDetail("module", name).
			WithDetail("not_before", module.GetNotBefore()).
			WithDetail("not_after", module.GetNotAfter())
	}

	return nil
}
