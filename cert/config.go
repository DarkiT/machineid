package cert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ConfigFile 配置文件结构
type ConfigFile struct {
	Version      string                 `json:"version" yaml:"version"`
	EnterpriseID int                    `json:"enterprise_id" yaml:"enterprise_id"`
	CA           CAConfiguration        `json:"ca" yaml:"ca"`
	Security     SecurityConfiguration  `json:"security" yaml:"security"`
	Cache        CacheConfiguration     `json:"cache" yaml:"cache"`
	Templates    map[string]interface{} `json:"templates" yaml:"templates"`
	Logging      LoggingConfiguration   `json:"logging" yaml:"logging"`
}

// CAConfiguration CA配置
type CAConfiguration struct {
	CertPath     string `json:"cert_path" yaml:"cert_path"`
	KeyPath      string `json:"key_path" yaml:"key_path"`
	CertPEM      string `json:"cert_pem" yaml:"cert_pem"`
	KeyPEM       string `json:"key_pem" yaml:"key_pem"`
	UseDefault   bool   `json:"use_default" yaml:"use_default"`
	AutoGenerate bool   `json:"auto_generate" yaml:"auto_generate"`
}

// SecurityConfiguration 安全配置
type SecurityConfiguration struct {
	EnableAntiDebug        bool   `json:"enable_anti_debug" yaml:"enable_anti_debug"`
	EnableTimeValidation   bool   `json:"enable_time_validation" yaml:"enable_time_validation"`
	RequireHardwareBinding bool   `json:"require_hardware_binding" yaml:"require_hardware_binding"`
	MaxClockSkew           string `json:"max_clock_skew" yaml:"max_clock_skew"`
}

// CacheConfiguration 缓存配置
type CacheConfiguration struct {
	TTL             string `json:"ttl" yaml:"ttl"`
	MaxSize         int    `json:"max_size" yaml:"max_size"`
	CleanupInterval string `json:"cleanup_interval" yaml:"cleanup_interval"`
	Enabled         bool   `json:"enabled" yaml:"enabled"`
}

// LoggingConfiguration 日志配置
type LoggingConfiguration struct {
	Level  string `json:"level" yaml:"level"`
	File   string `json:"file" yaml:"file"`
	Format string `json:"format" yaml:"format"`
}

// ConfigLoader 配置加载器
type ConfigLoader struct {
	searchPaths []string
	filename    string
}

// NewConfigLoader 创建配置加载器
func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{
		searchPaths: []string{
			".",
			"./config",
			"./cert",
			os.Getenv("HOME") + "/.cert",
			"/etc/cert",
		},
		filename: "cert.config",
	}
}

// WithSearchPaths 设置搜索路径
func (cl *ConfigLoader) WithSearchPaths(paths ...string) *ConfigLoader {
	cl.searchPaths = paths
	return cl
}

// WithFilename 设置配置文件名
func (cl *ConfigLoader) WithFilename(filename string) *ConfigLoader {
	cl.filename = filename
	return cl
}

// LoadConfig 加载配置文件
func (cl *ConfigLoader) LoadConfig() (*ConfigFile, error) {
	// 尝试各种文件扩展名
	extensions := []string{".json", ".yaml", ".yml"}

	for _, path := range cl.searchPaths {
		for _, ext := range extensions {
			fullPath := filepath.Join(path, cl.filename+ext)
			if config, err := cl.loadFromFile(fullPath); err == nil {
				return config, nil
			}
		}
	}

	return nil, NewConfigError(ErrMissingCA,
		"configuration file not found", nil).
		WithDetail("search_paths", cl.searchPaths).
		WithDetail("filename", cl.filename).
		WithSuggestion("创建配置文件或使用 GenerateDefaultConfig() 生成默认配置")
}

// loadFromFile 从文件加载配置
func (cl *ConfigLoader) loadFromFile(filePath string) (*ConfigFile, error) {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, err
	}

	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, NewConfigError(ErrFileSystemError,
			"failed to read config file", err).
			WithDetail("file_path", filePath)
	}

	config := &ConfigFile{}
	ext := filepath.Ext(filePath)

	// 根据文件扩展名解析
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, NewConfigError(ErrInvalidCAConfig,
				"failed to parse JSON config", err).
				WithDetail("file_path", filePath)
		}
	case ".yaml", ".yml":
		// 简单的YAML支持（仅支持基本格式）
		if err := parseSimpleYAML(data, config); err != nil {
			return nil, NewConfigError(ErrInvalidCAConfig,
				"failed to parse YAML config", err).
				WithDetail("file_path", filePath)
		}
	default:
		return nil, NewConfigError(ErrInvalidCAConfig,
			"unsupported config file format", nil).
			WithDetail("file_path", filePath).
			WithDetail("supported_formats", []string{".json", ".yaml", ".yml"})
	}

	// 验证配置
	if err := cl.validateConfig(config); err != nil {
		return nil, err
	}

	return config, nil
}

// validateConfig 验证配置文件
func (cl *ConfigLoader) validateConfig(config *ConfigFile) error {
	if config.Version == "" {
		return NewConfigError(ErrInvalidCAConfig,
			"version is required in config file", nil)
	}

	if config.EnterpriseID <= 0 {
		return NewConfigError(ErrInvalidCAConfig,
			"enterprise_id must be positive", nil).
			WithDetail("enterprise_id", config.EnterpriseID)
	}

	// 验证CA配置
	if err := cl.validateCAConfig(&config.CA); err != nil {
		return err
	}

	return nil
}

// validateCAConfig 验证CA配置
func (cl *ConfigLoader) validateCAConfig(ca *CAConfiguration) error {
	if !ca.UseDefault && !ca.AutoGenerate {
		// 如果不使用默认CA且不自动生成，则需要提供证书和私钥
		if ca.CertPath == "" && ca.CertPEM == "" {
			return NewConfigError(ErrMissingCA,
				"CA certificate path or PEM must be provided", nil)
		}
		if ca.KeyPath == "" && ca.KeyPEM == "" {
			return NewConfigError(ErrMissingCA,
				"CA private key path or PEM must be provided", nil)
		}
	}
	return nil
}

// ToAuthorizerConfig 转换为授权管理器配置
func (cf *ConfigFile) ToAuthorizerConfig() (AuthorizerConfig, error) {
	config := AuthorizerConfig{
		Version:      cf.Version,
		EnterpriseID: cf.EnterpriseID,
	}

	// 处理CA配置
	if err := cf.processCAConfig(&config); err != nil {
		return config, err
	}

	// 处理安全配置
	if err := cf.processSecurityConfig(&config); err != nil {
		return config, err
	}

	// 处理缓存配置
	if err := cf.processCacheConfig(&config); err != nil {
		return config, err
	}

	return config, nil
}

// processCAConfig 处理CA配置
func (cf *ConfigFile) processCAConfig(config *AuthorizerConfig) error {
	ca := &cf.CA

	if ca.UseDefault {
		config.CACert = defaultCACert
		config.CAKey = defaultCAKey
		return nil
	}

	if ca.AutoGenerate {
		// 自动生成CA证书（这里可以添加自动生成逻辑）
		config.CACert = defaultCACert
		config.CAKey = defaultCAKey
		return nil
	}

	// 从PEM字符串加载
	if ca.CertPEM != "" {
		config.CACert = []byte(ca.CertPEM)
	}
	if ca.KeyPEM != "" {
		config.CAKey = []byte(ca.KeyPEM)
	}

	// 从文件加载
	if ca.CertPath != "" {
		certData, err := os.ReadFile(ca.CertPath)
		if err != nil {
			return NewConfigError(ErrMissingCA,
				"failed to read CA certificate file", err).
				WithDetail("cert_path", ca.CertPath)
		}
		config.CACert = certData
	}

	if ca.KeyPath != "" {
		keyData, err := os.ReadFile(ca.KeyPath)
		if err != nil {
			return NewConfigError(ErrMissingCA,
				"failed to read CA private key file", err).
				WithDetail("key_path", ca.KeyPath)
		}
		config.CAKey = keyData
	}

	return nil
}

// processSecurityConfig 处理安全配置
func (cf *ConfigFile) processSecurityConfig(config *AuthorizerConfig) error {
	sec := &cf.Security

	config.Security = SecurityConfig{
		EnableAntiDebug:        sec.EnableAntiDebug,
		EnableTimeValidation:   sec.EnableTimeValidation,
		RequireHardwareBinding: sec.RequireHardwareBinding,
	}

	// 解析时钟偏差
	if sec.MaxClockSkew != "" {
		duration, err := time.ParseDuration(sec.MaxClockSkew)
		if err != nil {
			return NewConfigError(ErrInvalidCAConfig,
				"invalid max_clock_skew duration", err).
				WithDetail("max_clock_skew", sec.MaxClockSkew).
				WithSuggestion("使用如 '5m', '30s', '1h' 等格式")
		}
		config.Security.MaxClockSkew = duration
	} else {
		config.Security.MaxClockSkew = 5 * time.Minute
	}

	return nil
}

// processCacheConfig 处理缓存配置
func (cf *ConfigFile) processCacheConfig(config *AuthorizerConfig) error {
	cache := &cf.Cache

	config.Cache = CacheConfig{
		MaxSize: cache.MaxSize,
	}

	if config.Cache.MaxSize <= 0 {
		config.Cache.MaxSize = 1000
	}

	// 解析TTL
	if cache.TTL != "" {
		duration, err := time.ParseDuration(cache.TTL)
		if err != nil {
			return NewConfigError(ErrInvalidCAConfig,
				"invalid cache TTL duration", err).
				WithDetail("ttl", cache.TTL).
				WithSuggestion("使用如 '5m', '30s', '1h' 等格式")
		}
		config.Cache.TTL = duration
	} else {
		config.Cache.TTL = 5 * time.Minute
	}

	// 解析清理间隔
	if cache.CleanupInterval != "" {
		duration, err := time.ParseDuration(cache.CleanupInterval)
		if err != nil {
			return NewConfigError(ErrInvalidCAConfig,
				"invalid cleanup interval duration", err).
				WithDetail("cleanup_interval", cache.CleanupInterval).
				WithSuggestion("使用如 '10m', '1h' 等格式")
		}
		config.Cache.CleanupInterval = duration
	} else {
		config.Cache.CleanupInterval = 10 * time.Minute
	}

	return nil
}

// GenerateDefaultConfig 生成默认配置文件
func GenerateDefaultConfig(filePath string) error {
	config := ConfigFile{
		Version:      "1.0.0",
		EnterpriseID: defaultEnterpriseID,
		CA: CAConfiguration{
			UseDefault:   true,
			AutoGenerate: false,
		},
		Security: SecurityConfiguration{
			EnableAntiDebug:        true,
			EnableTimeValidation:   true,
			RequireHardwareBinding: false,
			MaxClockSkew:           "5m",
		},
		Cache: CacheConfiguration{
			TTL:             "5m",
			MaxSize:         1000,
			CleanupInterval: "10m",
			Enabled:         true,
		},
		Templates: map[string]interface{}{
			"client": map[string]interface{}{
				"name":           "标准客户端证书",
				"description":    "适用于一般客户端认证的证书模板",
				"validity_days":  365,
				"security_level": "medium",
			},
			"enterprise": map[string]interface{}{
				"name":           "企业级证书",
				"description":    "适用于企业级应用的高安全证书模板",
				"validity_days":  730,
				"security_level": "critical",
			},
		},
		Logging: LoggingConfiguration{
			Level:  "info",
			Format: "json",
		},
	}

	// 确定文件格式
	ext := filepath.Ext(filePath)
	var data []byte
	var err error

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	case ".yaml", ".yml":
		data, err = marshalSimpleYAML(&config)
	default:
		return NewConfigError(ErrInvalidCAConfig,
			"unsupported config file format", nil).
			WithDetail("file_path", filePath).
			WithSuggestion("使用 .json、.yaml 或 .yml 扩展名")
	}

	if err != nil {
		return NewConfigError(ErrInvalidCAConfig,
			"failed to marshal config", err)
	}

	// 确保目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return NewConfigError(ErrFileSystemError,
			"failed to create config directory", err).
			WithDetail("directory", dir)
	}

	// 写入文件
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		return NewConfigError(ErrFileSystemError,
			"failed to write config file", err).
			WithDetail("file_path", filePath)
	}

	return nil
}

// FromConfigFile 从配置文件创建授权管理器构建器
func FromConfigFile(filePath string) (*AuthorizerBuilder, error) {
	loader := NewConfigLoader()

	// 如果提供了特定路径，只在该路径搜索
	if filePath != "" {
		dir := filepath.Dir(filePath)
		filename := filepath.Base(filePath)
		ext := filepath.Ext(filename)
		if ext != "" {
			filename = filename[:len(filename)-len(ext)]
		}

		loader = loader.
			WithSearchPaths(dir).
			WithFilename(filename)
	}

	config, err := loader.LoadConfig()
	if err != nil {
		return nil, err
	}

	authConfig, err := config.ToAuthorizerConfig()
	if err != nil {
		return nil, err
	}

	builder := &AuthorizerBuilder{config: authConfig}
	return builder, nil
}

// SaveConfig 保存配置到文件
func SaveConfig(config *ConfigFile, filePath string) error {
	return GenerateDefaultConfig(filePath) // 这里可以改进为保存实际配置
}

// parseSimpleYAML 简单的YAML解析器（仅支持基本格式）
func parseSimpleYAML(data []byte, config *ConfigFile) error {
	// 为了避免外部依赖，这里提供一个非常基础的YAML解析
	// 实际项目中建议使用完整的YAML库
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, "\"'") // 去除引号

		switch key {
		case "version":
			config.Version = value
		case "enterprise_id":
			if val := parseIntValue(value); val != 0 {
				config.EnterpriseID = val
			}
		}
	}

	// 设置默认值
	if config.Version == "" {
		config.Version = "1.0.0"
	}
	if config.EnterpriseID == 0 {
		config.EnterpriseID = defaultEnterpriseID
	}

	return nil
}

// marshalSimpleYAML 简单的YAML序列化
func marshalSimpleYAML(config *ConfigFile) ([]byte, error) {
	var result strings.Builder
	result.WriteString("# Certificate Configuration\n")
	result.WriteString("version: \"" + config.Version + "\"\n")
	result.WriteString("enterprise_id: " + fmt.Sprintf("%d", config.EnterpriseID) + "\n")
	result.WriteString("ca:\n")
	result.WriteString("  use_default: " + fmt.Sprintf("%t", config.CA.UseDefault) + "\n")
	result.WriteString("  auto_generate: " + fmt.Sprintf("%t", config.CA.AutoGenerate) + "\n")
	result.WriteString("security:\n")
	result.WriteString("  enable_anti_debug: " + fmt.Sprintf("%t", config.Security.EnableAntiDebug) + "\n")
	result.WriteString("  enable_time_validation: " + fmt.Sprintf("%t", config.Security.EnableTimeValidation) + "\n")
	result.WriteString("  require_hardware_binding: " + fmt.Sprintf("%t", config.Security.RequireHardwareBinding) + "\n")
	result.WriteString("  max_clock_skew: \"" + config.Security.MaxClockSkew + "\"\n")
	result.WriteString("cache:\n")
	result.WriteString("  ttl: \"" + config.Cache.TTL + "\"\n")
	result.WriteString("  max_size: " + fmt.Sprintf("%d", config.Cache.MaxSize) + "\n")
	result.WriteString("  cleanup_interval: \"" + config.Cache.CleanupInterval + "\"\n")
	result.WriteString("  enabled: " + fmt.Sprintf("%t", config.Cache.Enabled) + "\n")

	return []byte(result.String()), nil
}

// parseIntValue 解析整数值
func parseIntValue(s string) int {
	// 简单的整数解析
	if s == "" {
		return 0
	}

	result := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			break
		}
	}

	return result
}
