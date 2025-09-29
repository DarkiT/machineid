package cert

import (
	"fmt"
	"strings"
)

// ErrorType 错误类型
type ErrorType int

const (
	// ValidationError 验证错误
	ValidationError ErrorType = iota
	// SecurityError 安全错误
	SecurityError
	// ConfigError 配置错误
	ConfigError
	// NetworkError 网络错误
	NetworkError
	// CertificateError 证书错误
	CertificateError
	// SystemError 系统错误
	SystemError
)

// ErrorCode 错误代码
type ErrorCode string

const (
	// 验证错误代码
	ErrInvalidMachineID     ErrorCode = "INVALID_MACHINE_ID"
	ErrInvalidVersion       ErrorCode = "INVALID_VERSION"
	ErrExpiredCertificate   ErrorCode = "EXPIRED_CERTIFICATE"
	ErrInvalidCertificate   ErrorCode = "INVALID_CERTIFICATE"
	ErrMissingRequiredField ErrorCode = "MISSING_REQUIRED_FIELD"

	// 安全错误代码
	ErrDebuggerDetected   ErrorCode = "DEBUGGER_DETECTED"
	ErrTimeManipulation   ErrorCode = "TIME_MANIPULATION"
	ErrUnauthorizedAccess ErrorCode = "UNAUTHORIZED_ACCESS"
	ErrCertificateRevoked ErrorCode = "CERTIFICATE_REVOKED"

	// 配置错误代码
	ErrInvalidCAConfig ErrorCode = "INVALID_CA_CONFIG"
	ErrMissingCA       ErrorCode = "MISSING_CA"
	ErrInvalidKeySize  ErrorCode = "INVALID_KEY_SIZE"
	ErrInvalidConfig   ErrorCode = "INVALID_CONFIG"

	// 系统错误代码
	ErrSystemClockSkew    ErrorCode = "SYSTEM_CLOCK_SKEW"
	ErrInsufficientRights ErrorCode = "INSUFFICIENT_RIGHTS"
	ErrFileSystemError    ErrorCode = "FILESYSTEM_ERROR"
)

// CertError 证书错误
type CertError struct {
	Type        ErrorType              // 错误类型
	Code        ErrorCode              // 错误代码
	Message     string                 // 错误消息
	Details     map[string]interface{} // 错误详情
	Cause       error                  // 原始错误
	Suggestions []string               // 解决建议
}

// Error 实现 error 接口
func (e *CertError) Error() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("[%s:%s]", e.getTypeString(), e.Code))
	parts = append(parts, e.Message)

	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("caused by: %v", e.Cause))
	}

	result := strings.Join(parts, " ")

	if len(e.Suggestions) > 0 {
		result += fmt.Sprintf("\nSuggestions: %s", strings.Join(e.Suggestions, "; "))
	}

	return result
}

// GetType 获取错误类型
func (e *CertError) GetType() ErrorType {
	return e.Type
}

// GetCode 获取错误代码
func (e *CertError) GetCode() ErrorCode {
	return e.Code
}

// GetDetails 获取错误详情
func (e *CertError) GetDetails() map[string]interface{} {
	return e.Details
}

// GetSuggestions 获取解决建议
func (e *CertError) GetSuggestions() []string {
	return e.Suggestions
}

// Is 检查是否为指定类型的错误
func (e *CertError) Is(target error) bool {
	if err, ok := target.(*CertError); ok {
		return e.Type == err.Type && e.Code == err.Code
	}
	return false
}

// Unwrap 解包原始错误
func (e *CertError) Unwrap() error {
	return e.Cause
}

// getTypeString 获取错误类型字符串
func (e *CertError) getTypeString() string {
	switch e.Type {
	case ValidationError:
		return "VALIDATION"
	case SecurityError:
		return "SECURITY"
	case ConfigError:
		return "CONFIG"
	case NetworkError:
		return "NETWORK"
	case CertificateError:
		return "CERTIFICATE"
	case SystemError:
		return "SYSTEM"
	default:
		return "UNKNOWN"
	}
}

// NewValidationError 创建验证错误
func NewValidationError(code ErrorCode, message string, cause error) *CertError {
	err := &CertError{
		Type:    ValidationError,
		Code:    code,
		Message: message,
		Cause:   cause,
		Details: make(map[string]interface{}),
	}
	err.addValidationSuggestions()
	return err
}

// NewSecurityError 创建安全错误
func NewSecurityError(code ErrorCode, message string, cause error) *CertError {
	err := &CertError{
		Type:    SecurityError,
		Code:    code,
		Message: message,
		Cause:   cause,
		Details: make(map[string]interface{}),
	}
	err.addSecuritySuggestions()
	return err
}

// NewConfigError 创建配置错误
func NewConfigError(code ErrorCode, message string, cause error) *CertError {
	err := &CertError{
		Type:    ConfigError,
		Code:    code,
		Message: message,
		Cause:   cause,
		Details: make(map[string]interface{}),
	}
	err.addConfigSuggestions()
	return err
}

// NewCertificateError 创建证书错误
func NewCertificateError(code ErrorCode, message string, cause error) *CertError {
	err := &CertError{
		Type:    CertificateError,
		Code:    code,
		Message: message,
		Cause:   cause,
		Details: make(map[string]interface{}),
	}
	err.addCertificateSuggestions()
	return err
}

// NewSystemError 创建系统错误
func NewSystemError(code ErrorCode, message string, cause error) *CertError {
	err := &CertError{
		Type:    SystemError,
		Code:    code,
		Message: message,
		Cause:   cause,
		Details: make(map[string]interface{}),
	}
	err.addSystemSuggestions()
	return err
}

// WithDetail 添加错误详情
func (e *CertError) WithDetail(key string, value interface{}) *CertError {
	e.Details[key] = value
	return e
}

// WithSuggestion 添加解决建议
func (e *CertError) WithSuggestion(suggestion string) *CertError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return e
}

// addValidationSuggestions 添加验证错误的建议
func (e *CertError) addValidationSuggestions() {
	switch e.Code {
	case ErrInvalidMachineID:
		e.Suggestions = append(e.Suggestions,
			"确保机器码长度至少8个字符",
			"如果是多个机器码，请用逗号分隔",
			"检查机器码格式是否正确")
	case ErrInvalidVersion:
		e.Suggestions = append(e.Suggestions,
			"版本号应采用语义化版本格式(如: 1.0.0)",
			"确保版本号只包含数字和点号",
			"检查版本号是否包含负数")
	case ErrExpiredCertificate:
		e.Suggestions = append(e.Suggestions,
			"请联系管理员更新证书",
			"检查系统时间是否正确",
			"确认证书的有效期设置")
	case ErrMissingRequiredField:
		e.Suggestions = append(e.Suggestions,
			"检查所有必需字段是否已填写",
			"参考文档确认必需字段列表")
	}
}

// addSecuritySuggestions 添加安全错误的建议
func (e *CertError) addSecuritySuggestions() {
	switch e.Code {
	case ErrDebuggerDetected:
		e.Suggestions = append(e.Suggestions,
			"关闭调试器后重试",
			"确保程序在正常环境下运行")
	case ErrTimeManipulation:
		e.Suggestions = append(e.Suggestions,
			"检查系统时间设置",
			"确保系统时间与网络时间同步",
			"避免手动修改系统时间")
	case ErrCertificateRevoked:
		e.Suggestions = append(e.Suggestions,
			"联系管理员确认证书状态",
			"检查是否有新的证书可用",
			"确认程序版本是否需要更新")
	}
}

// addConfigSuggestions 添加配置错误的建议
func (e *CertError) addConfigSuggestions() {
	switch e.Code {
	case ErrInvalidCAConfig:
		e.Suggestions = append(e.Suggestions,
			"检查CA证书和私钥是否匹配",
			"确认CA证书格式正确",
			"验证私钥格式和权限")
	case ErrMissingCA:
		e.Suggestions = append(e.Suggestions,
			"确保CA证书文件存在",
			"检查CA证书路径配置",
			"使用默认CA或提供自定义CA")
	}
}

// addCertificateSuggestions 添加证书错误的建议
func (e *CertError) addCertificateSuggestions() {
	switch e.Code {
	case ErrInvalidCertificate:
		e.Suggestions = append(e.Suggestions,
			"检查证书格式是否正确",
			"确认证书未被损坏",
			"验证证书是否由正确的CA签发")
	}
}

// addSystemSuggestions 添加系统错误的建议
func (e *CertError) addSystemSuggestions() {
	switch e.Code {
	case ErrSystemClockSkew:
		e.Suggestions = append(e.Suggestions,
			"同步系统时间与网络时间",
			"检查时区设置是否正确",
			"确保系统时间服务正常运行")
	case ErrFileSystemError:
		e.Suggestions = append(e.Suggestions,
			"检查文件权限",
			"确保磁盘空间充足",
			"验证文件路径是否正确")
	}
}

// IsValidationError 检查是否为验证错误
func IsValidationError(err error) bool {
	if certErr, ok := err.(*CertError); ok {
		return certErr.Type == ValidationError
	}
	return false
}

// IsSecurityError 检查是否为安全错误
func IsSecurityError(err error) bool {
	if certErr, ok := err.(*CertError); ok {
		return certErr.Type == SecurityError
	}
	return false
}

// IsConfigError 检查是否为配置错误
func IsConfigError(err error) bool {
	if certErr, ok := err.(*CertError); ok {
		return certErr.Type == ConfigError
	}
	return false
}
