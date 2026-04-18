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
	ErrInvalidMachineID            ErrorCode = "INVALID_MACHINE_ID"
	ErrInvalidVersion              ErrorCode = "INVALID_VERSION"
	ErrInvalidRequest              ErrorCode = "INVALID_REQUEST"
	ErrExpiredCertificate          ErrorCode = "EXPIRED_CERTIFICATE"
	ErrInvalidCertificate          ErrorCode = "INVALID_CERTIFICATE"
	ErrMissingRequiredField        ErrorCode = "MISSING_REQUIRED_FIELD"
	ErrCertificateNotTrusted       ErrorCode = "CERTIFICATE_NOT_TRUSTED"
	ErrCertificateExtensionMissing ErrorCode = "CERTIFICATE_EXTENSION_MISSING"
	ErrCertificateVersionMismatch  ErrorCode = "CERTIFICATE_VERSION_MISMATCH"
	ErrVersionTooOld               ErrorCode = "VERSION_TOO_OLD"
	ErrVersionFormatInvalid        ErrorCode = "VERSION_FORMAT_INVALID"
	ErrVersionCompareFailed        ErrorCode = "VERSION_COMPARE_FAILED"
	ErrMachineIDNotAuthorized      ErrorCode = "MACHINE_ID_NOT_AUTHORIZED"

	// 安全错误代码
	ErrDebuggerDetected           ErrorCode = "DEBUGGER_DETECTED"
	ErrTimeManipulation           ErrorCode = "TIME_MANIPULATION"
	ErrUnauthorizedAccess         ErrorCode = "UNAUTHORIZED_ACCESS"
	ErrCertificateRevoked         ErrorCode = "CERTIFICATE_REVOKED"
	ErrTimeRollback               ErrorCode = "TIME_ROLLBACK"                // 时间回滚
	ErrHardwareChanged            ErrorCode = "HARDWARE_CHANGED"             // 硬件变更
	ErrMemoryTampered             ErrorCode = "MEMORY_TAMPERED"              // 内存完整性异常
	ErrVirtualMachineDetected     ErrorCode = "VIRTUAL_MACHINE_DETECTED"     // 虚拟机/沙箱环境
	ErrHardwareBreakpointDetected ErrorCode = "HARDWARE_BREAKPOINT_DETECTED" // 硬件断点
	ErrDebugPortDetected          ErrorCode = "DEBUG_PORT_DETECTED"          // 调试端口
	ErrDebugObjectDetected        ErrorCode = "DEBUG_OBJECT_DETECTED"        // 调试对象句柄
	ErrDebugFlagsDetected         ErrorCode = "DEBUG_FLAGS_DETECTED"         // 调试标志

	// 配置错误代码
	ErrInvalidCAConfig ErrorCode = "INVALID_CA_CONFIG"
	ErrMissingCA       ErrorCode = "MISSING_CA"
	ErrInvalidKeySize  ErrorCode = "INVALID_KEY_SIZE"
	ErrInvalidConfig   ErrorCode = "INVALID_CONFIG"

	// 系统错误代码
	ErrSystemClockSkew    ErrorCode = "SYSTEM_CLOCK_SKEW"
	ErrInsufficientRights ErrorCode = "INSUFFICIENT_RIGHTS"
	ErrFileSystemError    ErrorCode = "FILESYSTEM_ERROR"

	// 容器和快照错误代码
	ErrContainerBindingFailed ErrorCode = "CONTAINER_BINDING_FAILED" // 容器绑定失败
	ErrSnapshotExpired        ErrorCode = "SNAPSHOT_EXPIRED"         // 快照过期
	ErrSnapshotInvalid        ErrorCode = "SNAPSHOT_INVALID"         // 快照无效

	// 模块授权错误代码
	ErrModuleNotAuthorized ErrorCode = "MODULE_NOT_AUTHORIZED" // 模块未授权
	ErrModuleExpired       ErrorCode = "MODULE_EXPIRED"        // 模块授权过期
	ErrModuleQuotaExceeded ErrorCode = "MODULE_QUOTA_EXCEEDED" // 模块配额超限
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

// ErrorType 返回错误类型
func (e *CertError) ErrorType() ErrorType {
	return e.Type
}

// ErrorCode 返回错误代码
func (e *CertError) ErrorCode() ErrorCode {
	return e.Code
}

// ErrorDetails 返回错误详情
func (e *CertError) ErrorDetails() map[string]interface{} {
	return e.Details
}

// ErrorSuggestions 返回解决建议
func (e *CertError) ErrorSuggestions() []string {
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
	return sanitizeSecurityError(err)
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
	return sanitizeSecurityError(e)
}

// WithSuggestion 添加解决建议
func (e *CertError) WithSuggestion(suggestion string) *CertError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return sanitizeSecurityError(e)
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
			"该错误码已保留用于向后兼容；新版本中版本相关错误应使用更细粒度的错误码",
			"优先检查是否为 VERSION_FORMAT_INVALID / VERSION_TOO_OLD / VERSION_COMPARE_FAILED")
	case ErrVersionFormatInvalid:
		e.Suggestions = append(e.Suggestions,
			"证书中的版本号格式非法，应为纯数字点分格式(如: 1.0.0)",
			"检查证书签发时的 MinClientVersion 参数")
	case ErrVersionTooOld:
		e.Suggestions = append(e.Suggestions,
			"程序版本过低，请更新到证书要求的最低版本",
			"检查 WithRuntimeVersion 是否设置为真实运行版本")
	case ErrVersionCompareFailed:
		e.Suggestions = append(e.Suggestions,
			"版本比较失败：检查 WithRuntimeVersion 与证书 MinClientVersion 是否为纯数字点分格式",
			"如包含预发布标识（如 -beta），请在签发侧或运行侧做格式归一化")
	case ErrExpiredCertificate:
		e.Suggestions = append(e.Suggestions,
			"请联系管理员更新证书",
			"检查系统时间是否正确",
			"确认证书的有效期设置")
	case ErrMissingRequiredField:
		e.Suggestions = append(e.Suggestions,
			"检查所有必需字段是否已填写",
			"参考文档确认必需字段列表")
	case ErrInvalidRequest:
		e.Suggestions = append(e.Suggestions,
			"证书请求参数不合法：检查必填字段与字段格式",
			"建议使用 NewClientRequest().Build() 以获得更早期的校验错误")
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
	case ErrMachineIDNotAuthorized:
		e.Suggestions = append(e.Suggestions,
			"机器码不匹配：确认传入 ValidateCert 的 machineID 是否与签发时一致",
			"如机器硬件绑定策略变化，请重新签发证书")
	case ErrTimeRollback:
		e.Suggestions = append(e.Suggestions,
			"检测到系统时间回滚，请同步到正确时间",
			"如果时间正确，清除历史时间戳后重试",
			"确保系统时间服务正常运行")
	case ErrHardwareChanged:
		e.Suggestions = append(e.Suggestions,
			"硬件配置发生变化，请重新生成证书",
			"联系管理员更新硬件绑定信息",
			"检查硬件快照是否需要更新")
	case ErrContainerBindingFailed:
		e.Suggestions = append(e.Suggestions,
			"容器环境绑定失败，检查硬件访问权限",
			"确认容器配置允许访问宿主机硬件信息",
			"考虑使用容器级绑定模式")
	case ErrSnapshotExpired:
		e.Suggestions = append(e.Suggestions,
			"硬件快照已过期，请创建新快照",
			"联系管理员延长快照有效期")
	case ErrSnapshotInvalid:
		e.Suggestions = append(e.Suggestions,
			"硬件快照签名验证失败",
			"检查快照文件是否被篡改",
			"确认使用正确的应用标识符")
	case ErrMemoryTampered:
		e.Suggestions = append(e.Suggestions,
			"检测到内存完整性异常：可能存在注入/篡改或内存故障",
			"建议在干净环境重启并复核运行环境安全")
	case ErrVirtualMachineDetected:
		e.Suggestions = append(e.Suggestions,
			"检测到虚拟机/沙箱环境：确认是否在分析/自动化环境中运行",
			"如为合法虚拟化部署，请降低安全级别或配置白名单策略")
	case ErrHardwareBreakpointDetected:
		e.Suggestions = append(e.Suggestions,
			"检测到硬件断点：可能处于调试/分析环境",
			"请在无调试器环境运行，或降低安全级别")
	case ErrDebugPortDetected:
		e.Suggestions = append(e.Suggestions,
			"检测到调试端口：可能处于调试/分析环境",
			"请关闭调试器后重试")
	case ErrDebugObjectDetected:
		e.Suggestions = append(e.Suggestions,
			"检测到调试对象：可能处于调试/分析环境",
			"请关闭调试器后重试")
	case ErrDebugFlagsDetected:
		e.Suggestions = append(e.Suggestions,
			"检测到调试标志异常：可能处于调试/分析环境",
			"请关闭调试器后重试")
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
