package cert

import "sync/atomic"

// 安全错误信息脱敏开关。
//
// 默认开启（生产安全），避免向攻击者暴露具体检测点与细节。
// 调试/CI 场景可显式关闭以获得更丰富的诊断信息。
var securityErrorSanitizeEnabled atomic.Bool

func init() {
	securityErrorSanitizeEnabled.Store(true)
}

// SetSecurityErrorSanitizeEnabled 设置安全错误信息脱敏开关。
func SetSecurityErrorSanitizeEnabled(enabled bool) {
	securityErrorSanitizeEnabled.Store(enabled)
}

func isSecurityErrorSanitizeEnabled() bool {
	return securityErrorSanitizeEnabled.Load()
}

func sanitizeSecurityError(err *CertError) *CertError {
	if err == nil {
		return nil
	}
	if err.Type != SecurityError {
		return err
	}
	if !isSecurityErrorSanitizeEnabled() {
		return err
	}

	// 生产默认：
	// - message 统一为不泄露细节的短语
	// - details 清空
	// - suggestions 清空
	// - cause 清空（避免透出 syscall/路径/内部实现信息）
	err.Message = "security check failed"
	err.Details = make(map[string]interface{})
	err.Suggestions = nil
	err.Cause = nil
	return err
}
