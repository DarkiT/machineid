package cert

import (
	"errors"
	"testing"
)

// TestNewCertificateError 测试证书错误创建
func TestNewCertificateError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		code  ErrorCode
		msg   string
		cause error
	}{
		{
			name:  "无原因错误",
			code:  ErrInvalidCertificate,
			msg:   "证书无效",
			cause: nil,
		},
		{
			name:  "带原因错误",
			code:  ErrInvalidCertificate,
			msg:   "证书解析失败",
			cause: errors.New("PEM decode failed"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewCertificateError(tt.code, tt.msg, tt.cause)

			// 验证错误不为nil
			if err == nil {
				t.Fatal("错误应该不为nil")
			}

			// 验证错误消息
			if err.Error() == "" {
				t.Error("错误消息不应为空")
			}

			// 验证错误代码
			if err.Code != tt.code {
				t.Errorf("错误代码不匹配: 期望 %v, 实际 %v", tt.code, err.Code)
			}
		})
	}
}

// TestCertError_Is 测试错误类型判断
func TestCertError_Is(t *testing.T) {
	t.Parallel()

	baseErr := NewCertificateError(ErrInvalidCertificate, "test error", nil)
	sameCodeErr := NewCertificateError(ErrInvalidCertificate, "another error", nil)
	diffCodeErr := NewCertificateError(ErrExpiredCertificate, "expired", nil)

	// 测试 errors.Is
	if !errors.Is(baseErr, sameCodeErr) {
		t.Error("相同错误代码应该匹配")
	}

	if errors.Is(baseErr, diffCodeErr) {
		t.Error("不同错误代码不应该匹配")
	}
}

// TestCertError_Unwrap 测试错误展开
func TestCertError_Unwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("root cause")
	err := NewCertificateError(ErrInvalidCertificate, "wrapped error", cause)

	// 测试 errors.Unwrap
	unwrapped := errors.Unwrap(err)
	if unwrapped == nil {
		t.Fatal("应该能展开错误")
	}

	if unwrapped.Error() != cause.Error() {
		t.Errorf("展开的错误不匹配: 期望 %v, 实际 %v", cause, unwrapped)
	}
}

// TestNewValidationError 测试验证错误创建
func TestNewValidationError(t *testing.T) {
	t.Parallel()

	err := NewValidationError(ErrMissingRequiredField, "缺少必需字段", nil)

	if err == nil {
		t.Fatal("错误不应为nil")
	}

	// 验证错误代码
	if err.Code != ErrMissingRequiredField {
		t.Errorf("错误代码不匹配: 期望 %v, 实际 %v", ErrMissingRequiredField, err.Code)
	}
}

// TestCertError_WithDetail 测试添加错误详情
func TestCertError_WithDetail(t *testing.T) {
	t.Parallel()

	err := NewCertificateError(ErrInvalidCertificate, "test error", nil)

	// 添加详情
	detailedErr := err.WithDetail("key1", "value1").WithDetail("key2", 123)

	// 验证详情
	if len(detailedErr.Details) != 2 {
		t.Errorf("详情数量不匹配: 期望 2, 实际 %d", len(detailedErr.Details))
	}
}

// TestErrorCodes 测试所有错误代码定义
func TestErrorCodes(t *testing.T) {
	t.Parallel()

	codes := []ErrorCode{
		ErrInvalidCertificate,
		ErrExpiredCertificate,
		ErrInvalidMachineID,
		ErrInvalidVersion,
		ErrCertificateRevoked,
		ErrMissingRequiredField,
		ErrDebuggerDetected,
		ErrTimeManipulation,
		ErrInvalidCAConfig,
		ErrSystemClockSkew,
	}

	for _, code := range codes {
		code := code
		t.Run(string(code), func(t *testing.T) {
			t.Parallel()

			// 创建错误
			err := NewCertificateError(code, "test", nil)
			if err == nil {
				t.Fatal("错误不应为nil")
			}

			// 验证错误码
			if err.Code != code {
				t.Errorf("错误代码不匹配: 期望 %v, 实际 %v", code, err.Code)
			}
		})
	}
}
