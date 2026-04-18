package cert

import "testing"

func TestSecurityErrorSanitize_EnabledMasksDetails(t *testing.T) {
	t.Parallel()
	SetSecurityErrorSanitizeEnabled(true)

	err := NewSecurityError(ErrDebuggerDetected, "debugger detected", errDummy{}).
		WithDetail("foo", "bar").
		WithSuggestion("do something")

	ce := err
	if ce.Message == "debugger detected" {
		t.Fatalf("脱敏开启时不应暴露原始 message")
	}
	if len(ce.Details) != 0 {
		t.Fatalf("脱敏开启时 details 应为空: %#v", ce.Details)
	}
	if len(ce.Suggestions) != 0 {
		t.Fatalf("脱敏开启时 suggestions 应为空: %#v", ce.Suggestions)
	}
	if ce.Cause != nil {
		t.Fatalf("脱敏开启时 cause 应为空: %#v", ce.Cause)
	}
}

func TestSecurityErrorSanitize_DisabledKeepsDetails(t *testing.T) {
	// 该测试依赖全局开关，避免并行导致其他测试覆盖。
	SetSecurityErrorSanitizeEnabled(false)
	t.Cleanup(func() { SetSecurityErrorSanitizeEnabled(true) })

	err := NewSecurityError(ErrDebuggerDetected, "debugger detected", errDummy{}).
		WithDetail("foo", "bar").
		WithSuggestion("do something")

	ce := err
	if ce.Message != "debugger detected" {
		t.Fatalf("脱敏关闭时应保留 message: %s", ce.Message)
	}
	if ce.Details["foo"] != "bar" {
		t.Fatalf("脱敏关闭时应保留 details: %#v", ce.Details)
	}
	if len(ce.Suggestions) == 0 {
		t.Fatalf("脱敏关闭时应保留 suggestions")
	}
	if ce.Cause == nil {
		t.Fatalf("脱敏关闭时应保留 cause")
	}
}

type errDummy struct{}

func (errDummy) Error() string { return "dummy" }
