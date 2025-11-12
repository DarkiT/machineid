//go:build linux
// +build linux

package machineid

import "testing"

// TestIsHexString 校验十六进制字符串判断逻辑
func TestIsHexString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"全部小写", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true},
		{"全部大写", "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890", true},
		{"混合大小写", "AaBbCc1234", true},
		{"包含非十六进制字符", "abcdex", false},
		{"空字符串", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHexString(tt.input); got != tt.want {
				t.Fatalf("期望 %v, 实际 %v (输入: %q)", tt.want, got, tt.input)
			}
		})
	}
}
