//go:build linux
// +build linux

package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

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

func TestNormalizeContainerIDCandidate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{"空字符串", "", ""},
		{"短ID", "abc123", ""},
		{"Docker Scope", "docker-1234567890abcdef.scope", "1234567890abcdef"},
		{"Containerd URL", "containerd://0123456789abcdef0123", "0123456789abcdef0123"},
		{"Libpod", "libpod-abcdefabcdefabcdefabcd", "abcdefabcdefabcdefabcd"},
		{"非十六进制", "docker-xyz.scope", ""},
	}

	for _, tt := range tests {
		if got := normalizeContainerIDCandidate(tt.in); got != tt.out {
			t.Fatalf("%s: 期望 %q, 实际 %q", tt.name, tt.out, got)
		}
	}
}

func TestContainerScopedIDFromHints(t *testing.T) {
	base := "base-id"
	hint := "hint-value"
	got := containerScopedIDFromHints(base, hint)
	if got == "" {
		t.Fatal("期望返回非空哈希")
	}
	sum := sha256.Sum256([]byte(base + ":" + hint))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("哈希结果不匹配, 期望 %s, 实际 %s", want, got)
	}
	if other := containerScopedIDFromHints(base, "", "second"); other == "" {
		t.Fatal("存在有效 hint 时不应为空")
	}
	if none := containerScopedIDFromHints(base); none != "" {
		t.Fatalf("没有 hint 时应返回空, 实际 %s", none)
	}
}
