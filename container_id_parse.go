package machineid

import "strings"

const (
	minContainerIDLen = 12
	maxContainerIDLen = 64
)

func normalizeContainerIDCandidate(segment string) string {
	candidate := strings.TrimSpace(segment)
	candidate = strings.Trim(candidate, " \"'")
	if candidate == "" {
		return ""
	}

	// 移除常见容器运行时前缀
	prefixes := []string{
		"docker-", "docker:",
		"cri-containerd-", "containerd://", "containerd-",
		"crio-", "cri-o://",
		"libpod-", "podman-",
		"sandbox-",
		"kubepods-burstable-", "kubepods-besteffort-", "kubepods-guaranteed-", "kubepods-",
		"pod-", "task-", "run-",
	}
	for _, prefix := range prefixes {
		candidate = strings.TrimPrefix(candidate, prefix)
	}

	// 移除常见后缀
	suffixes := []string{".scope", ".slice", ".service"}
	for _, suffix := range suffixes {
		candidate = strings.TrimSuffix(candidate, suffix)
	}

	candidate = strings.Trim(candidate, ":-._")

	// 从开头截取（保留容器 ID 的有效部分，而非末尾）
	if len(candidate) > maxContainerIDLen {
		candidate = candidate[:maxContainerIDLen]
	}

	// 验证长度和格式
	if len(candidate) >= minContainerIDLen && len(candidate) <= maxContainerIDLen {
		// 优先检查纯十六进制（标准容器 ID）
		if isHexString(candidate) {
			return candidate
		}
		// 放宽限制：允许字母数字混合（某些运行时使用非纯十六进制 ID）
		if isAlphanumericString(candidate) {
			return candidate
		}
	}
	return ""
}

// isAlphanumericString 检查字符串是否仅包含字母和数字
func isAlphanumericString(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			continue
		}
		return false
	}
	return true
}
