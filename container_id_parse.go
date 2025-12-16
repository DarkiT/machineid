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
	for _, prefix := range []string{"docker-", "docker:", "cri-containerd-", "containerd://", "crio-", "libpod-", "sandbox-", "kubepods-burstable-", "kubepods-best-effort-", "kubepods-", "pod-", "task-", "run-"} {
		candidate = strings.TrimPrefix(candidate, prefix)
	}
	candidate = strings.TrimSuffix(candidate, ".scope")
	candidate = strings.Trim(candidate, ":-._")
	if len(candidate) > maxContainerIDLen {
		candidate = candidate[len(candidate)-maxContainerIDLen:]
	}
	if len(candidate) >= minContainerIDLen && len(candidate) <= maxContainerIDLen && isHexString(candidate) {
		return candidate
	}
	return ""
}
