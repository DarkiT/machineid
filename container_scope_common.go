package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// ContainerHintProvider 提供用于容器派生机器码的附加指纹
type ContainerHintProvider func() []string

// ContainerHintCombineMode 控制容器 scoped ID 如何消费多个 hint。
type ContainerHintCombineMode int32

const (
	// ContainerHintCombineFirst 保持历史行为：只使用第一条非空 hint。
	ContainerHintCombineFirst ContainerHintCombineMode = iota
	// ContainerHintCombineAll 使用全部非空 hint 按顺序合成容器 scoped ID。
	ContainerHintCombineAll
)

func (m ContainerHintCombineMode) String() string {
	switch m {
	case ContainerHintCombineFirst:
		return "first"
	case ContainerHintCombineAll:
		return "all"
	default:
		return "unknown"
	}
}

var errInvalidContainerHintCombineMode = errors.New("machineid: invalid container hint combine mode")

func isValidContainerHintCombineMode(mode ContainerHintCombineMode) bool {
	switch mode {
	case ContainerHintCombineFirst, ContainerHintCombineAll:
		return true
	default:
		return false
	}
}

func containerHintCombineModePtr(mode ContainerHintCombineMode) *ContainerHintCombineMode {
	value := mode
	return &value
}

func resolveContainerFeatureCombineMode(config *ContainerBindingConfig) ContainerHintCombineMode {
	if config != nil && config.HintCombineMode != nil && isValidContainerHintCombineMode(*config.HintCombineMode) {
		return *config.HintCombineMode
	}
	return ContainerHintCombineAll
}

type namedContainerHintProvider struct {
	name string
	fn   ContainerHintProvider
}

var (
	containerHintProvidersMu    sync.RWMutex
	containerHintProviders      []ContainerHintProvider
	namedContainerHintProviders []namedContainerHintProvider
	containerHintCombineMode    atomic.Int32
	allowK8sEnvHint             = func() bool { return false }
)

// RegisterContainerHintProvider 注册自定义容器指纹提供者
func RegisterContainerHintProvider(provider ContainerHintProvider) {
	if provider == nil {
		return
	}
	containerHintProvidersMu.Lock()
	containerHintProviders = append(containerHintProviders, provider)
	containerHintProvidersMu.Unlock()
}

// RegisterNamedContainerHintProvider 注册具名容器指纹提供者，名称需唯一
func RegisterNamedContainerHintProvider(name string, provider ContainerHintProvider) {
	if name == "" || provider == nil {
		return
	}
	containerHintProvidersMu.Lock()
	defer containerHintProvidersMu.Unlock()
	for i, existing := range namedContainerHintProviders {
		if existing.name == name {
			namedContainerHintProviders[i].fn = provider
			return
		}
	}
	namedContainerHintProviders = append(namedContainerHintProviders, namedContainerHintProvider{name: name, fn: provider})
}

// UnregisterContainerHintProvider 移除指定名称的具名容器指纹提供者
func UnregisterContainerHintProvider(name string) bool {
	if name == "" {
		return false
	}
	containerHintProvidersMu.Lock()
	defer containerHintProvidersMu.Unlock()
	for i, provider := range namedContainerHintProviders {
		if provider.name != name {
			continue
		}
		namedContainerHintProviders = append(namedContainerHintProviders[:i], namedContainerHintProviders[i+1:]...)
		return true
	}
	return false
}

// ResetContainerHintProviders 清空全部自定义容器指纹提供者（含匿名与具名）
func ResetContainerHintProviders() {
	containerHintProvidersMu.Lock()
	containerHintProviders = nil
	namedContainerHintProviders = nil
	containerHintProvidersMu.Unlock()
}

// SetContainerHintCombineMode 设置容器 scoped ID 的 hint 合成策略。
//
// 为保持兼容，默认模式为 ContainerHintCombineFirst；切换模式时会自动清理 ID 缓存。
func SetContainerHintCombineMode(mode ContainerHintCombineMode) error {
	if !isValidContainerHintCombineMode(mode) {
		return errInvalidContainerHintCombineMode
	}
	containerHintCombineMode.Store(int32(mode))
	ClearCache()
	return nil
}

// GetContainerHintCombineMode 返回当前容器 scoped ID 的 hint 合成策略。
func GetContainerHintCombineMode() ContainerHintCombineMode {
	mode := ContainerHintCombineMode(containerHintCombineMode.Load())
	if isValidContainerHintCombineMode(mode) {
		return mode
	}
	return ContainerHintCombineFirst
}

func collectContainerHints() []string {
	hints := defaultContainerHints()
	if allowK8sEnvHint() {
		hints = append(hints, defaultK8sHints()...)
	}
	containerHintProvidersMu.RLock()
	providers := append([]ContainerHintProvider(nil), containerHintProviders...)
	namedProviders := append([]namedContainerHintProvider(nil), namedContainerHintProviders...)
	containerHintProvidersMu.RUnlock()
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		for _, hint := range provider() {
			if hint != "" {
				hints = append(hints, hint)
			}
		}
	}
	for _, provider := range namedProviders {
		if provider.fn == nil {
			continue
		}
		for _, hint := range provider.fn() {
			if hint != "" {
				hints = append(hints, hint)
			}
		}
	}
	return hints
}

func defaultK8sHints() []string {
	var hints []string
	add := func(key, value string) {
		if value == "" {
			return
		}
		hints = append(hints, key+":"+value)
	}

	add("pod_uid", os.Getenv("POD_UID"))
	add("pod_name", os.Getenv("POD_NAME"))
	add("pod_namespace", os.Getenv("POD_NAMESPACE"))
	add("node_name", os.Getenv("NODE_NAME"))

	if uid := os.Getenv("KUBERNETES_POD_UID"); uid != "" {
		add("pod_uid", uid)
	}
	if uid := os.Getenv("K8S_POD_UID"); uid != "" {
		add("pod_uid", uid)
	}

	if pod := os.Getenv("HOSTNAME"); pod != "" && strings.HasPrefix(pod, "pod") {
		add("pod_name", pod)
	}
	return hints
}

func deriveContainerScopedID(baseID string) string {
	return containerScopedIDFromHintsWithMode(baseID, GetContainerHintCombineMode(), collectContainerHints()...)
}

func containerScopedIDFromHints(baseID string, hints ...string) string {
	return containerScopedIDFromHintsWithMode(baseID, ContainerHintCombineFirst, hints...)
}

func containerScopedIDFromHintsWithMode(baseID string, mode ContainerHintCombineMode, hints ...string) string {
	if baseID == "" {
		return ""
	}
	combinedHint := combineContainerHintInput(mode, hints...)
	if combinedHint == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(baseID + ":" + combinedHint))
	return hex.EncodeToString(sum[:])
}

func combineContainerHintInput(mode ContainerHintCombineMode, hints ...string) string {
	filtered := make([]string, 0, len(hints))
	seen := make(map[string]struct{}, len(hints))
	for _, hint := range hints {
		if hint == "" {
			continue
		}
		if _, ok := seen[hint]; ok {
			continue
		}
		seen[hint] = struct{}{}
		filtered = append(filtered, hint)
	}
	if len(filtered) == 0 {
		return ""
	}
	if mode == ContainerHintCombineAll {
		return strings.Join(filtered, "|")
	}
	return filtered[0]
}
