package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// ContainerHintProvider 提供用于容器派生机器码的附加指纹
type ContainerHintProvider func() []string

var (
	containerHintProvidersMu sync.RWMutex
	containerHintProviders   []ContainerHintProvider
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

func collectContainerHints() []string {
	hints := defaultContainerHints()
	containerHintProvidersMu.RLock()
	providers := append([]ContainerHintProvider(nil), containerHintProviders...)
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
	return hints
}

func deriveContainerScopedID(baseID string) string {
	return containerScopedIDFromHints(baseID, collectContainerHints()...)
}

func containerScopedIDFromHints(baseID string, hints ...string) string {
	if baseID == "" {
		return ""
	}
	for _, hint := range hints {
		if hint == "" {
			continue
		}
		sum := sha256.Sum256([]byte(baseID + ":" + hint))
		return hex.EncodeToString(sum[:])
	}
	return ""
}
