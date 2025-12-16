package machineid

import "sync"

// BindingProviderFunc 提供额外绑定方式
type BindingProviderFunc func(appID, machineID string) (value string, stable bool, err error)

type bindingProvider struct {
	name string
	fn   BindingProviderFunc
}

var (
	bindingProvidersMu sync.RWMutex
	bindingProviders   []bindingProvider
)

// RegisterBindingProvider 注册自定义绑定提供者，名称需唯一
func RegisterBindingProvider(name string, provider BindingProviderFunc) {
	if name == "" || provider == nil {
		return
	}
	bindingProvidersMu.Lock()
	defer bindingProvidersMu.Unlock()
	for i, p := range bindingProviders {
		if p.name == name {
			bindingProviders[i].fn = provider
			return
		}
	}
	bindingProviders = append(bindingProviders, bindingProvider{name: name, fn: provider})
}

func listBindingProviders() []bindingProvider {
	bindingProvidersMu.RLock()
	defer bindingProvidersMu.RUnlock()
	return append([]bindingProvider(nil), bindingProviders...)
}
