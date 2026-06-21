package machineid

import (
	"context"
	"crypto/sha256"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// HardwareScope 描述硬件信号的语义范围，便于诊断指纹组成来源。
type HardwareScope string

const (
	HardwareScopeFirmware HardwareScope = "firmware"
	HardwareScopeStorage  HardwareScope = "storage"
	HardwareScopeCPU      HardwareScope = "cpu"
	HardwareScopeNetwork  HardwareScope = "network"
	HardwareScopeRuntime  HardwareScope = "runtime"
)

// HardwareSignal 描述单条可参与硬件指纹计算的信号。
//
// Weight 表示该信号在当前平台上的稳定性与可信度；Strong 用于标识它是否可视作强宿主级特征。
// Source 用于标识信号来源，例如 builtin/linux、inventory-agent、fixture 等。
type HardwareSignal struct {
	Name   string        `json:"name"`
	Value  string        `json:"value"`
	Weight int           `json:"weight"`
	Strong bool          `json:"strong,omitempty"`
	Scope  HardwareScope `json:"scope,omitempty"`
	Source string        `json:"source,omitempty"`
}

// HardwareSignalProvider 提供可参与硬件指纹计算的信号集合。
type HardwareSignalProvider interface {
	Signals(ctx context.Context) ([]HardwareSignal, error)
}

// HardwareSignalProviderFunc 允许用函数快速实现 HardwareSignalProvider。
type HardwareSignalProviderFunc func(ctx context.Context) ([]HardwareSignal, error)

// Signals 使 HardwareSignalProviderFunc 满足 HardwareSignalProvider 接口。
func (fn HardwareSignalProviderFunc) Signals(ctx context.Context) ([]HardwareSignal, error) {
	return fn(ctx)
}

// HardwareProviderMode 控制外部硬件 provider 与内建信号的组合方式。
type HardwareProviderMode int

const (
	// HardwareProviderAppend 在内建信号与进程级 registry 结果后追加 provider 输出。
	HardwareProviderAppend HardwareProviderMode = iota
	// HardwareProviderReplace 仅使用当前调用显式传入的 provider，忽略内建信号与全局 registry。
	HardwareProviderReplace
)

// HardwareOptions 控制单次调用的硬件信号来源。
type HardwareOptions struct {
	Provider HardwareSignalProvider
	Mode     HardwareProviderMode
}

// BindingOptions 控制 ProtectedID 等绑定 API 的可选行为。
type BindingOptions struct {
	Hardware *HardwareOptions
}

type namedHardwareSignalProvider struct {
	name     string
	provider HardwareSignalProvider
}

var (
	hardwareSignalProvidersMu sync.RWMutex
	hardwareSignalProviders   []namedHardwareSignalProvider
)

// RegisterNamedHardwareSignalProvider 注册具名硬件信号 provider。
//
// 适用于测试夹具、插件宿主或企业内部 agent 注入场景。相同名称会被后注册的 provider 替换。
func RegisterNamedHardwareSignalProvider(name string, provider HardwareSignalProvider) {
	if name == "" || provider == nil {
		return
	}

	hardwareSignalProvidersMu.Lock()
	defer hardwareSignalProvidersMu.Unlock()

	for i, p := range hardwareSignalProviders {
		if p.name == name {
			hardwareSignalProviders[i].provider = provider
			return
		}
	}

	hardwareSignalProviders = append(hardwareSignalProviders, namedHardwareSignalProvider{
		name:     name,
		provider: provider,
	})
}

// UnregisterHardwareSignalProvider 移除指定名称的硬件信号 provider。
func UnregisterHardwareSignalProvider(name string) bool {
	if name == "" {
		return false
	}

	hardwareSignalProvidersMu.Lock()
	defer hardwareSignalProvidersMu.Unlock()

	for i, p := range hardwareSignalProviders {
		if p.name != name {
			continue
		}
		hardwareSignalProviders = append(hardwareSignalProviders[:i], hardwareSignalProviders[i+1:]...)
		return true
	}

	return false
}

// ResetHardwareSignalProviders 清空全部进程级硬件信号 provider。
func ResetHardwareSignalProviders() {
	hardwareSignalProvidersMu.Lock()
	hardwareSignalProviders = nil
	hardwareSignalProvidersMu.Unlock()
}

func listHardwareSignalProviders() []namedHardwareSignalProvider {
	hardwareSignalProvidersMu.RLock()
	defer hardwareSignalProvidersMu.RUnlock()
	return append([]namedHardwareSignalProvider(nil), hardwareSignalProviders...)
}

// GetHardwareFingerprintWithOptions 使用指定 hardware options 生成硬件指纹。
func GetHardwareFingerprintWithOptions(options *HardwareOptions) (string, error) {
	status, err := GetHardwareFingerprintStatusWithOptions(options)
	if err != nil {
		return "", err
	}
	return status.Value, nil
}

// GetHardwareFingerprintStatusWithOptions 返回携带诊断信息的硬件指纹结果。
//
// 当 options 为 nil 时，行为与 GetHardwareFingerprintStatus 完全一致；
// 当设置 Replace 模式时，仅消费当前调用显式提供的 provider。
func GetHardwareFingerprintStatusWithOptions(options *HardwareOptions) (*FingerprintStatus, error) {
	if options == nil {
		return fingerprintStatusProvider()
	}
	return getHardwareFingerprintStatusWithOptionsInternal(options)
}

func defaultFingerprintStatusProvider() (*FingerprintStatus, error) {
	return getHardwareFingerprintStatusWithOptionsInternal(nil)
}

func getHardwareFingerprintStatusWithOptionsInternal(options *HardwareOptions) (*FingerprintStatus, error) {
	signals, err := collectHardwareSignals(context.Background(), options)
	if err != nil {
		return nil, err
	}

	selectThreshold, stableThreshold := builtinHardwareFingerprintPolicy()
	return composeFingerprintStatus(signals, selectThreshold, stableThreshold)
}

func collectHardwareSignals(ctx context.Context, options *HardwareOptions) ([]HardwareSignal, error) {
	opts := normalizeHardwareOptions(options)

	var (
		signals   []HardwareSignal
		firstErr  error
		addSource = func(provider HardwareSignalProvider, fallbackSource string) {
			items, err := signalsFromProvider(ctx, provider, fallbackSource)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			signals = append(signals, items...)
		}
	)

	if opts.Provider != nil && opts.Mode == HardwareProviderReplace {
		addSource(opts.Provider, "custom")
		signals = mergeHardwareSignals(signals)
		if len(signals) == 0 {
			if firstErr != nil {
				return nil, firstErr
			}
			return nil, fmt.Errorf("no hardware signals available")
		}
		return signals, nil
	}

	addSource(hardwareSignalProvider, "builtin")

	for _, provider := range listHardwareSignalProviders() {
		addSource(provider.provider, provider.name)
	}

	if opts.Provider != nil {
		addSource(opts.Provider, "custom")
	}

	signals = mergeHardwareSignals(signals)
	if len(signals) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no hardware signals available")
	}

	return signals, nil
}

func normalizeHardwareOptions(options *HardwareOptions) *HardwareOptions {
	if options == nil {
		return &HardwareOptions{}
	}

	copied := *options
	if copied.Provider == nil && copied.Mode == HardwareProviderReplace {
		copied.Mode = HardwareProviderAppend
	}
	return &copied
}

func signalsFromProvider(ctx context.Context, provider HardwareSignalProvider, fallbackSource string) ([]HardwareSignal, error) {
	if provider == nil {
		return nil, nil
	}

	signals, err := provider.Signals(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]HardwareSignal, 0, len(signals))
	for _, signal := range signals {
		value := strings.TrimSpace(signal.Value)
		if value == "" || signal.Weight <= 0 {
			continue
		}

		name := strings.TrimSpace(signal.Name)
		if name == "" {
			name = fallbackSource
		}
		if name == "" {
			name = "signal"
		}

		source := strings.TrimSpace(signal.Source)
		if source == "" {
			source = fallbackSource
		}

		scope := signal.Scope
		if scope == "" {
			scope = inferHardwareScope(name)
		}

		result = append(result, HardwareSignal{
			Name:   name,
			Value:  value,
			Weight: signal.Weight,
			Strong: signal.Strong,
			Scope:  scope,
			Source: source,
		})
	}

	return result, nil
}

func mergeHardwareSignals(signals []HardwareSignal) []HardwareSignal {
	if len(signals) == 0 {
		return nil
	}

	type mergedSignal struct {
		index  int
		signal HardwareSignal
	}

	merged := make(map[string]mergedSignal, len(signals))
	for i, signal := range signals {
		key := signal.Name + "\x00" + signal.Value
		current, exists := merged[key]
		if !exists {
			merged[key] = mergedSignal{index: i, signal: signal}
			continue
		}

		if signal.Weight > current.signal.Weight {
			current.signal.Weight = signal.Weight
		}
		if signal.Strong {
			current.signal.Strong = true
		}
		if current.signal.Source == "" && signal.Source != "" {
			current.signal.Source = signal.Source
		}
		if current.signal.Scope == "" && signal.Scope != "" {
			current.signal.Scope = signal.Scope
		}
		merged[key] = current
	}

	items := make([]mergedSignal, 0, len(merged))
	for _, item := range merged {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].index < items[j].index
	})

	result := make([]HardwareSignal, 0, len(items))
	for _, item := range items {
		result = append(result, item.signal)
	}
	return result
}

func composeFingerprintStatus(signals []HardwareSignal, selectThreshold, stableThreshold int) (*FingerprintStatus, error) {
	if len(signals) == 0 {
		return nil, fmt.Errorf("no hardware signals available")
	}

	candidates := append([]HardwareSignal(nil), signals...)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Weight != candidates[j].Weight {
			return candidates[i].Weight > candidates[j].Weight
		}
		if candidates[i].Strong != candidates[j].Strong {
			return candidates[i].Strong
		}
		if candidates[i].Name != candidates[j].Name {
			return candidates[i].Name < candidates[j].Name
		}
		return candidates[i].Value < candidates[j].Value
	})

	var (
		components  []string
		selected    []HardwareSignal
		totalWeight int
	)

	for _, signal := range candidates {
		components = append(components, fmt.Sprintf("%s:%s", signal.Name, signal.Value))
		selected = append(selected, signal)
		totalWeight += signal.Weight
		if selectThreshold > 0 && totalWeight >= selectThreshold {
			break
		}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("no valid hardware signals found")
	}

	stable := stableThreshold <= 0 || totalWeight >= stableThreshold
	return &FingerprintStatus{
		Value:       hashHardwareComponents(components),
		Stable:      stable,
		Signals:     selected,
		Sources:     uniqueHardwareSources(selected),
		TotalWeight: totalWeight,
	}, nil
}

func uniqueHardwareSources(signals []HardwareSignal) []string {
	if len(signals) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(signals))
	result := make([]string, 0, len(signals))
	for _, signal := range signals {
		if signal.Source == "" {
			continue
		}
		if _, ok := seen[signal.Source]; ok {
			continue
		}
		seen[signal.Source] = struct{}{}
		result = append(result, signal.Source)
	}

	sort.Strings(result)
	return result
}

func hashHardwareComponents(components []string) string {
	if len(components) == 0 {
		return ""
	}

	sum := sha256Sum(strings.Join(components, "|"))
	return sum
}

func sha256Sum(data string) string {
	sum := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", sum)
}

func hardwareSignalsFromWeights(weights []HardwareWeight, source string) []HardwareSignal {
	if len(weights) == 0 {
		return nil
	}

	signals := make([]HardwareSignal, 0, len(weights))
	for _, weight := range weights {
		value := strings.TrimSpace(weight.Value)
		if value == "" || weight.Weight <= 0 {
			continue
		}

		signals = append(signals, HardwareSignal{
			Name:   weight.Name,
			Value:  value,
			Weight: weight.Weight,
			Strong: weight.Weight >= 80,
			Scope:  inferHardwareScope(weight.Name),
			Source: source,
		})
	}

	return signals
}

func inferHardwareScope(name string) HardwareScope {
	switch name {
	case "product_uuid", "system_uuid", "board_serial", "product_serial", "chassis_serial",
		"uefi_vars", "tpm", "acpi_tables", "bios_version", "system_info":
		return HardwareScopeFirmware
	case "root_uuid", "disk_serial", "nvme_serial":
		return HardwareScopeStorage
	case "cpu_id", "cpu_signature":
		return HardwareScopeCPU
	case "mac", "mac_primary", "mac_address", "nic_pci":
		return HardwareScopeNetwork
	default:
		return HardwareScopeRuntime
	}
}

func builtinHardwareFingerprintPolicy() (selectThreshold, stableThreshold int) {
	switch runtime.GOOS {
	case "linux":
		return 200, 150
	case "windows":
		return 200, 150
	case "darwin":
		return 200, 150
	default:
		return 0, 1
	}
}
