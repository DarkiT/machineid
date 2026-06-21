# machineid

[![Go Reference](https://pkg.go.dev/badge/github.com/darkit/machineid.svg)](https://pkg.go.dev/github.com/darkit/machineid)
[![Go Report Card](https://goreportcard.com/badge/github.com/darkit/machineid)](https://goreportcard.com/report/github.com/darkit/machineid)

高性能跨平台机器码生成库，支持多种操作系统和容器环境，提供安全的机器标识与授权管理功能。

![Gopher 47](logo.png)

## 项目简介

machineid 是一个 Go 语言库，用于获取操作系统安装级别的稳定机器标识（Machine ID），提供 HMAC-SHA256 应用绑定保护、硬件指纹增强和多层级容器环境适配能力。在 Linux 平台上，`ID()` 会优先尝试宿主机可见的硬件机器码，仅当硬件特征不可用或不够稳定时才回退到传统 machine-id / 容器标识链路。

本库同时提供 `cert` 子包的完整 PKI 证书授权管理功能，详见 [cert 包文档](cert/README.md)。

### 核心能力

- 获取操作系统原生机器码（Windows / Linux / macOS / FreeBSD / AIX）
- 跨平台容器环境检测（Docker / Containerd / Podman / Kubernetes）
- 基于 HMAC-SHA256 的应用级机器码保护
- 多级硬件指纹增强绑定（硬件指纹 > MAC 绑定 > 纯机器码自动降级）
- 可扩展的自定义绑定提供者、硬件信号提供者和容器特征提供者
- 容器感知的唯一性增强机器码（宿主机唯一 / 容器实例唯一）
- 无管理员权限要求，纯 Go 实现无 CGO 依赖

## 安装

```bash
go get github.com/darkit/machineid
```

安装命令行工具：

```bash
go install github.com/darkit/machineid/cmd/machineid@latest
go install github.com/darkit/machineid/cmd/hardware@latest
go install github.com/darkit/machineid/cmd/authorize@latest
```

## 快速开始

### 基础用法

```go
package main

import (
    "fmt"
    "log"
    "github.com/darkit/machineid"
)

func main() {
    // 获取原始机器码
    id, err := machineid.ID()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("机器码: %s\n", id)

    // 获取应用专属的保护机器码（推荐）
    protectedID, err := machineid.ProtectedID("your.app.id")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("保护机器码: %s\n", protectedID)

    // 获取唯一性增强机器码（默认容器唯一）
    uniqueID, err := machineid.UniqueID("your.app.id")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("唯一机器码: %s\n", uniqueID)
}
```

### 系统信息摘要

```go
info, err := machineid.GetInfo("your.app.id")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("机器码: %s\n", info.MachineID)
fmt.Printf("保护机器码: %s\n", info.ProtectedID)
fmt.Printf("MAC 地址: %s\n", info.MACAddress)
fmt.Printf("是否容器: %t\n", info.IsContainer)
if info.ContainerID != "" {
    fmt.Printf("容器 ID: %s\n", info.ContainerID)
}
```

### 智能硬件绑定与来源诊断

```go
// ProtectedID 自动选择最佳可用的硬件绑定方式
// 优先级：硬件指纹 > MAC 地址 > 纯机器码
bindingResult, err := machineid.ProtectedIDResult("your.app.id")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("保护机器码: %s\n", bindingResult.Hash)
fmt.Printf("绑定模式: %s (提供者: %s)\n", bindingResult.Mode, bindingResult.Provider)

// 宿主机唯一（容器内可切换）
hostUnique, err := machineid.UniqueIDResult("your.app.id", &machineid.UniqueIDOptions{
    EnableContainer: true,
    Mode:            machineid.UniqueIDModeHost,
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("宿主机唯一机器码: %s\n", hostUnique.Hash)
fmt.Printf("来源: %s (容器模式: %s)\n", hostUnique.Provider, hostUnique.ContainerMode)

// 当前 ID 来源诊断
inspection, err := machineid.InspectID()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("当前 ID: %s\n", inspection.ID)
fmt.Printf("来源: %s\n", inspection.Source)
fmt.Printf("是否容器: %t\n", inspection.IsContainer)
fmt.Printf("回退链: %v\n", inspection.FallbackChain)
```

## API 参考

### 基础标识

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `ID()` | 获取原始机器码，Linux 优先宿主机硬件 | `(string, error)` |
| `ProtectedID(appID)` | 获取智能硬件绑定的保护机器码（推荐） | `(string, error)` |
| `ProtectedIDResult(appID)` | 获取保护机器码及完整绑定信息 | `(*BindingResult, error)` |
| `ProtectedIDWithOptions(appID, opts)` | 使用显式 BindingOptions 生成保护机器码 | `(string, error)` |
| `ProtectedIDResultWithOptions(appID, opts)` | 使用显式 BindingOptions 生成保护机器码及绑定信息 | `(*BindingResult, error)` |
| `UniqueID(appID)` | 获取唯一性增强机器码 | `(string, error)` |
| `UniqueIDResult(appID, opts)` | 使用 UniqueIDOptions 获取唯一性增强机器码及绑定信息 | `(*BindingResult, error)` |

### 兼容性 API

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `ProtectedIDWithMAC(appID)` | 使用 MAC 地址绑定的保护机器码 | `(string, error)` |
| `ProtectedIDWithMACResult(appID)` | 使用 MAC 地址绑定的保护机器码及绑定信息 | `(*BindingResult, error)` |
| `ProtectedIDWithHardware(appID)` | 使用硬件指纹绑定的保护机器码 | `(string, error)` |

### 容器感知 API

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `IsContainer()` | 检查是否运行在容器环境 | `bool` |
| `ProtectedIDWithContainerAware(appID, config)` | 容器感知的保护机器码生成 | `(*BindingResult, error)` |
| `ProtectedIDWithContainerAwareWithOptions(appID, config, opts)` | 容器感知保护机器码 + 显式硬件 provider | `(*BindingResult, error)` |

### 系统信息

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `GetInfo(appID)` | 获取完整系统信息摘要（推荐） | `(*Info, error)` |
| `GetMACAddress()` | 获取主网卡 MAC 地址 | `(string, error)` |
| `GetHardwareFingerprint()` | 获取硬件指纹 | `(string, error)` |
| `GetHardwareFingerprintStatus()` | 获取硬件指纹状态（含信号详情） | `(*FingerprintStatus, error)` |
| `GetHardwareFingerprintStatusWithOptions(opts)` | 使用显式 hardware provider 生成指纹状态 | `(*FingerprintStatus, error)` |
| `GetHardwareFingerprintWithOptions(opts)` | 使用显式 hardware provider 生成指纹 | `(string, error)` |
| `InspectID()` | 诊断当前 ID 的来源链路 | `(*IDInspection, error)` |

### Provider / Hint 生命周期管理

以下 API 管理进程级全局注册表，适用于测试隔离、插件宿主和短生命周期扩展场景。

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `RegisterBindingProvider(name, provider)` | 注册自定义绑定提供者（名称唯一） | — |
| `UnregisterBindingProvider(name)` | 移除指定名称的自定义绑定提供者 | `bool` |
| `ResetBindingProviders()` | 清空全部自定义绑定提供者并恢复默认 | — |
| `RegisterNamedHardwareSignalProvider(name, provider)` | 注册具名硬件信号 provider | — |
| `UnregisterHardwareSignalProvider(name)` | 移除指定名称的硬件信号 provider | `bool` |
| `ResetHardwareSignalProviders()` | 清空全部进程级硬件信号 provider | — |
| `RegisterContainerHintProvider(provider)` | 注册自定义容器特征提供者（匿名） | — |
| `RegisterNamedContainerHintProvider(name, provider)` | 注册具名容器特征提供者（名称唯一） | — |
| `UnregisterContainerHintProvider(name)` | 移除指定名称的具名容器特征提供者 | `bool` |
| `ResetContainerHintProviders()` | 清空全部容器特征提供者（匿名 + 具名） | — |
| `ClearCache()` | 清除 ID 和 MAC 地址缓存 | — |
| `ClearHardwareCache()` | 清除硬件指纹缓存 | — |

### 容器 Hint 合成策略

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `GetContainerHintCombineMode()` | 获取容器 scoped ID 的 hint 合成策略 | `ContainerHintCombineMode` |
| `SetContainerHintCombineMode(mode)` | 设置容器 scoped ID 的 hint 合成策略，自动清理 ID 缓存 | `error` |

### 核心类型

#### BindingResult

描述保护 ID 最终采用的绑定模式与降级原因。

```go
type BindingResult struct {
    Hash             string      // 生成的机器码哈希
    Mode             BindingMode // 绑定模式：fingerprint / mac / machine_id / custom
    Provider         string      // 提供者名称
    FingerprintError error       // 硬件指纹获取失败的错误
    MACError         error       // MAC 地址获取失败的错误
    ContainerMode    string      // 容器绑定策略：host / container / hybrid / none
    ContainerID      string      // 容器 ID（如果检测到）
}
```

#### Info

完整的系统信息摘要。

```go
type Info struct {
    MachineID   string `json:"machine_id"`
    ProtectedID string `json:"protected_id"`
    MACAddress  string `json:"mac_address,omitempty"`
    IsContainer bool   `json:"is_container"`
    ContainerID string `json:"container_id,omitempty"`
}
```

#### IDInspection

当前 ID 的来源诊断信息。

```go
type IDInspection struct {
    ID                       string     `json:"id"`
    Source                   IDSource   `json:"source"`
    IsContainer              bool       `json:"is_container"`
    ContainerID              string     `json:"container_id,omitempty"`
    HostHardwareAvailable    bool       `json:"host_hardware_available,omitempty"`
    ContainerScopedAvailable bool       `json:"container_scoped_available,omitempty"`
    FallbackChain            []IDSource `json:"fallback_chain,omitempty"`
}
```

#### FingerprintStatus

硬件指纹的值与稳定性信息。

```go
type FingerprintStatus struct {
    Value       string            // 指纹值
    Stable      bool              // 是否稳定
    Signals     []HardwareSignal  // 参与计算的信号列表
    Sources     []string          // 信号来源
    TotalWeight int               // 总权重
}
```

#### HardwareSignal

参与硬件指纹计算的单条信号。

```go
type HardwareSignal struct {
    Name   string        // 信号名称
    Value  string        // 信号值
    Weight int           // 权重
    Strong bool          // 是否强宿主级特征
    Scope  HardwareScope // 语义范围：firmware / storage / cpu / network / runtime
    Source string        // 来源标识
}
```

#### ContainerBindingConfig

容器绑定的策略配置。

```go
type ContainerBindingConfig struct {
    Mode                ContainerBindingMode       // 绑定模式：auto / host / container
    PreferHostHardware  bool                       // 优先使用宿主机硬件
    FallbackToContainer bool                       // 宿主机硬件不可用时允许降级
    PersistentVolume    string                     // 持久卷路径（用于容器级标识持久化）
    HintCombineMode     *ContainerHintCombineMode  // 容器特征合成策略
}
```

#### UniqueIDOptions

唯一性增强机器码的生成选项。

```go
type UniqueIDOptions struct {
    EnableContainer       bool                     // 启用容器感知逻辑
    ContainerConfig       *ContainerBindingConfig  // 容器绑定配置
    Mode                  UniqueIDMode             // 唯一性策略：容器唯一 / 宿主机唯一
    EnableCustomProviders bool                     // 是否启用自定义绑定提供者
    ForceMACBinding       bool                     // 是否强制 MAC 绑定
    Hardware              *HardwareOptions          // 硬件信号来源控制
}
```

## 自定义扩展

### 自定义绑定提供者

当内置硬件指纹和 MAC 绑定不可用时，`ProtectedID` 会尝试自定义提供者。

```go
machineid.RegisterBindingProvider("disk", func(appID, machineID string) (string, bool, error) {
    serial, err := readDiskSerial()
    if err != nil || serial == "" {
        return "", false, err
    }
    return serial, true, nil
})
```

返回结果中 `Mode` 为 `custom`，`Provider` 为 `"disk"`。

### 自定义硬件信号提供者

如果需要在主硬件指纹链中注入额外的信号（而非仅作为 fallback），可注册 `HardwareSignalProvider`：

```go
provider := machineid.HardwareSignalProviderFunc(func(ctx context.Context) ([]machineid.HardwareSignal, error) {
    return []machineid.HardwareSignal{
        {
            Name:   "asset_tag",
            Value:  "rack-a/host-42",
            Weight: 220,
            Strong: true,
            Scope:  machineid.HardwareScopeFirmware,
            Source: "inventory-agent",
        },
    }, nil
})

machineid.RegisterNamedHardwareSignalProvider("inventory", provider)
defer machineid.UnregisterHardwareSignalProvider("inventory")

result, err := machineid.ProtectedIDResultWithOptions("your.app.id", &machineid.BindingOptions{
    Hardware: &machineid.HardwareOptions{
        Provider: provider,
        Mode:     machineid.HardwareProviderAppend, // 追加到内建信号之后
    },
})
```

推荐实践：

- 扩展最终绑定 fallback：使用 `RegisterBindingProvider()`
- 扩展主硬件指纹链：使用 `HardwareSignalProvider`
- 业务调用优先走 per-call 的 `HardwareOptions`
- 进程级 `RegisterNamedHardwareSignalProvider()` 适合测试、插件宿主或企业 agent 集成

### 容器特征扩展

Kubernetes 环境下，容器指纹会自动纳入 Pod/Node 相关环境变量（`POD_UID`、`POD_NAME`、`POD_NAMESPACE`、`NODE_NAME`、`KUBERNETES_POD_UID`、`K8S_POD_UID` 等）。如需补充自定义 hint：

```go
machineid.RegisterNamedContainerHintProvider("my-hint", func() []string {
    return []string{"cluster-x", "region-us-east"}
})
```

## 容器环境适配指南

### 上层 API 优先使用 Config 控制（推荐）

业务逻辑应通过 `ContainerBindingConfig.HintCombineMode` 按调用控制语义，而不是依赖进程级全局开关：

```go
combineMode := machineid.ContainerHintCombineAll
cfg := &machineid.ContainerBindingConfig{
    Mode:                machineid.ContainerBindingContainer,
    PreferHostHardware:  false,
    FallbackToContainer: true,
    PersistentVolume:    "/var/lib/your-app",
    HintCombineMode:     &combineMode,
}

result, err := machineid.UniqueIDResult("your.app.id", &machineid.UniqueIDOptions{
    EnableContainer: true,
    ContainerConfig: cfg,
    Mode:            machineid.UniqueIDModeContainer,
})
```

### 仅在兼容旧代码时使用全局开关

```go
// 仅在需要调整底层 ID() 容器 fallback 行为时使用
if err := machineid.SetContainerHintCombineMode(machineid.ContainerHintCombineAll); err != nil {
    log.Fatal(err)
}
id, err := machineid.ID()
```

### 重要语义边界

- `ID()` 是底层 raw identity，在 Linux 上优先选择宿主可见硬件机器码，不论当前进程是在容器里还是宿主机上；只有硬件特征不可见或不够稳定时才回退到 machine-id / container fallback。
- `UniqueIDModeHost` / `UniqueIDModeContainer` 是更高层的业务语义开关：前者表示尽量绑定宿主/VM，后者表示尽量绑定容器实例。显式传入 `UniqueIDOptions` 时需要同时设置 `EnableContainer: true`。

## 工作原理

### 机器码来源

| 操作系统 | 主要来源 | 备用来源 |
|----------|----------|----------|
| Windows | 注册表 `MachineGuid` | — |
| Linux | `/var/lib/dbus/machine-id` | `/etc/machine-id`、`$HOME/.config/machine-id` |
| macOS | `IOPlatformUUID` | — |
| FreeBSD | `/etc/hostid` | `smbios.system.uuid` |
| AIX | `uname -u` | — |

### 容器环境检测

**Linux**：
- 检查 `/proc/self/cgroup` 和 `/proc/self/mountinfo`
- 支持 Docker、Containerd、Podman 等容器运行时
- 环境变量：`CONTAINER_ID`、`DOCKER_CONTAINER_ID`

**其他平台**：
- 检查 `/.dockerenv` 文件
- 环境变量检测

### 安全设计

1. 原始机器码应视为机密信息，生产环境建议使用 `ProtectedID()` 而非 `ID()`
2. HMAC-SHA256 用于应用绑定，返回 64 位十六进制字符串
3. `ProtectedID()` 自动选择最佳可用的硬件绑定方式，优先级：硬件指纹 > MAC 地址 > 纯机器码

## 命令行工具

```bash
# 获取原始机器码
machineid

# 获取应用专属机器码
machineid --appid MyApp

# 获取硬件指纹与系统诊断
hardware

# 证书授权管理演示
authorize

# 输出示例
# 原始: 8245d07ef271816592fbd6172e521a945bdc4e3dca2fd91ef57cddf5a298b73f
# 应用专属: DCEF03E8DB3B602695BAFE227E6CC73180807D3A0FDAB459EC0A8FA2DCA1E99E
```

## 构建与测试

### 构建

```bash
# 构建当前架构
make build

# 构建所有平台
make build-all

# 构建常用平台 (Linux, Windows, macOS)
make build-common

# 查看构建信息
make info
```

支持的目标平台：`linux/amd64`、`linux/arm64`、`linux/arm`、`windows/amd64`、`windows/arm64`、`darwin/amd64`、`darwin/arm64`、`freebsd/amd64`。

### 测试

```bash
# 运行所有测试
make test

# 运行竞态检测测试
make test-race

# 基准测试
make benchmark

# 查看测试覆盖率
make cover

# 跨平台编译兼容性检测
make check-cross-builds
```

### 代码质量

```bash
# 代码格式化
make fmt

# 静态检查
make lint

# 安全检查
make vet
```

## 迁移指南

### 从原版 denisbrodbeck/machineid 迁移

本版本与原版 API 完全兼容，主要改进：

1. `ProtectedID` 智能优化：自动选择最佳硬件绑定方式
2. 新增容器检测、系统信息、缓存机制
3. 性能优化：并发安全、智能缓存（成功 5min / 失败 10s TTL）
4. 扩展模块：证书授权管理（`cert` 子包）
5. 可扩展的 provider / hint 体系

### 兼容性

```go
// 原版用法（仍然支持）
id, _ := machineid.ID()
protectedID, _ := machineid.ProtectedID("app")

// 推荐用法
info, _ := machineid.GetInfo("app")
// 使用 info.MachineID 和 info.ProtectedID
```

## 已知限制

1. **虚拟机克隆**：克隆的虚拟机可能具有相同的机器码
2. **系统重装**：重装操作系统通常会改变机器码
3. **容器环境**：优先使用宿主可见硬件机器码；若硬件特征不可见或不够稳定，则回退到 container-scoped / container ID，重新创建容器时可能变化
4. **镜像环境**：基于相同模板创建的镜像可能共享相同的 machine-id

## 相关链接

- [Go Package Reference](https://pkg.go.dev/github.com/darkit/machineid)
- [原始项目](https://github.com/denisbrodbeck/machineid)
- [machine-id(5) 手册](http://man7.org/linux/man-pages/man5/machine-id.5.html)
- [Windows MachineGuid 文档](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct)

## 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 致谢

- 原始项目作者 [Denis Brodbeck](https://github.com/denisbrodbeck)
- Go Gopher 图标由 [Renee French](http://reneefrench.blogspot.com/) 设计，遵循 [Creative Commons Attribution 3.0](https://creativecommons.org/licenses/by/3.0/) 许可
