# machineid

[![GoDoc](https://godoc.org/github.com/darkit/machineid?status.svg)](https://godoc.org/github.com/darkit/machineid) [![Go Report Card](https://goreportcard.com/badge/github.com/darkit/machineid)](https://goreportcard.com/report/github.com/darkit/machineid)

高性能跨平台机器码生成库，支持多种操作系统和容器环境，提供安全的机器标识和授权管理功能。

![Image of Gopher 47](logo.png)

## ✨ 主要特性

### 🚀 核心功能
- **跨平台支持** - 支持 Windows、Linux、macOS、FreeBSD、AIX 等多种操作系统
- **容器环境适配** - 自动检测和适配 Docker、Containerd 等容器运行时
- **无管理员权限** - 所有功能均无需管理员或 root 权限
- **简洁稳定** - 核心功能基于系统机器码，可选硬件绑定增强安全性

### 🔒 安全特性
- **HMAC-SHA256 加密** - 使用加密安全的哈希算法保护机器标识
- **应用级绑定** - 支持应用特定的机器码生成
- **MAC 地址绑定** - 可选的硬件绑定增强安全性
- **证书授权管理** - 完整的 PKI 证书签发和验证系统

### ⚡ 性能优化
- **智能缓存** - 内存缓存机制减少重复计算
- **并发安全** - 全面的并发保护和线程安全设计
- **快速响应** - 优化的算法确保毫秒级响应

## 📦 安装

```bash
go get github.com/darkit/machineid
```

命令行工具安装：
```bash
go install github.com/darkit/machineid/cmd/machineid@latest
```

## 🚀 快速开始

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
    
    // 获取应用专属的受保护机器码（推荐）
    protectedID, err := machineid.ProtectedID("your.app.id")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("受保护机器码: %s\n", protectedID)
}
```

### 高级功能

```go
package main

import (
    "fmt"
    "log"
    "github.com/darkit/machineid"
)

func main() {
    // 获取系统信息摘要
    info, err := machineid.GetInfo("your.app.id")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("机器码: %s\n", info.MachineID)
    fmt.Printf("受保护机器码: %s\n", info.ProtectedID)
    fmt.Printf("MAC地址: %s\n", info.MACAddress)
    fmt.Printf("是否为容器: %t\n", info.IsContainer)
    if info.ContainerID != "" {
        fmt.Printf("容器ID: %s\n", info.ContainerID)
    }
}
```

### 智能硬件绑定

```go
// ProtectedID 现在自动使用最佳可用的硬件绑定方式
// 优先级：硬件指纹 > MAC地址 > 纯机器码
protectedID, err := machineid.ProtectedID("your.app.id")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("智能保护机器码: %s\n", protectedID)

// 直接获取MAC地址（可选）
macAddr, err := machineid.GetMACAddress()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("主网卡MAC: %s\n", macAddr)
```

### 自定义绑定提供者

如果需要扩展绑定来源（例如磁盘序列号、云厂商元数据），可以注册自定义提供者：

```go
machineid.RegisterBindingProvider("disk", func(appID, machineID string) (string, bool, error) {
    serial, err := readDiskSerial()
    if err != nil || serial == "" {
        return "", false, err
    }
    return serial, true, nil
})
```

当内置硬件指纹和 MAC 绑定不可用时，`ProtectedID` 会尝试自定义提供者，并在 `BindingResult` 中返回 `Mode="custom"`、`Provider="disk"` 等信息。

### 容器环境检测

```go
// 检查是否运行在容器中
if machineid.IsContainer() {
    fmt.Println("运行在容器环境中")
} else {
    fmt.Println("运行在物理机或虚拟机中")
}
```

## 🔧 API 参考

### 核心函数

| 函数 | 描述 | 返回值 |
|------|------|--------|
| `ID()` | 获取原始机器码 | `(string, error)` |
| `ProtectedID(appID)` | **获取智能硬件绑定的保护机器码（推荐）** | `(string, error)` |
| `GetInfo(appID)` | **获取完整系统信息（推荐）** | `(*Info, error)` |
| `GetMACAddress()` | 获取主网卡MAC地址 | `(string, error)` |
| `IsContainer()` | 检查是否在容器环境 | `bool` |
| `ClearCache()` | 清除所有缓存 | `void` |

### Info 结构体

```go
type Info struct {
    MachineID   string `json:"machine_id"`            // 原始机器码
    ProtectedID string `json:"protected_id"`          // 智能保护机器码
    MACAddress  string `json:"mac_address,omitempty"` // MAC地址
    IsContainer bool   `json:"is_container"`          // 是否容器环境
    ContainerID string `json:"container_id,omitempty"` // 容器ID
}
```

## 🏗️ 证书授权管理

本库还提供了完整的 PKI 证书管理功能，用于软件授权和客户信息管理。

> 📚 **详细文档**：完整的证书管理功能请参阅 [cert包文档](./cert/README.md)

### 主要功能
- ✅ **CA证书生成** - 自定义根证书和私钥管理
- ✅ **客户端证书签发** - 基于机器码的证书签发
- ✅ **证书验证** - 完整的证书链验证和有效性检查
- ✅ **客户信息提取** - 从证书中提取完整客户资料
- ✅ **智能监控** - 自动监控证书状态和到期预警
- ✅ **安全防护** - 4级安全防护(反调试、虚拟机检测等)
- ✅ **批量处理** - 大规模证书操作支持

### 基础授权管理

```go
package main

import (
    "time"
    "github.com/darkit/machineid"
    "github.com/darkit/machineid/cert"
)

func main() {
    // 创建授权管理器（默认开发友好，无安全检查）
    auth, err := cert.NewAuthorizer().
        WithRuntimeVersion("2.5.0"). // 设置当前运行的软件版本
        Build()
    if err != nil {
        panic(err)
    }

    // 获取机器码（使用标准ProtectedIDResult 以保留绑定来源）
    bindingResult, _ := machineid.ProtectedIDResult("your.app.id")
    machineID := bindingResult.Hash

    // 构建证书请求
    request, err := cert.NewClientRequest().
        WithMachineID(machineID).
        WithBindingResult(bindingResult).
        WithExpiry(time.Now().AddDate(1, 0, 0)).
        WithCompany("示例科技公司", "研发部").
        WithContact("张经理", "13800138000", "zhang@example.com").
        WithMinClientVersion("2.0.0").
        WithValidityDays(365).
        Build()

    // 签发证书
    certificate, err := auth.IssueClientCert(request)
    if err != nil {
        panic(err)
    }

    // 验证证书
    err = auth.ValidateCert(certificate.CertPEM, machineID)
    if err != nil {
        panic(err)
    }

    // 提取客户信息
    clientInfo, err := auth.ExtractClientInfo(certificate.CertPEM)
    if err == nil {
        fmt.Printf("授权给: %s (%s)\n", clientInfo.CompanyName, clientInfo.ContactPerson)
        fmt.Printf("联系方式: %s\n", clientInfo.ContactEmail)
        fmt.Printf("绑定模式: %s\n", clientInfo.BindingMode)
        fmt.Printf("绑定提供者: %s\n", clientInfo.BindingProvider)
        fmt.Printf("到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02"))
    }

    // 启动智能监控（可选）
    watchCallback := func(event cert.WatchEvent, info *cert.ClientInfo, err error) {
        switch event {
        case cert.WatchEventExpiring:
            fmt.Printf("警告: 证书即将到期 - %s\n", info.CompanyName)
        case cert.WatchEventExpired:
            fmt.Printf("紧急: 证书已过期 - %s\n", info.CompanyName)
        }
    }
    
    // 启动监控（1小时检查间隔，7天预警期）
    watcher, _ := auth.Watch(certificate.CertPEM, machineID, watchCallback)
    defer watcher.Stop()
}
```

> 💡 **版本提示**：`WithRuntimeVersion` 表示当前正在运行的软件实际版本，用于校验证书要求；`WithMinClientVersion` 表示签发证书时要求客户端至少达到的版本，两者互不冲突。

### 环境配置和安全等级

```go
// 开发环境（无安全检查，推荐）
devAuth, _ := cert.ForDevelopment().Build()

// 生产环境（基础安全检查）
prodAuth, _ := cert.ForProduction().Build()

// 高安全环境（完整反调试保护）
secureAuth, _ := cert.NewAuthorizer().WithSecureDefaults().Build()

// 关键系统（最高安全级别）
criticalAuth, _ := cert.NewAuthorizer().WithCriticalSecurity().Build()
```

### 证书管理新增功能

#### 客户信息提取

```go
// 从任何证书中提取完整的客户信息
clientInfo, err := auth.ExtractClientInfo(certPEM)
if err != nil {
    // 处理错误
}

fmt.Printf("公司: %s\n", clientInfo.CompanyName)
fmt.Printf("联系人: %s (%s)\n", clientInfo.ContactPerson, clientInfo.ContactEmail)
fmt.Printf("到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02"))
```

#### 智能监控回调

```go
// 定义监控回调处理不同事件
watchCallback := func(event cert.WatchEvent, clientInfo *cert.ClientInfo, err error) {
    switch event {
    case cert.WatchEventExpiring:
        // 证书即将到期（默认7天预警）
        sendRenewalNotification(clientInfo)
    case cert.WatchEventExpired:
        // 证书已过期
        disableService(clientInfo)
    case cert.WatchEventRevoked:
        // 证书被吊销
        handleSecurityIncident(clientInfo)
    }
}

// 启动监控（支持自定义间隔）
watcher, err := auth.Watch(certPEM, machineID, watchCallback,
    time.Hour,        // 检查间隔（可选，默认1小时）
    3*24*time.Hour)   // 预警期（可选，默认7天）

// 监控管理器（管理多个证书）
manager := cert.NewWatcherManager()
manager.AddWatcher("license1", watcher1)
manager.AddWatcher("license2", watcher2)
```

## 🔍 工作原理

### 机器码来源

| 操作系统 | 主要来源 | 备用来源 |
|----------|----------|----------|
| **Windows** | 注册表 `MachineGuid` | - |
| **Linux** | `/var/lib/dbus/machine-id` | `/etc/machine-id`, `$HOME/.config/machine-id` |
| **macOS** | `IOPlatformUUID` | - |
| **FreeBSD** | `/etc/hostid` | `smbios.system.uuid` |
| **AIX** | `uname -u` | - |

### 容器环境处理

**Linux 容器检测**：
- 检查 `/proc/self/cgroup` 和 `/proc/self/mountinfo`
- 支持 Docker、Containerd、Podman 等容器运行时
- 环境变量检测：`CONTAINER_ID`、`DOCKER_CONTAINER_ID`

**其他系统**：
- 检查 `/.dockerenv` 文件
- 环境变量检测

### 安全考虑

1. **原始机器码保护**
   - 原始机器码应视为机密信息
   - 生产环境建议使用 `ProtectedID()` 而非 `ID()`

2. **加密算法**
   - 使用 HMAC-SHA256 进行应用绑定
   - 返回64位十六进制字符串

3. **智能硬件绑定**
   - `ProtectedID()` 自动选择最佳可用的硬件绑定方式
   - 优先级：硬件指纹 > MAC地址 > 纯机器码
   - 在不同环境下提供最佳的稳定性和安全性平衡

## 📱 命令行工具

```bash
# 获取原始机器码
machineid

# 获取应用专属机器码
machineid --appid MyApp

# 输出示例
# 原始: 8245d07ef271816592fbd6172e521a945bdc4e3dca2fd91ef57cddf5a298b73f
# 应用专属: DCEF03E8DB3B602695BAFE227E6CC73180807D3A0FDAB459EC0A8FA2DCA1E99E
```

## 🧪 测试

```bash
# 运行所有测试
go test -v

# 运行基准测试
go test -bench=.

# 测试覆盖率
go test -cover
```

## 🔄 迁移指南

### 从原版 denisbrodbeck/machineid 迁移

本版本与原版 API 完全兼容，主要改进包括：

1. **ProtectedID 智能优化**：自动选择最佳硬件绑定方式，提供更好的稳定性
2. **新增功能**：容器检测、系统信息、缓存机制
3. **性能优化**：并发安全、智能缓存
4. **扩展模块**：证书授权管理

### 版本兼容性

```go
// 原版用法（仍然支持）
id, _ := machineid.ID()
protectedID, _ := machineid.ProtectedID("app")

// 新版建议用法
info, _ := machineid.GetInfo("app")
// 使用 info.MachineID 和 info.ProtectedID
```

## 🤝 贡献指南

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📋 已知限制

1. **虚拟机克隆**：克隆的虚拟机可能具有相同的机器码
2. **系统重装**：重装操作系统通常会更改机器码
3. **容器环境**：容器中的机器码基于容器 ID，重新创建容器会改变
4. **Linux 用户目录**：用户级机器码文件 `$HOME/.config/machine-id` 在某些环境下可能不可用

## 🔗 相关链接

- [原始项目](https://github.com/denisbrodbeck/machineid)
- [机器码标准说明](http://man7.org/linux/man-pages/man5/machine-id.5.html)
- [Windows MachineGuid 文档](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct)

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- 原始项目作者 [Denis Brodbeck](https://github.com/denisbrodbeck)
- Go Gopher 图标由 [Renee French](http://reneefrench.blogspot.com/) 设计

---

**⭐ 如果这个项目对你有帮助，请给我们一个 Star！**
