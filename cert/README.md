# Cert 企业级软件授权管理解决方案

`cert` 包是一个功能完整的企业级软件授权管理解决方案，提供证书签发、验证、吊销以及**可选的**安全防护功能。专为需要软件许可控制的应用程序设计，**默认开发友好，按需启用安全保护**。

## 🚀 主要特性

### 📜 证书管理

- **CA 证书生成**：支持自定义 CA 证书和私钥管理
- **Ed25519 签名算法**：使用现代高效的 Ed25519 椭圆曲线签名，提供高安全性和优异性能
- **客户端证书签发**：基于机器码的证书签发系统
- **证书验证**：完整的证书链验证和有效性检查
- **证书吊销**：动态吊销列表管理和实时更新
- **批量处理**：支持大规模证书批量签发和验证

### 🛡️ 安全防护（可选）

- **分级保护**：4 个安全级别，从禁用到关键防护
- **反调试保护**：多层次调试器检测和防护机制
- **环境检测**：虚拟机和沙箱环境识别
- **进程保护**：DLL 注入和代码注入检测
- **时间篡改检测**：系统时间验证和时钟偏差检查
- **完整性验证**：程序完整性校验和内存保护
- **硬件绑定**：基于机器码的硬件绑定验证

### 📊 授权管理

- **版本控制**：强制版本更新和兼容性管理
- **有效期管理**：灵活的证书生命周期控制
- **授权管理**：完整的客户信息和联系方式管理
- **智能监控**：自动监控证书状态，及时通知到期和异常事件
- **缓存优化**：智能缓存机制提升验证性能
- **配置管理**：灵活的配置系统支持多环境部署

### 🎯 模块级授权（新增）

- **模块权限控制**：按模块授权，支持启用/禁用、配额限制
- **时间段授权**：模块级独立有效期，支持 NotBefore/NotAfter
- **统一授权接口**：证书和 License 统一访问方式
- **自动格式识别**：自动识别 PEM 证书或 JSON License
- **批量模块验证**：一次验证多个模块权限

## 📦 安装

```bash
go get github.com/darkit/machineid/cert
```

## ⚡ 快速开始

### 1. 创建授权管理器

```go
import "github.com/darkit/machineid/cert"

// 开发环境（完全禁用安全检查，推荐）
auth, err := cert.ForDevelopment().Build()
if err != nil {
    log.Fatal("创建授权管理器失败:", err)
}

// 生产环境（基础安全检查）
prodAuth, err := cert.ForProduction().Build()

// 默认配置（禁用安全检查）
defaultAuth, err := cert.NewAuthorizer().Build()

// 自定义安全级别
customAuth, err := cert.NewAuthorizer().
    WithRuntimeVersion("2.0.0").
    WithSecurityLevel(2).                 // 高级安全保护
    WithMaxClockSkew(1 * time.Minute).
    Build()
```

### 2. 生成 CA 证书

```go
caInfo := cert.CAInfo{
    CommonName:   "ZStudio Software",
    Organization: "子说软件工作室",
    Country:      "CN",
    Province:     "Guangdong",
    Locality:     "Guangzhou",
    ValidDays:    3650, // 10年有效期
}

// 生成新的CA证书
err := auth.GenerateCA(caInfo)
if err != nil {
    log.Fatal("生成CA证书失败:", err)
}

// 保存CA证书到指定目录
err = auth.SaveCA("./certificates")
```

### 3. 签发客户端证书

```go
// 构建证书请求
bindingResult, _ := machineid.ProtectedIDResult("your.app.id")
req := &cert.ClientCertRequest{
    Identity: cert.Identity{
        MachineID:      bindingResult.Hash,
        BindingMode:    string(bindingResult.Mode),
        BindingProvider: bindingResult.Provider,
        ExpiryDate:     time.Now().AddDate(1, 0, 0), // 1年有效期
    },
    Company: cert.Company{
        Name:       "客户公司",
        Department: "技术部",
        Address: &cert.Address{
            Country:  "CN",
            Province: "广东省",
            City:     "深圳市",
            Street:   "科技园南路",
        },
    },
    Contact: &cert.Contact{
        Person: "张三",
        Phone:  "13800138000",
        Email:  "zhangsan@example.com",
    },
    Technical: cert.Technical{
        MinClientVersion:   "2.0.0",
        ValidityPeriodDays: 365,
    },
}

// 签发证书
certificate, err := auth.IssueClientCert(req)
if err != nil {
    log.Fatal("签发证书失败:", err)
}

// 保存客户端证书
err = auth.SaveClientCert(certificate, "./client-certificates")
```

### 4. 证书验证（可选安全检查）

```go
// 证书验证（根据安全级别自动执行检查）
err := auth.ValidateCert(certificate.CertPEM, machineID)
if err != nil {
    switch {
    case cert.IsSecurityError(err):
        log.Printf("安全检查失败: %v", err)
        // 处理安全问题：调试器、虚拟机、沙箱等
        // 只有在启用安全检查时才会出现
    case cert.IsValidationError(err):
        log.Printf("证书验证失败: %v", err)
        // 处理证书问题：过期、吊销、机器码不匹配等
    default:
        log.Printf("其他错误: %v", err)
    }
    return
}

log.Println("证书验证成功")

// 手动执行安全检查
if err := auth.PerformSecurityCheck(); err != nil {
    log.Printf("手动安全检查失败: %v", err)
}
```

### 5. 客户信息提取

```go
// 从现有证书中提取完整的客户信息
clientInfo, err := auth.ExtractClientInfo(certificate.CertPEM)
if err != nil {
    log.Fatal("提取客户信息失败:", err)
}

// 显示提取的信息
fmt.Printf("=== 客户授权信息 ===\n")
fmt.Printf("机器ID: %s\n", clientInfo.MachineID)
fmt.Printf("公司名称: %s\n", clientInfo.CompanyName)
fmt.Printf("部门: %s\n", clientInfo.Department)
fmt.Printf("联系人: %s\n", clientInfo.ContactPerson)
fmt.Printf("联系电话: %s\n", clientInfo.ContactPhone)
fmt.Printf("联系邮箱: %s\n", clientInfo.ContactEmail)
fmt.Printf("绑定模式: %s\n", clientInfo.BindingMode)
fmt.Printf("绑定提供者: %s\n", clientInfo.BindingProvider)
fmt.Printf("最低客户端版本: %s\n", clientInfo.MinClientVersion)
fmt.Printf("证书有效期: %d天\n", clientInfo.ValidityPeriodDays)
fmt.Printf("到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02 15:04:05"))

// 应用场景示例
// 1. 客户管理 - 快速获取授权客户联系信息
// 2. 技术支持 - 了解客户使用的软件版本
// 3. 许可审计 - 生成授权使用报告
// 4. 合规检查 - 验证授权分发记录
```

### 6. 授权监控回调

系统提供了智能的授权监控机制，自动定期检查证书状态，并通过回调通知上层应用：

```go
// 定义监控回调函数
watchCallback := func(event cert.WatchEvent, clientInfo *cert.ClientInfo, err error) {
    switch event {
    case cert.WatchEventExpiring:
        log.Printf("警告: 证书即将到期 - %s (%s)",
            clientInfo.CompanyName, clientInfo.ContactPerson)
        // 发送邮件通知、触发续期流程等
        sendRenewalNotification(clientInfo)

    case cert.WatchEventExpired:
        log.Printf("紧急: 证书已过期 - %s", clientInfo.CompanyName)
        // 停止服务、显示过期提示等
        handleExpiredLicense(clientInfo)

    case cert.WatchEventInvalid:
        log.Printf("错误: 证书无效 - %v", err)
        // 重新验证、联系支持等
        handleInvalidCertificate(err)

    case cert.WatchEventRevoked:
        log.Printf("严重: 证书已被吊销 - %s", clientInfo.CompanyName)
        // 立即停止服务、安全审计等
        handleRevokedCertificate(clientInfo)
    }
}

// 启动监控 - 使用默认配置（1小时检查间隔，7天预警期）
watcher, err := auth.Watch(certPEM, machineID, watchCallback)

// 自定义监控间隔和预警期
watcher, err := auth.Watch(certPEM, machineID, watchCallback,
    30*time.Minute,  // 30分钟检查一次
    3*24*time.Hour)  // 3天到期预警

// 高级配置监控
watcher := cert.NewCertWatcher(auth, certPEM, machineID, watchCallback).
    WithCheckInterval(10 * time.Minute).     // 检查间隔
    WithExpiryWarning(24 * time.Hour).       // 预警期
    WithConfig(&cert.WatchConfig{
        EnableRevocationCheck: true,         // 启用吊销检查
        MaxRetries:           5,             // 最大重试次数
        RetryInterval:        2 * time.Minute, // 重试间隔
    })

if err := watcher.Start(); err != nil {
    log.Fatal("启动监控失败:", err)
}

// 获取监控统计
stats := watcher.Stats()
fmt.Printf("检查次数: %v, 运行状态: %v\n",
    stats["check_count"], stats["is_running"])

// 停止监控
watcher.Stop()
```

#### 监控管理器 - 管理多个证书

```go
// 创建监控管理器
manager := cert.NewWatcherManager()

// 添加多个证书监控
watcher1, _ := auth.Watch(cert1PEM, machineID1, callback, time.Hour)
watcher2, _ := auth.Watch(cert2PEM, machineID2, callback, 30*time.Minute)

manager.AddWatcher("license1", watcher1)
manager.AddWatcher("license2", watcher2)

// 获取所有监控统计
allStats := manager.AllStats()
for id, stats := range allStats {
    fmt.Printf("%s: 检查%v次, 运行中=%v\n",
        id, stats["check_count"], stats["is_running"])
}

// 停止所有监控
manager.StopAll()
```

#### 监控事件类型

| 事件                   | 触发条件                   | 建议处理                           |
| ---------------------- | -------------------------- | ---------------------------------- |
| **WatchEventExpiring** | 距离到期时间小于预警期     | 发送续期提醒，准备新证书           |
| **WatchEventExpired**  | 证书已过期                 | 停止服务或显示过期提示             |
| **WatchEventInvalid**  | 证书验证失败或安全检查失败 | 根据回调 err 的 ErrorCode 定位原因 |
| **WatchEventRevoked**  | 证书被加入吊销列表         | 立即停止服务，进行安全审计         |

> 强安全提示：`WatchEventInvalid` 是“总括事件”。具体失败原因请以回调参数 `err` 为准：
>
> - `err` 为 `*CertError` 时，可通过 `err.ErrorCode()` 精确区分原因（例如 `CERTIFICATE_NOT_TRUSTED`、`CERTIFICATE_EXTENSION_MISSING`、`CERTIFICATE_VERSION_MISMATCH`、`INVALID_VERSION`、`UNAUTHORIZED_ACCESS`、`DEBUGGER_DETECTED` 等）。
> - 也可通过 watcher 的 `Stats()` 获取 `last_error_type` / `last_error_code` 进行运维归因。

常见错误码速查：

- `MACHINE_ID_NOT_AUTHORIZED`：传入的 machineID 不在证书授权列表中
- `VERSION_TOO_OLD`：运行版本低于证书要求的最低版本
- `VERSION_FORMAT_INVALID`：证书内 MinClientVersion 格式非法（仅支持纯数字点分格式）
- `VERSION_COMPARE_FAILED`：版本比较失败（通常是运行版本或证书版本格式不符合要求）
- `INVALID_REQUEST`：签发证书时的请求参数不合法（缺字段/格式不符）

兼容提示：

- `INVALID_VERSION`：保留用于向后兼容；新版本中版本相关错误应优先使用更细粒度的错误码

#### 默认监控配置

```go
// 系统默认配置
config := cert.DefaultWatchConfig()
// CheckInterval: 1小时
// ExpiryWarningPeriod: 7天
// EnableExpiryWarning: true
// EnableRevocationCheck: true
// MaxRetries: 3次
// RetryInterval: 5分钟
```

### 7. 证书吊销管理

```go
// 创建吊销管理器
revokeManager, err := cert.NewRevokeManager("1.0.0")

// 吊销特定证书
revokeManager.AddRevocation("证书序列号", "security_breach")

// 检查证书是否被吊销
isRevoked, reason := revokeManager.IsRevoked("证书序列号")

// 移除吊销记录
revokeManager.RemoveRevocation("证书序列号")

// 使用动态吊销列表
auth, err := cert.NewAuthorizer().
    WithRevokeListUpdater(func() ([]byte, error) {
        // 从远程API获取最新吊销列表
        resp, err := http.Get("https://api.example.com/revoke-list")
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()
        return io.ReadAll(resp.Body)
    }).
    Build()
```

#### 吊销列表自动更新

```go
// 创建带更新函数的吊销管理器
revokeManager, err := cert.NewRevokeManager("1.0.0",
    cert.WithRevokeListUpdater(func() ([]byte, error) {
        resp, err := http.Get("https://api.example.com/revoke-list")
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()
        return io.ReadAll(resp.Body)
    }),
)

// 配置自动更新
config := &cert.AutoUpdateConfig{
    Interval:      time.Hour,           // 更新间隔
    RetryInterval: 5 * time.Minute,     // 重试间隔
    MaxRetries:    3,                   // 最大重试次数
    OnUpdate: func(oldTime, newTime time.Time, err error) {
        if err != nil {
            log.Printf("吊销列表更新失败: %v", err)
        } else {
            log.Printf("吊销列表已更新: %v -> %v", oldTime, newTime)
        }
    },
}

// 启动自动更新
err = revokeManager.StartAutoUpdate(config)

// 检查自动更新状态
if revokeManager.IsAutoUpdateRunning() {
    log.Println("自动更新正在运行")
}

// 手动触发更新
err = revokeManager.UpdateRevokeList()

// 停止自动更新
revokeManager.StopAutoUpdate()
```

### 8. 环境检测

系统提供智能环境检测，可区分物理机、虚拟机、容器和沙箱环境：

```go
// 创建安全管理器
sm := cert.NewSecurityManager(cert.SecurityLevelAdvanced)
defer sm.Close()

// 检测当前运行环境
envType := sm.DetectEnvironment()

switch envType {
case cert.EnvTypePhysical:
    log.Println("运行在物理机上")
case cert.EnvTypeVM:
    log.Println("运行在虚拟机中")
case cert.EnvTypeContainer:
    log.Println("运行在容器中")
case cert.EnvTypeSandbox:
    log.Println("运行在沙箱环境中")
}

// 执行安全检查（自动区分容器和沙箱）
if err := sm.Check(); err != nil {
    log.Printf("安全检查失败: %v", err)
}
```

#### 环境类型说明

| 环境类型 | 说明 | 安全检查行为 |
|----------|------|--------------|
| `EnvTypePhysical` | 物理机 | 正常检查 |
| `EnvTypeVM` | 虚拟机（VMware、VirtualBox 等） | 级别 2+ 时警告 |
| `EnvTypeContainer` | 容器（Docker、K8s、Containerd） | **不触发沙箱警告** |
| `EnvTypeSandbox` | 沙箱（Cuckoo、Joe Sandbox 等） | 级别 2+ 时拒绝 |

### 9. 模块级授权

系统支持按模块进行细粒度授权控制，适用于需要分模块销售或按功能授权的场景。

#### 签发带模块授权的证书

```go
// 构建带模块授权的证书请求
req, err := cert.NewClientRequest().
    WithMachineID(machineID).
    WithExpiry(time.Now().AddDate(1, 0, 0)).
    WithCompany("示例公司", "研发部").
    WithMinClientVersion("2.0.0").
    WithValidityDays(365).
    // 配置模块授权
    WithModules(
        cert.Module("report").WithQuota(100),           // 报表模块，配额100
        cert.Module("export").Enabled(),                 // 导出模块，启用
        cert.Module("api").Disabled(),                   // API模块，禁用
        cert.Module("premium").ValidFor(180),            // 高级功能，180天有效
        cert.Module("trial").ValidBetween(start, end),   // 试用功能，指定时间段
    ).
    Build()

// 签发证书
certificate, err := auth.IssueClientCert(req)
```

#### 模块配置选项

| 方法 | 说明 | 示例 |
|------|------|------|
| `Module(name)` | 创建模块配置（默认启用） | `Module("report")` |
| `.Enabled()` | 显式启用模块 | `Module("export").Enabled()` |
| `.Disabled()` | 禁用模块 | `Module("api").Disabled()` |
| `.WithQuota(n)` | 设置配额限制 | `Module("report").WithQuota(100)` |
| `.ValidFor(days)` | 设置有效天数 | `Module("trial").ValidFor(30)` |
| `.ValidFrom(time)` | 设置生效时间 | `Module("feature").ValidFrom(startTime)` |
| `.ValidUntil(time)` | 设置过期时间 | `Module("promo").ValidUntil(endTime)` |
| `.ValidBetween(from, to)` | 设置有效期范围 | `Module("event").ValidBetween(start, end)` |
| `.WithExtra(data)` | 附加扩展数据 | `Module("custom").WithExtra(`{"key":"value"}`)` |

#### 验证模块权限

```go
// 方式1: 简单检查模块是否启用
has, err := auth.HasModule(certPEM, "report")
if err != nil {
    log.Fatal(err)
}
if !has {
    log.Println("无报表模块权限")
}

// 方式2: 获取模块配额
quota, err := auth.GetModuleQuota(certPEM, "report")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("报表配额: %d\n", quota) // 0 表示无限制

// 方式3: 完整模块验证（权限+时间）
err = auth.ValidateModule(certPEM, "report", machineID)
if err != nil {
    if certErr, ok := err.(*cert.CertError); ok {
        switch certErr.Code {
        case cert.ErrModuleNotAuthorized:
            log.Println("模块未授权")
        case cert.ErrModuleExpired:
            log.Println("模块授权已过期")
        }
    }
}

// 方式4: 批量验证多个模块
requiredModules := []string{"report", "export"}
err = auth.ValidateModules(certPEM, machineID, requiredModules)
if err != nil {
    log.Printf("模块验证失败: %v", err)
}
```

#### 提取模块权限信息

```go
// 提取所有模块权限
features, err := auth.ExtractModules(certPEM)
if err != nil {
    log.Fatal(err)
}

if features != nil {
    for _, module := range features.Modules {
        fmt.Printf("模块: %s, 启用: %t, 配额: %d\n",
            module.Name, module.Enabled, module.Quota)
        if module.NotAfter > 0 {
            fmt.Printf("  过期时间: %s\n",
                time.Unix(module.NotAfter, 0).Format("2006-01-02"))
        }
    }
}

// 通过 ClientInfo 获取模块权限
clientInfo, err := auth.ExtractClientInfo(certPEM)
if clientInfo.Features != nil {
    if clientInfo.Features.HasModule("report") {
        fmt.Println("有报表模块权限")
    }
}
```

### 10. 统一授权接口

系统提供统一的 `Authorization` 接口，支持证书和 License 的多态访问，简化授权验证逻辑。

#### Authorization 接口

```go
// Authorization 统一授权接口
type Authorization interface {
    Type() AuthorizationType           // 返回授权类型（certificate/license）
    Validate(machineID string) error   // 验证授权
    HasModule(name string) bool        // 检查模块权限
    GetModuleQuota(name string) int    // 获取模块配额
    ValidateModule(name string) error  // 验证模块（权限+时间）
    GetMeta(key string) string         // 获取元数据
    ExpiresAt() time.Time              // 返回过期时间
    MachineIDs() []string              // 返回授权的机器码列表
}
```

#### 自动识别授权格式

```go
// ParseAuthorization 自动识别并解析授权数据
// 支持 PEM 格式证书和 JSON 格式 License
authorization, err := auth.ParseAuthorization(data, publicKey)
if err != nil {
    log.Fatal(err)
}

// 根据类型处理
switch authorization.Type() {
case cert.AuthTypeCertificate:
    fmt.Println("证书授权")
case cert.AuthTypeLicense:
    fmt.Println("License 授权")
}

// 统一访问方式
fmt.Printf("过期时间: %s\n", authorization.ExpiresAt().Format("2006-01-02"))
fmt.Printf("机器码: %v\n", authorization.MachineIDs())

if authorization.HasModule("report") {
    quota := authorization.GetModuleQuota("report")
    fmt.Printf("报表模块配额: %d\n", quota)
}
```

#### 批量模块验证

```go
// ValidateWithModules 一次验证基础授权和多个模块
requiredModules := []string{"report", "export", "api"}
err := auth.ValidateWithModules(data, machineID, requiredModules, publicKey)
if err != nil {
    log.Printf("授权验证失败: %v", err)
}
```

#### 证书授权实现

```go
// 从证书创建授权对象
certAuth, err := cert.NewCertAuthorization(certPEM, auth)
if err != nil {
    log.Fatal(err)
}

// 使用授权对象
fmt.Printf("类型: %s\n", certAuth.Type())           // "certificate"
fmt.Printf("过期: %s\n", certAuth.ExpiresAt())
fmt.Printf("有报表权限: %t\n", certAuth.HasModule("report"))

// 获取底层证书（如需要）
x509Cert := certAuth.Certificate()
features := certAuth.Features()
```

#### License 授权实现

```go
// 验证 License 并创建授权对象
payload, err := cert.ValidateLicenseJSON(licenseJSON, publicKey, machineID, time.Now())
if err != nil {
    log.Fatal(err)
}

licAuth := cert.NewLicenseAuthorization(payload, publicKey)

// 使用授权对象
fmt.Printf("类型: %s\n", licAuth.Type())            // "license"
fmt.Printf("过期: %s\n", licAuth.ExpiresAt())
fmt.Printf("有报表权限: %t\n", licAuth.HasModule("report"))

// License 特有功能
if licAuth.HasFeature("tier") {
    tier, _ := licAuth.GetFeatureValue("tier")
    fmt.Printf("授权等级: %v\n", tier)
}

// 获取元数据
customer := licAuth.GetMeta("customer")
fmt.Printf("客户: %s\n", customer)
```

#### 多态使用示例

```go
// 统一处理不同类型的授权
func checkAuthorization(authorization cert.Authorization, machineID string) error {
    // 基础验证
    if err := authorization.Validate(machineID); err != nil {
        return fmt.Errorf("授权验证失败: %w", err)
    }

    // 检查过期时间
    if time.Until(authorization.ExpiresAt()) < 7*24*time.Hour {
        log.Println("警告: 授权即将过期")
    }

    // 验证必需模块
    requiredModules := []string{"core", "report"}
    for _, module := range requiredModules {
        if err := authorization.ValidateModule(module); err != nil {
            return fmt.Errorf("模块 %s 验证失败: %w", module, err)
        }
    }

    return nil
}

// 使用示例
certAuth, _ := cert.NewCertAuthorization(certPEM, auth)
licAuth := cert.NewLicenseAuthorization(payload, publicKey)

// 多态调用
checkAuthorization(certAuth, machineID)
checkAuthorization(licAuth, machineID)
```

### 11. License 模块授权

License 同样支持模块级授权，通过 Features 字段配置：

#### 签发带模块的 License

```go
payload := cert.LicensePayload{
    LicenseID: "LIC-001",
    MachineID: machineID,
    NotAfter:  time.Now().AddDate(1, 0, 0),
    Features: map[string]any{
        "modules": map[string]any{
            "report": map[string]any{
                "enabled": true,
                "quota":   100,
            },
            "export": map[string]any{
                "enabled":   true,
                "not_after": "2025-12-31",
            },
            "api": map[string]any{
                "enabled": false,
            },
        },
        "tier": "enterprise",
        "max_users": 50,
    },
    Meta: map[string]string{
        "customer": "Acme Corp",
        "plan":     "enterprise",
    },
}

licenseJSON, err := cert.IssueLicense(payload, privateKey)
```

#### 验证 License 模块

```go
// 验证 License
payload, err := cert.ValidateLicenseJSON(licenseJSON, publicKey, machineID, time.Now())
if err != nil {
    log.Fatal(err)
}

// 检查功能
if payload.HasFeature("modules.report.enabled") {
    fmt.Println("有报表模块权限")
}

// 获取功能值
if tier, ok := payload.GetFeatureValue("tier"); ok {
    fmt.Printf("授权等级: %v\n", tier)
}

// 获取模块配置
if config, ok := payload.GetModuleConfig("report"); ok {
    fmt.Printf("模块: %s, 启用: %t, 配额: %d\n",
        config.Name, config.Enabled, config.Quota)
}

// 验证模块访问权限
err = payload.ValidateModuleAccess("report", time.Now())
if err != nil {
    log.Printf("模块访问验证失败: %v", err)
}
```

#### 模块错误码

| 错误码 | 说明 |
|--------|------|
| `ErrModuleNotAuthorized` | 模块未授权或已禁用 |
| `ErrModuleExpired` | 模块授权已过期或未生效 |
| `ErrModuleQuotaExceeded` | 模块配额已用尽 |

## 🛡️ 安全级别系统

### 安全级别概览

系统提供 4 个可选的安全级别，**默认完全禁用**以确保开发友好：

| 级别  | 名称     | 检测项              | 性能影响 | 适用场景               |
| ----- | -------- | ------------------- | -------- | ---------------------- |
| **0** | **禁用** | 无检测              | 无       | **开发、调试（默认）** |
| **1** | **基础** | 简单调试器检测      | 极小     | **测试环境**           |
| **2** | **高级** | 完整反逆向保护      | 小       | **生产环境（推荐）**   |
| **3** | **关键** | 最严格检查+进程保护 | 中等     | **关键系统**           |

### 配置方式

```go
// 方式1: 使用预设配置
devAuth := cert.ForDevelopment().Build()    // 级别0 (默认)
prodAuth := cert.ForProduction().Build()    // 级别2 (高级安全)
testAuth := cert.ForTesting().Build()       // 级别0

// 方式2: 显式设置安全级别
auth := cert.NewAuthorizer().
    WithSecurityLevel(0).Build()            // 禁用所有安全检查
auth := cert.NewAuthorizer().
    WithSecurityLevel(2).Build()            // 高级安全保护

// 方式3: 便捷配置方法
auth := cert.NewAuthorizer().DisableSecurity().Build()      // 级别0
auth := cert.NewAuthorizer().WithBasicSecurity().Build()    // 级别1
auth := cert.NewAuthorizer().WithSecureDefaults().Build()   // 级别2
auth := cert.NewAuthorizer().WithCriticalSecurity().Build() // 级别3
```

### 各级别详细功能

#### 🔓 级别 0：完全禁用（默认推荐）

```go
auth := cert.ForDevelopment().Build()
// 或
auth := cert.NewAuthorizer().Build() // 默认就是级别0
```

- **检测项**: 无
- **性能**: 无影响
- **用途**: 开发、调试、测试
- **特点**: 完全无干扰，专注于业务逻辑开发

#### 🛡️ 级别 1：基础防护

```go
auth := cert.ForProduction().Build()
```

- **检测项**: 基础调试器检测（IsDebuggerPresent、TracerPid 等）
- **性能**: 极小影响（~1-2ms）
- **用途**: 生产环境基础保护
- **特点**: 兼容性好，检测常见调试器

#### 🛡️ 级别 2：高级防护

```go
auth := cert.NewAuthorizer().WithSecureDefaults().Build()
```

- **检测项**:
  - 高级调试器检测（时间攻击、API 监控）
  - 虚拟机环境检测（VMware、VirtualBox 等）
  - 沙箱环境检测（Cuckoo、Joe Sandbox 等）
- **性能**: 小影响（~5-10ms）
- **用途**: 高价值软件保护
- **特点**: 全面的反逆向分析保护

#### 🔒 级别 3：关键防护

```go
auth := cert.NewAuthorizer().WithCriticalSecurity().Build()
```

- **检测项**:
  - 所有级别 2 的检测项
  - 进程保护（DLL 注入、代码注入检测）
  - 内存保护（关键数据加密）
  - 系统调用监控
- **性能**: 中等影响（~10-20ms）
- **用途**: 关键系统、军工软件
- **特点**: 最严格的安全检查，不允许任何分析

### 反调试技术详解

#### 🔓 级别 0 - 完全禁用（默认）

```go
auth := cert.NewAuthorizer().Build() // 默认级别0
// 或显式设置
auth := cert.NewAuthorizer().WithSecurityLevel(0).Build()
```

- **检测项**: 无任何检测
- **性能开销**: 0ms
- **适用场景**: 开发、调试、单元测试
- **特点**: 完全无干扰，专注业务逻辑开发

#### 🛡️ 级别 1 - 基础防护

```go
auth := cert.NewAuthorizer().WithBasicSecurity().Build()
```

**Windows 平台检测**：

- `IsDebuggerPresent()` - 检测调试器存在
- PEB 结构检查 - 验证`BeingDebugged`标志
- 调试堆检测 - 检查堆标志异常
- 硬件断点检测 - 读取调试寄存器 DR0-DR3（Windows x86/x64）
- 硬件断点状态寄存器 - DR6/DR7 非零时同样视为可疑（Windows x86/x64）
- 调试端口检查 - 通过 NtQueryInformationProcess(ProcessDebugPort) 检测调试端口
- 调试对象检查 - 通过 NtQueryInformationProcess(ProcessDebugObjectHandle) 检测调试对象
- 调试标志检查 - 通过 NtQueryInformationProcess(ProcessDebugFlags) 检测调试标志

**Linux 平台检测**：

- TracerPid 检查 - 读取`/proc/self/status`中的跟踪进程
- 调试器进程扫描 - 检查`gdb`、`lldb`等进程

**macOS 平台检测**：

- P_TRACED 状态 - 通过`sysctl`检查进程跟踪状态
- 调试器进程检测 - 扫描常见调试工具

**性能开销**: 1-2ms，适合生产环境

#### 🛡️ 级别 2 - 高级防护

```go
auth := cert.ForProduction().Build() // 生产环境默认级别2
// 或手动设置
auth := cert.NewAuthorizer().WithSecureDefaults().Build()
```

**高级反调试技术**：

- **时间差攻击检测** - 测量指令执行时间，检测单步调试
- **系统调用/跟踪检测** - Linux 下通过 TracerPid 检测 ptrace/strace 跟踪
- **调试端口检查** - 通过`NtQueryInformationProcess`检查调试端口（Windows）
- **异常处理检测** - 利用异常处理机制检测调试器
- **硬件断点检测** - 检查调试寄存器`DR0-DR7`

**虚拟机检测**：

- **VMware 检测** - 检查 VMware 特有设备和服务
- **VirtualBox 检测** - 查找 VBOX 相关注册表项和文件
- **Hyper-V 检测** - 检测 Microsoft 虚拟化标志
- **QEMU 检测** - 识别 QEMU/KVM 环境特征

**沙箱检测**：

- **Cuckoo Sandbox** - 检测 Cuckoo 特有的文件和注册表
- **Joe Sandbox** - 识别 Joe 分析环境
- **Anubis 检测** - 检查 Anubis 恶意软件分析平台

**性能开销**: 5-10ms，适合高价值软件保护

#### 🔒 级别 3 - 关键防护

```go
auth := cert.NewAuthorizer().WithCriticalSecurity().Build()
```

**进程保护技术**：

- **DLL 注入检测** - 监控异常的内存映射和模块加载
- **代码注入检测** - 检查可执行区域的异常变化
- **内存布局分析** - 检测内存映射异常
- **API Hook 检测** - 识别 API 拦截和重定向

**内存保护机制**：

- **关键数据加密** - 使用 XOR 等算法加密敏感内存区域
- **内存权限控制** - 动态设置关键区域访问权限
- **数据完整性校验** - 定期校验关键数据完整性
- **内存清理** - 程序退出时安全清理敏感数据

**系统监控**：

- **系统调用监控** - 检测异常的系统调用模式
- **文件系统监控** - 监控敏感文件访问
- **网络行为分析** - 检测异常网络通信

**性能开销**: 10-20ms，适合关键系统和军工软件

### 检测技术分类说明

#### 调试器检测

| 技术              | 级别 | 平台    | 描述                       |
| ----------------- | ---- | ------- | -------------------------- |
| IsDebuggerPresent | 1+   | Windows | 最基础的调试器检测 API     |
| PEB 检查          | 1+   | Windows | 检查进程环境块中的调试标志 |
| TracerPid         | 1+   | Linux   | 检查进程跟踪状态           |
| P_TRACED          | 1+   | macOS   | 检查进程跟踪标志           |
| 时间差攻击        | 2+   | 全平台  | 通过执行时间检测单步调试   |
| 调试端口检查      | 2+   | Windows | 通过 NT API 检查调试端口   |
| 异常处理检测      | 2+   | Windows | 利用结构化异常处理检测     |
| 硬件断点检测      | 2+   | x86/x64 | 检查调试寄存器状态         |

#### 环境检测

| 环境类型    | 检测级别 | 检测方法                         |
| ----------- | -------- | -------------------------------- |
| VMware      | 2+       | 注册表项、设备名称、MAC 地址前缀 |
| VirtualBox  | 2+       | 注册表项、文件系统、设备枚举     |
| Hyper-V     | 2+       | 系统信息、特殊标志位             |
| QEMU/KVM    | 2+       | CPUID 指令、设备信息             |
| Cuckoo 沙箱 | 2+       | 特有文件、注册表、网络配置       |
| Joe 沙箱    | 2+       | 环境变量、文件系统特征           |

### 环境检测技术

#### 虚拟机检测

- **VMware**: 检测 VMware 特有设备和注册表
- **VirtualBox**: 检查 VBOX 相关特征
- **Hyper-V**: 检测 Microsoft 虚拟化标志
- **QEMU**: 检查 QEMU/KVM 环境特征

实现说明：

- 当前实现已在安全检查链路中加入虚拟机检测（安全级别 2+），触发时返回错误码 `VIRTUAL_MACHINE_DETECTED`。

#### 沙箱检测

- **Cuckoo Sandbox**: 检测 Cuckoo 特有的文件和环境
- **Joe Sandbox**: 检查 Joe 分析环境特征
- **Anubis**: 检测 Anubis 恶意软件分析环境

### 进程保护技术

#### 注入检测

- **DLL 注入**: 监控异常的内存映射和模块加载
- **代码注入**: 检查可执行区域的异常变化
- **内存布局**: 分析内存布局异常

#### 内存保护

- **关键数据加密**: 使用 XOR 加密保护敏感内存
- **内存权限**: 设置关键区域为只读
- **数据清理**: 程序退出时清理敏感数据

## 📋 配置管理

### 环境预设配置

```go
// 开发环境（完全禁用安全检查）
devAuth := cert.ForDevelopment() // SecurityLevel=0

// 测试环境（禁用安全检查）
testAuth := cert.ForTesting()    // SecurityLevel=0

// 生产环境（基础安全检查）
prodAuth := cert.ForProduction() // SecurityLevel=1
```

### 自定义安全配置

```go
// 完全禁用安全检查（推荐用于开发）
auth := cert.NewAuthorizer().
    DisableSecurity().
    Build()

// 高级安全配置（高价值软件）
auth := cert.NewAuthorizer().
    WithSecureDefaults().         // SecurityLevel=2
    WithMaxClockSkew(time.Minute).
    WithCacheTTL(time.Minute * 10).
    Build()

// 关键安全配置（最高级别）
auth := cert.NewAuthorizer().
    WithCriticalSecurity().       // SecurityLevel=3
    Build()

// 显式设置安全级别
auth := cert.NewAuthorizer().
    WithSecurityLevel(1).         // 基础安全级别
    EnableTimeValidation(true).
    Build()
```

### Builder 配置方式

`cert` 核心包只保留内存配置模型和 Builder API，不再承担配置文件读取、保存、默认模板生成或搜索路径约定。  
如需 YAML / JSON / env / flags 配置，请由上层应用自行解析后，再映射到 `AuthorizerBuilder`：

```go
auth := cert.NewAuthorizer().
    WithRuntimeVersion("2.0.0").
    WithSecurityLevel(2).
    EnableTimeValidation(true).
    WithMaxClockSkew(5 * time.Minute).
    WithCacheTTL(10 * time.Minute).
    WithCacheSize(5000).
    Build()
```

## 🔧 高级功能

### 批量证书处理

```go
// 创建批量管理器
batchManager := cert.NewBatchManager(auth)

// 批量签发证书
requests := []*cert.ClientCertRequest{ /* ... */ }
results := batchManager.IssueMultipleCerts(requests)

// 批量验证证书
validations := []cert.CertValidation{ /* ... */ }
validationResults := batchManager.ValidateMultipleCerts(validations)
```

### 缓存优化

系统使用 **O(1) 时间复杂度的 LRU 缓存**，基于双向链表实现高效驱逐：

```go
// 方式1：通过 Builder 创建带缓存的授权管理器
cachedAuth, err := cert.NewAuthorizer().
    WithCacheConfig(cert.CacheConfig{
        TTL:             10 * time.Minute,
        MaxSize:         1000,
        CleanupInterval: 5 * time.Minute,
    }).
    BuildWithCache()

// 方式2：为现有授权管理器添加缓存
auth, _ := cert.NewAuthorizer().Build()
cachedAuth := auth.WithCache()

// 验证会自动使用缓存
err := cachedAuth.ValidateCert(certPEM, machineID)

// 查看缓存统计
stats := cachedAuth.CacheStats()
fmt.Printf("命中: %d, 未命中: %d, 驱逐: %d\n", stats.Hits, stats.Misses, stats.Evicted)
fmt.Printf("命中率: %.2f%%\n", cachedAuth.CacheHitRate()*100)

// 清空缓存
cachedAuth.ClearCache()
```

#### 缓存特性

- **O(1) LRU 驱逐**：使用双向链表实现，大缓存时性能稳定
- **并发安全**：读写锁保护，支持高并发访问
- **自动清理**：后台协程定期清理过期条目
- **统计信息**：命中/未命中/驱逐计数，便于监控

### 模板系统

```go
// 创建模板管理器
templateMgr := cert.NewTemplateManager()

// 使用预定义模板
template, _ := templateMgr.Template("enterprise")
fmt.Printf("有效期: %d天\n", template.ValidityDays)

// 添加自定义模板
customTemplate := &cert.CertTemplate{
    Name:           "自定义模板",
    Description:    "适用于特殊场景",
    ValidityDays:   730, // 2年
    SecurityLevel:  cert.TemplateSecurityLevelHigh,
    RequiredFields: []string{"MachineID", "CompanyName"},
}
templateMgr.AddTemplate("custom", customTemplate)

// 使用模板验证请求
err := templateMgr.ValidateRequestWithTemplate(req, "enterprise")

// 应用模板到请求
err = templateMgr.ApplyTemplate(req, "enterprise")
```

## 📊 错误处理

系统提供详细的错误分类和处理建议：

```go
err := auth.ValidateCert(certPEM, machineID)
if err != nil {
    if certErr, ok := err.(*cert.CertError); ok {
        fmt.Printf("错误类别: %d\n", certErr.ErrorType())
        fmt.Printf("错误代码: %s\n", certErr.ErrorCode())
        fmt.Printf("错误详情: %v\n", certErr.ErrorDetails())
        fmt.Printf("解决建议: %v\n", certErr.ErrorSuggestions())
    }
}
```

### 错误类型

- `ValidationError`: 证书验证错误（格式、过期等）
- `SecurityError`: 安全检查错误（调试器、沙箱等）
- `ConfigError`: 配置错误（CA 缺失、参数无效等）
- `SystemError`: 系统错误（时钟偏差、文件系统等）

## 🔍 监控和日志

### 安全事件监控

```go
// 初始化安全管理器
sm := auth.InitSecurityManager()

// 监控安全事件（自动记录）
// [SECURITY] 2024-01-20 15:30:45: Virtual machine environment detected
// [SECURITY] 2024-01-20 15:30:46: Defense measures activated
```

### 缓存统计

```go
// 获取缓存授权管理器
cachedAuth := auth.WithCache()

// 获取缓存统计信息
stats := cachedAuth.CacheStats()
fmt.Printf("缓存命中: %d\n", stats.Hits)
fmt.Printf("缓存未命中: %d\n", stats.Misses)
fmt.Printf("命中率: %.2f%%\n", cachedAuth.CacheHitRate()*100)
```

## 🏗️ 系统集成

### Web API 集成

```go
func validateLicenseHandler(w http.ResponseWriter, r *http.Request) {
    certData := r.Header.Get("X-License-Cert")
    machineID := r.Header.Get("X-Machine-ID")

    // 推荐：优先验证 license 文件（Ed25519），轻量且离线可验
    // publicKeyPEM 应由服务端下发/配置，或在客户端内置
    // pub, _ := cert.ParseEd25519PublicKeyPEM(publicKeyPEM)
    // // machineID 推荐传 machineid.ProtectedIDResult(appID).Hash（而非原始 machine-id）
    // // binding, _ := machineid.ProtectedIDResult(appID)
    // // machineID := binding.Hash
    // if _, err := cert.ValidateLicenseJSON([]byte(certData), pub, machineID, time.Now().UTC()); err != nil {
    //     http.Error(w, "License validation failed", 403)
    //     return
    // }
    //
    // 如仍使用证书作为授权载体，可继续走 ValidateCert
    if err := auth.ValidateCert([]byte(certData), machineID); err != nil {
        http.Error(w, "License validation failed", 403)
        return
    }

    w.WriteHeader(200)
    json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
}
```

### gRPC 服务

```protobuf
service LicenseService {
    rpc ValidateLicense(ValidateRequest) returns (ValidateResponse);
    rpc IssueLicense(IssueRequest) returns (IssueResponse);
    rpc RevokeLicense(RevokeRequest) returns (RevokeResponse);
}
```

## 🚀 性能优化

### 最佳实践

1. **使用缓存**: 启用证书验证缓存减少重复计算
2. **批量处理**: 大规模证书操作使用批量 API
3. **异步更新**: 吊销列表和配置使用异步更新
4. **连接池**: 网络请求使用连接池复用
5. **内存管理**: 及时清理不需要的证书数据

### 性能指标

- 证书验证: ~1-5ms（缓存命中）
- 证书签发: ~10-50ms
- 安全检查: ~5-20ms
- 批量处理: 1000 个证书/秒

## 📋 部署指南

### 生产环境部署

```go
// 生产环境推荐配置
auth := cert.ForProduction().
    WithCA(prodCACert, prodCAKey).      // 使用生产CA
    WithCacheTTL(30 * time.Minute).     // 适中的缓存时间
    WithMaxClockSkew(1 * time.Minute).  // 严格的时间检查
    Build()
```

> ⚠️ **生产交付约定**
>
> - `UseDefaultCA()` / 内置 `defaultCACert` / `defaultCAKey` 仅用于开发、测试和兜底兼容，不应作为生产根 CA 长期使用。
> - 生产环境必须显式通过 `WithCA(prodCACert, prodCAKey)` 注入独立 CA，或先调用 `GenerateCA()` 生成后再持久化加载。
> - 安全扫描若命中内置 CA 私钥，应按“兜底资产”解释，不应误判为生产密钥泄露；前提是生产部署已显式替换。

## ⚠️ 重要安全说明

### CA 私钥保护

CA 私钥是整个系统的核心，必须严格保护：

- **加密存储**: 使用硬件安全模块(HSM)或加密文件系统
- **访问控制**: 限制访问权限，使用最小权限原则
- **备份策略**: 安全的密钥备份和恢复机制
- **定期轮换**: 定期更换 CA 密钥（建议 2-5 年）
- **审计日志**: 记录所有密钥使用操作

### 安全最佳实践

1. **网络安全**: 使用 HTTPS 传输证书和验证请求
2. **存储安全**: 加密存储敏感配置和密钥文件
3. **访问控制**: 实施严格的身份认证和授权
4. **监控告警**: 部署安全事件监控和异常告警
5. **应急响应**: 建立证书泄露应急处理流程

## 🔧 故障排除

### 常见问题

#### 证书验证失败

```bash
# 检查系统时间
ntpdate -s time.nist.gov

# 检查证书有效期
openssl x509 -in certificate.pem -noout -dates

# 检查机器码匹配
echo "当前机器码: $(go run -tags=cert ./cmd/get-machine-id)"
```

#### 安全检查失败

```go
// 临时禁用安全检查（仅用于调试）
devAuth := cert.ForDevelopment().Build() // EnableAntiDebug=false

// 或检查具体安全问题
if err := auth.PerformSecurityCheck(); err != nil {
    fmt.Printf("安全检查详情: %v\n", err)
}
```

## 📖 API 文档

完整的 API 文档请参阅：

- [GoDoc](https://pkg.go.dev/github.com/darkit/machineid/cert)
- [示例代码](./examples.go)
- [Builder 配置方式](#builder-配置方式)

## 🔄 版本兼容性

- **Go 版本**: 需要 Go 1.19+
- **平台支持**: Windows, Linux, macOS
- **架构支持**: amd64, arm64, 386

## 📄 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 🤝 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 开发环境设置

```bash
# 克隆代码
git clone https://github.com/darkit/machineid.git
cd machineid/cert

# 运行测试
go test -v ./...

# 运行示例
go run examples.go
```

## 📞 支持

如果您遇到问题或需要帮助：

- 🐛 [报告 Bug](https://github.com/darkit/machineid/issues/new?template=bug_report.md)
- 💡 [功能建议](https://github.com/darkit/machineid/issues/new?template=feature_request.md)
- 📚 [Wiki 文档](https://github.com/darkit/machineid/wiki)

---

**注意**: 本解决方案专为合法的软件授权管理设计，请遵守当地法律法规，不得用于恶意目的。
