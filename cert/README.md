# cert — 企业级软件授权管理

`cert` 包提供完整的 PKI 证书管理功能，支持证书签发、验证、吊销、模块级授权、License 签发与校验，以及可选的运行时安全防护。基于 Ed25519 椭圆曲线签名算法，默认面向开发友好，安全功能按需启用。

## 主要特性

- X.509 CA 证书生成与客户端证书签发（Ed25519）
- 证书链验证、吊销管理、批量处理
- License 授权文件（Ed25519 JSON 签名，轻量离线鉴别）
- 统一 `Authorization` 接口，多态处理证书与 License
- 模块级授权：按模块启用/禁用、配额限制、独立有效期
- 4 级可选安全防护：反调试、虚拟机检测、沙箱检测、进程保护
- 智能缓存（O(1) LRU 驱逐）、证书监控与到期预警
- 客户信息提取与授权审计

## 安装

```bash
go get github.com/darkit/machineid/cert
```

## 快速开始

### 1. 创建授权管理器

```go
import "github.com/darkit/machineid/cert"

// 开发环境（完全禁用安全检查，默认）
auth, err := cert.ForDevelopment().Build()
if err != nil {
    log.Fatal(err)
}

// 生产环境（安全等级 2，高级反逆向保护）
prodAuth, err := cert.ForProduction().Build()

// 自定义配置
customAuth, err := cert.NewAuthorizer().
    WithRuntimeVersion("2.0.0").
    WithSecurityLevel(2).
    WithMaxClockSkew(1 * time.Minute).
    WithCacheTTL(30 * time.Minute).
    Build()
```

### 2. 生成 CA 证书

```go
err := auth.GenerateCA(cert.CAInfo{
    CommonName:   "ZStudio Software",
    Organization: "子说软件工作室",
    Country:      "CN",
    Province:     "Guangdong",
    Locality:     "Guangzhou",
    ValidDays:    3650, // 10 年
})
if err != nil {
    log.Fatal(err)
}

// 保存到磁盘
err = auth.SaveCA("./certificates")
```

### 3. 签发客户端证书

```go
bindingResult, _ := machineid.ProtectedIDResult("your.app.id")

req, err := cert.NewClientRequest().
    WithMachineID(bindingResult.Hash).
    WithBindingResult(bindingResult).
    WithExpiry(time.Now().AddDate(1, 0, 0)).
    WithCompany("客户公司", "研发部").
    WithContact("张三", "13800138000", "zhangsan@example.com").
    WithMinClientVersion("2.0.0").
    WithValidityDays(365).
    Build()
if err != nil {
    log.Fatal(err)
}

certificate, err := auth.IssueClientCert(req)
if err != nil {
    log.Fatal(err)
}
```

### 4. 验证证书

```go
err := auth.ValidateCert(certificate.CertPEM, machineID)
if err != nil {
    if cert.IsSecurityError(err) {
        log.Printf("安全检查失败: %v", err)
    } else if cert.IsValidationError(err) {
        log.Printf("证书验证失败: %v", err)
    }
    return
}
log.Println("证书验证通过")
```

### 5. 提取客户信息

```go
clientInfo, err := auth.ExtractClientInfo(certificate.CertPEM)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("公司: %s\n", clientInfo.CompanyName)
fmt.Printf("联系人: %s (%s)\n", clientInfo.ContactPerson, clientInfo.ContactEmail)
fmt.Printf("绑定模式: %s\n", clientInfo.BindingMode)
fmt.Printf("绑定提供者: %s\n", clientInfo.BindingProvider)
fmt.Printf("到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02"))
```

### 6. 证书监控

```go
callback := func(event cert.WatchEvent, info *cert.ClientInfo, err error) {
    switch event {
    case cert.WatchEventExpiring:
        log.Printf("证书即将到期: %s (%s)", info.CompanyName, info.ContactPerson)
    case cert.WatchEventExpired:
        log.Printf("证书已过期: %s", info.CompanyName)
    case cert.WatchEventRevoked:
        log.Printf("证书已吊销: %s", info.CompanyName)
    case cert.WatchEventInvalid:
        log.Printf("证书无效: %v", err)
    }
}

// 启动监控（默认 1 小时检查间隔，7 天预警期）
watcher, err := auth.Watch(certPEM, machineID, callback)
if err != nil {
    log.Fatal(err)
}
defer watcher.Stop()

// 自定义间隔和预警期
watcher, _ := auth.Watch(certPEM, machineID, callback,
    30*time.Minute,  // 30 分钟检查一次
    3*24*time.Hour)  // 3 天到期预警
```

## 安全级别系统

四个可选的安全级别，默认完全禁用以确保开发友好。

| 级别 | 名称 | 检测项                | 性能影响 | 适用场景           |
| ---- | ---- | --------------------- | -------- | ------------------ |
| 0    | 禁用 | 无                    | 无       | 开发、调试（默认） |
| 1    | 基础 | 调试器检测            | ~1-2ms   | 测试环境           |
| 2    | 高级 | 完整反逆向保护        | ~5-10ms  | 生产环境（推荐）   |
| 3    | 关键 | 最严格检查 + 进程保护 | ~10-20ms | 关键系统           |

### 快速配置

```go
// 预设配置
auth := cert.ForDevelopment().Build()   // 级别 0
auth := cert.ForProduction().Build()    // 级别 2
auth := cert.ForTesting().Build()       // 级别 0

// Builder 配置
auth := cert.NewAuthorizer().Build()                              // 默认级别 0
auth := cert.NewAuthorizer().WithBasicSecurity().Build()          // 级别 1
auth := cert.NewAuthorizer().WithSecureDefaults().Build()         // 级别 2
auth := cert.NewAuthorizer().WithCriticalSecurity().Build()       // 级别 3
auth := cert.NewAuthorizer().WithSecurityLevel(1).Build()         // 显式设置
```

### 各级别功能详情

**级别 0 — 禁用**

完全无检测，无性能开销，适用于开发调试。

**级别 1 — 基础**

- Windows: `IsDebuggerPresent()`、PEB `BeingDebugged` 标志、调试端口/对象/标志检查、硬件断点检测（DR0-DR7）
- Linux: TracerPid 检查、调试器进程扫描
- macOS: P_TRACED 状态、调试器进程检测

**级别 2 — 高级**

包含级别 1 所有检测，额外增加：

- 时间差攻击检测、异常处理检测
- VMware / VirtualBox / Hyper-V / QEMU 虚拟机检测
- Cuckoo / Joe Sandbox / Anubis 沙箱检测

**级别 3 — 关键**

包含级别 2 所有检测，额外增加：

- DLL 注入检测、代码注入检测、内存布局分析
- 关键数据加密保护、内存权限控制
- 系统调用监控、文件系统监控

### 环境检测

`SecurityManager` 可区分运行环境类型：

```go
sm := cert.NewSecurityManager(cert.SecurityLevelAdvanced)
defer sm.Close()

envType := sm.DetectEnvironment()
switch envType {
case cert.EnvTypePhysical:
    // 物理机
case cert.EnvTypeVM:
    // 虚拟机
case cert.EnvTypeContainer:
    // 容器（Docker/K8s/Containerd）— 不触发沙箱警告
case cert.EnvTypeSandbox:
    // 沙箱环境
}
```

## 模块级授权

支持按模块进行细粒度授权控制，适用于分模块销售或按功能授权的场景。

### 签发带模块授权的证书

```go
req, err := cert.NewClientRequest().
    WithMachineID(machineID).
    WithExpiry(time.Now().AddDate(1, 0, 0)).
    WithCompany("示例公司", "研发部").
    WithMinClientVersion("2.0.0").
    WithValidityDays(365).
    WithModules(
        cert.Module("report").WithQuota(100),              // 报表模块，配额 100
        cert.Module("export").Enabled(),                    // 导出模块，启用
        cert.Module("api").Disabled(),                      // API 模块，禁用
        cert.Module("premium").ValidFor(180),               // 高级模块，180 天有效
        cert.Module("trial").ValidBetween(start, end),      // 试用模块，指定时间段
    ).
    Build()

certificate, err := auth.IssueClientCert(req)
```

### 模块配置选项

| 方法                      | 说明                     | 示例                                 |
| ------------------------- | ------------------------ | ------------------------------------ |
| `Module(name)`            | 创建模块配置（默认启用） | `Module("report")`                   |
| `.Enabled()`              | 显式启用                 | `Module("export").Enabled()`         |
| `.Disabled()`             | 禁用                     | `Module("api").Disabled()`           |
| `.WithQuota(n)`           | 设置配额限制             | `Module("report").WithQuota(100)`    |
| `.ValidFor(days)`         | 设置有效天数             | `Module("trial").ValidFor(30)`       |
| `.ValidFrom(time)`        | 设置生效时间             | `Module("feature").ValidFrom(start)` |
| `.ValidUntil(time)`       | 设置过期时间             | `Module("promo").ValidUntil(end)`    |
| `.ValidBetween(from, to)` | 设置有效期范围           | `Module("event").ValidBetween(s, e)` |
| `.WithExtra(data)`        | 附加扩展数据             | `Module("custom").WithExtra(map)`    |

### 验证模块权限

```go
// 检查模块是否启用
has, err := auth.HasModule(certPEM, "report")

// 获取模块配额
quota, err := auth.GetModuleQuota(certPEM, "report")

// 完整模块验证（权限 + 时间）
err = auth.ValidateModule(certPEM, "report", machineID)

// 批量验证
err = auth.ValidateModules(certPEM, machineID, []string{"report", "export"})

// 提取所有模块权限
features, err := auth.ExtractModules(certPEM)
if features != nil {
    for _, m := range features.Modules {
        fmt.Printf("模块 %s: 启用=%t, 配额=%d\n", m.Name, m.Enabled, m.Quota)
    }
}
```

### 模块错误码

| 错误码                   | 说明                   |
| ------------------------ | ---------------------- |
| `ErrModuleNotAuthorized` | 模块未授权或已禁用     |
| `ErrModuleExpired`       | 模块授权已过期或未生效 |
| `ErrModuleQuotaExceeded` | 模块配额已用尽         |

## 统一授权接口

系统提供 `Authorization` 接口，支持证书和 License 的多态访问。

```go
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

### 自动识别授权格式

```go
// ParseAuthorization 自动识别 PEM 证书和 JSON License
authorization, err := auth.ParseAuthorization(data, publicKey)

switch authorization.Type() {
case cert.AuthTypeCertificate:
    fmt.Println("证书授权")
case cert.AuthTypeLicense:
    fmt.Println("License 授权")
}

// 统一访问
fmt.Printf("过期时间: %s\n", authorization.ExpiresAt())
fmt.Printf("机器码: %v\n", authorization.MachineIDs())

if authorization.HasModule("report") {
    quota := authorization.GetModuleQuota("report")
    fmt.Printf("配额: %d\n", quota)
}
```

### 多态使用

```go
func checkAuth(auth cert.Authorization, machineID string) error {
    if err := auth.Validate(machineID); err != nil {
        return fmt.Errorf("验证失败: %w", err)
    }
    if time.Until(auth.ExpiresAt()) < 7*24*time.Hour {
        log.Println("警告: 即将过期")
    }
    for _, m := range []string{"core", "report"} {
        if err := auth.ValidateModule(m); err != nil {
            return fmt.Errorf("模块 %s: %w", m, err)
        }
    }
    return nil
}

// certAuth, _ := cert.NewCertAuthorization(certPEM, authorizer)
// licAuth := cert.NewLicenseAuthorization(payload, publicKey)
// checkAuth(certAuth, machineID) // 多态调用
// checkAuth(licAuth, machineID)
```

## License 授权

License 是 Ed25519 签名的 JSON 载体，比 X.509 证书更轻量，适合离线分发与快速校验。

### 签发 License

```go
payload := cert.LicensePayload{
    LicenseID: "LIC-001",
    MachineID: machineID,
    NotAfter:  time.Now().AddDate(1, 0, 0),
    Features: map[string]any{
        "modules": map[string]any{
            "report": map[string]any{"enabled": true, "quota": 100},
            "export": map[string]any{"enabled": true, "not_after": "2025-12-31"},
            "api":    map[string]any{"enabled": false},
        },
        "tier":      "enterprise",
        "max_users": 50,
    },
    Meta: map[string]string{
        "customer": "Acme Corp",
        "plan":     "enterprise",
    },
}

licenseJSON, err := cert.IssueLicense(payload, privateKey)
```

### 验证 License

```go
// 基础验证
payload, err := cert.ValidateLicenseJSON(licenseJSON, publicKey, machineID, time.Now())
if err != nil {
    log.Fatal(err)
}

// 推荐：VerifiedMachineID = machineid.ProtectedIDResult(appID).Hash
// err = cert.ValidateLicenseJSONWithAppID(licenseJSON, publicKey, appID, time.Now())

// 检查模块
if payload.HasFeature("modules.report.enabled") {
    // ...
}

// 获取配置
if config, ok := payload.GetModuleConfig("report"); ok {
    fmt.Printf("模块 %s: 启用=%t, 配额=%d\n", config.Name, config.Enabled, config.Quota)
}

// 验证模块访问（含时间校验）
err = payload.ValidateModuleAccess("report", time.Now())
```

### License 密钥管理

```go
// 生成 Ed25519 密钥对（PEM 格式）
pubPEM, privPEM, err := cert.GenerateLicenseKeyPairPEM()

// 解析密钥
pubKey, err := cert.ParseEd25519PublicKeyPEM(pubPEM)
privKey, err := cert.ParseEd25519PrivateKeyPEM(privPEM)
```

## 证书吊销管理

```go
// 创建吊销管理器
rm, err := cert.NewRevokeManager("1.0.0")
if err != nil {
    log.Fatal(err)
}

// 吊销证书
rm.AddRevocation("serial-number", "security_breach")

// 检查吊销状态
isRevoked, reason := rm.IsRevoked("serial-number")

// 移除吊销记录
rm.RemoveRevocation("serial-number")
```

### 吊销列表自动更新

```go
rm, err := cert.NewRevokeManager("1.0.0",
    cert.WithRevokeListUpdater(func() ([]byte, error) {
        resp, err := http.Get("https://api.example.com/revoke-list")
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()
        return io.ReadAll(resp.Body)
    }),
)

config := &cert.AutoUpdateConfig{
    Interval:      time.Hour,
    RetryInterval: 5 * time.Minute,
    MaxRetries:    3,
    OnUpdate: func(oldTime, newTime time.Time, err error) {
        if err != nil {
            log.Printf("吊销列表更新失败: %v", err)
        }
    },
}

err = rm.StartAutoUpdate(config)
defer rm.StopAutoUpdate()
```

## 缓存优化

系统使用 O(1) 时间复杂度的 LRU 缓存，基于双向链表实现高效驱逐，并发安全。

```go
// Builder 方式创建带缓存的授权管理器
cachedAuth, err := cert.NewAuthorizer().
    WithCacheConfig(cert.CacheConfig{
        TTL:             10 * time.Minute,
        MaxSize:         1000,
        CleanupInterval: 5 * time.Minute,
    }).
    BuildWithCache()
if err != nil {
    log.Fatal(err)
}

// 为现有授权管理器添加缓存
auth, _ := cert.NewAuthorizer().Build()
cachedAuth := auth.WithCache()

// 缓存统计
stats := cachedAuth.CacheStats()
fmt.Printf("命中: %d, 未命中: %d, 命中率: %.2f%%\n",
    stats.Hits, stats.Misses, cachedAuth.CacheHitRate()*100)

// 清空缓存
cachedAuth.ClearCache()

// 释放后台清理协程
cachedAuth.Close()
```

## 批处理

```go
// 批量签发
batchManager := cert.NewBatchManager(auth)
results := batchManager.IssueMultipleCerts(requests)

// 并发控制
manager := cert.NewBatchManager(auth).WithMaxWorkers(4)

// 批量验证
validations := []cert.CertValidation{
    {CertPEM: cert1PEM, MachineID: mid1},
    {CertPEM: cert2PEM, MachineID: mid2},
}
validationResults := batchManager.ValidateMultipleCerts(validations)
```

## 证书信息检查

```go
inspector := cert.NewCertificateInspector()
certInfo, err := inspector.InspectPEM(certificate.CertPEM)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("主题: %s\n", certInfo.Subject)
fmt.Printf("序列号: %s\n", certInfo.SerialNumber)
fmt.Printf("有效期: %s 至 %s\n",
    certInfo.NotBefore.Format("2006-01-02 15:04:05"),
    certInfo.NotAfter.Format("2006-01-02 15:04:05"))
fmt.Printf("密钥算法: %s (%s)\n", certInfo.PublicKeyAlgorithm, certInfo.KeySize)
```

## 错误处理

系统提供分类的 `CertError` 类型，支持错误码判定。

```go
err := auth.ValidateCert(certPEM, machineID)
if err != nil {
    if certErr, ok := err.(*cert.CertError); ok {
        fmt.Printf("错误类型: %d\n", certErr.ErrorType())
        fmt.Printf("错误代码: %s\n", certErr.ErrorCode())
        fmt.Printf("详细信息: %v\n", certErr.ErrorDetails())
        fmt.Printf("解决建议: %v\n", certErr.ErrorSuggestions())
    }
}
```

### 错误类型

| 类型              | 说明                                       |
| ----------------- | ------------------------------------------ |
| `ValidationError` | 证书验证错误（格式、过期、机器码不匹配等） |
| `SecurityError`   | 安全检查错误（调试器、虚拟机、沙箱等）     |
| `ConfigError`     | 配置错误（CA 缺失、参数无效等）            |
| `SystemError`     | 系统错误（时钟偏差、文件系统等）           |

### 常见错误码

| 错误码                          | 说明                                   |
| ------------------------------- | -------------------------------------- |
| `MACHINE_ID_NOT_AUTHORIZED`     | 传入的 machineID 不在证书授权列表中    |
| `CERTIFICATE_NOT_TRUSTED`       | 证书签名不受信任                       |
| `CERTIFICATE_EXPIRED`           | 证书已过期                             |
| `CERTIFICATE_REVOKED`           | 证书已被吊销                           |
| `CERTIFICATE_EXTENSION_MISSING` | 缺少必需的扩展字段                     |
| `CERTIFICATE_VERSION_MISMATCH`  | 证书版本与运行版本不匹配               |
| `VERSION_TOO_OLD`               | 运行版本低于证书要求                   |
| `VERSION_FORMAT_INVALID`        | 版本号格式非法（仅支持纯数字点分格式） |
| `INVALID_REQUEST`               | 签发请求参数不合法                     |
| `DEBUGGER_DETECTED`             | 检测到调试器                           |
| `VIRTUAL_MACHINE_DETECTED`      | 检测到虚拟机环境                       |
| `SANDBOX_ENVIRONMENT_DETECTED`  | 检测到沙箱环境                         |

## 配置参考

### Builder API

```go
auth := cert.NewAuthorizer().
    WithRuntimeVersion("2.0.0").    // 当前运行版本
    WithCA(caCert, caKey).           // 自定义 CA 证书和私钥
    UseDefaultCA().                  // 使用内置 CA（仅开发/测试，生产禁用）
    WithEnterpriseID(1000).          // 企业标识符
    WithSecurityLevel(2).            // 安全级别（0-3）
    EnableTimeValidation(true).      // 启用时间验证
    WithMaxClockSkew(5 * time.Minute). // 最大时钟偏差
    WithCacheTTL(10 * time.Minute).    // 缓存 TTL
    WithCacheSize(5000).               // 缓存大小
    Build()
```

### 生产部署注意

- 生产环境必须显式通过 `WithCA(prodCACert, prodCAKey)` 注入独立 CA，或在首次部署时调用 `GenerateCA()` 生成后持久化加载
- `UseDefaultCA()` 和内置 `defaultCACert` / `defaultCAKey` 仅用于开发、测试和兜底兼容，不应作为生产根 CA 长期使用
- `ForProduction()` 安全级别为 2（高级），如需保持旧行为可显式覆盖：`ForProduction().WithSecurityLevel(1)`

## 性能指标

| 操作                 | 耗时          |
| -------------------- | ------------- |
| 证书验证（缓存命中） | ~1-5ms        |
| 证书签发             | ~10-50ms      |
| 安全检查（级别 2）   | ~5-10ms       |
| 安全检查（级别 3）   | ~10-20ms      |
| 批量处理             | ~1000 证书/秒 |

## 监控事件类型

| 事件                 | 触发条件           | 建议处理                        |
| -------------------- | ------------------ | ------------------------------- |
| `WatchEventExpiring` | 距离到期小于预警期 | 发送续期提醒                    |
| `WatchEventExpired`  | 证书已过期         | 停止服务或提示                  |
| `WatchEventInvalid`  | 证书验证失败       | 根据 error.ErrorCode() 定位原因 |
| `WatchEventRevoked`  | 证书被吊销         | 立即停止服务，安全审计          |

> `WatchEventInvalid` 是总括事件，具体原因以回调参数 `err` 为准。`err` 为 `*CertError` 时，可通过 `err.ErrorCode()` 精确区分。

## 安全最佳实践

1. **CA 私钥保护**：使用硬件安全模块（HSM）或加密文件系统，限制访问权限
2. **网络安全**：使用 HTTPS 传输证书和验证请求
3. **存储安全**：加密存储敏感配置和密钥文件
4. **定期轮换**：建议 2-5 年更换 CA 密钥
5. **监控告警**：部署安全事件监控和异常告警
6. **审计日志**：记录所有密钥使用和证书签发操作

## API 文档

- [Go Package Reference](https://pkg.go.dev/github.com/darkit/machineid/cert)
- 代码示例：[examples.go](examples.go)
- 根包文档：[../README.md](../README.md)

## 兼容性

- Go 1.19+
- 平台支持：Windows、Linux、macOS
- 架构支持：amd64、arm64、386

## 许可证

MIT License - 详见 [LICENSE](../LICENSE)
