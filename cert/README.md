# Cert 企业级软件授权管理解决方案

`cert` 包是一个功能完整的企业级软件授权管理解决方案，提供证书签发、验证、吊销以及**可选的**安全防护功能。专为需要软件许可控制的应用程序设计，**默认开发友好，按需启用安全保护**。

## 🚀 主要特性

### 📜 证书管理
- **CA 证书生成**：支持自定义 CA 证书和私钥管理
- **客户端证书签发**：基于机器码的证书签发系统
- **证书验证**：完整的证书链验证和有效性检查
- **证书吊销**：动态吊销列表管理和实时更新
- **批量处理**：支持大规模证书批量签发和验证

### 🛡️ 安全防护（可选）
- **分级保护**：4个安全级别，从禁用到关键防护
- **反调试保护**：多层次调试器检测和防护机制
- **环境检测**：虚拟机和沙箱环境识别
- **进程保护**：DLL注入和代码注入检测
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
    WithVersion("2.0.0").
    WithSecurityLevel(2).                 // 高级安全保护
    WithMaxClockSkew(1 * time.Minute).
    Build()
```

### 2. 生成 CA 证书

```go
caInfo := cert.CAInfo{
    CommonName:   "ZStudio Software CA",
    Organization: "子说软件工作室",
    Country:      "CN",
    Province:     "Guangdong", 
    Locality:     "Guangzhou",
    ValidDays:    3650, // 10年有效期
    KeySize:      4096,
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
req := &cert.ClientCertRequest{
    Identity: cert.Identity{
        MachineID:  "DESKTOP-ABC123-HDD-12345678",
        ExpiryDate: time.Now().AddDate(1, 0, 0), // 1年有效期
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
        Version:            "2.0.0",
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
fmt.Printf("程序版本: %s\n", clientInfo.Version)
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
stats := watcher.GetStats()
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
allStats := manager.GetAllStats()
for id, stats := range allStats {
    fmt.Printf("%s: 检查%v次, 运行中=%v\n", 
        id, stats["check_count"], stats["is_running"])
}

// 停止所有监控
manager.StopAll()
```

#### 监控事件类型

| 事件 | 触发条件 | 建议处理 |
|------|----------|----------|
| **WatchEventExpiring** | 距离到期时间小于预警期 | 发送续期提醒，准备新证书 |
| **WatchEventExpired** | 证书已过期 | 停止服务或显示过期提示 |
| **WatchEventInvalid** | 证书格式错误或验证失败 | 检查证书文件，联系技术支持 |
| **WatchEventRevoked** | 证书被加入吊销列表 | 立即停止服务，进行安全审计 |

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
err = revokeManager.RevokeCertificate("证书序列号", "security_breach")

// 检查证书是否被吊销
isRevoked, reason := revokeManager.IsRevoked("证书序列号")

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

## 🛡️ 安全级别系统

### 安全级别概览

系统提供4个可选的安全级别，**默认完全禁用**以确保开发友好：

| 级别 | 名称 | 检测项 | 性能影响 | 适用场景 |
|------|------|--------|----------|----------|
| **0** | **禁用** | 无检测 | 无 | **开发、调试（默认）** |
| **1** | **基础** | 简单调试器检测 | 极小 | **生产环境** |
| **2** | **高级** | 完整反逆向保护 | 小 | **高价值软件** |
| **3** | **关键** | 最严格检查+进程保护 | 中等 | **关键系统** |

### 配置方式

```go
// 方式1: 使用预设配置
devAuth := cert.ForDevelopment().Build()    // 级别0 (默认)
prodAuth := cert.ForProduction().Build()    // 级别1
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

#### 🔓 级别0：完全禁用（默认推荐）
```go
auth := cert.ForDevelopment().Build()
// 或
auth := cert.NewAuthorizer().Build() // 默认就是级别0
```
- **检测项**: 无
- **性能**: 无影响
- **用途**: 开发、调试、测试
- **特点**: 完全无干扰，专注于业务逻辑开发

#### 🛡️ 级别1：基础防护
```go
auth := cert.ForProduction().Build()
```
- **检测项**: 基础调试器检测（IsDebuggerPresent、TracerPid等）
- **性能**: 极小影响（~1-2ms）
- **用途**: 生产环境基础保护
- **特点**: 兼容性好，检测常见调试器

#### 🛡️ 级别2：高级防护
```go
auth := cert.NewAuthorizer().WithSecureDefaults().Build()
```
- **检测项**: 
  - 高级调试器检测（时间攻击、API监控）
  - 虚拟机环境检测（VMware、VirtualBox等）
  - 沙箱环境检测（Cuckoo、Joe Sandbox等）
- **性能**: 小影响（~5-10ms）
- **用途**: 高价值软件保护
- **特点**: 全面的反逆向分析保护

#### 🔒 级别3：关键防护
```go
auth := cert.NewAuthorizer().WithCriticalSecurity().Build()
```
- **检测项**: 
  - 所有级别2的检测项
  - 进程保护（DLL注入、代码注入检测）
  - 内存保护（关键数据加密）
  - 系统调用监控
- **性能**: 中等影响（~10-20ms）
- **用途**: 关键系统、军工软件
- **特点**: 最严格的安全检查，不允许任何分析

### 反调试技术详解

#### 🔓 级别0 - 完全禁用（默认）
```go
auth := cert.NewAuthorizer().Build() // 默认级别0
// 或显式设置
auth := cert.NewAuthorizer().WithSecurityLevel(0).Build()
```
- **检测项**: 无任何检测
- **性能开销**: 0ms
- **适用场景**: 开发、调试、单元测试
- **特点**: 完全无干扰，专注业务逻辑开发

#### 🛡️ 级别1 - 基础防护
```go
auth := cert.ForProduction().Build() // 自动设为级别1
// 或手动设置
auth := cert.NewAuthorizer().WithBasicSecurity().Build()
```
**Windows平台检测**：
- `IsDebuggerPresent()` - 检测调试器存在
- PEB结构检查 - 验证`BeingDebugged`标志
- 调试堆检测 - 检查堆标志异常

**Linux平台检测**：
- TracerPid检查 - 读取`/proc/self/status`中的跟踪进程
- 调试器进程扫描 - 检查`gdb`、`lldb`等进程

**macOS平台检测**：
- P_TRACED状态 - 通过`sysctl`检查进程跟踪状态
- 调试器进程检测 - 扫描常见调试工具

**性能开销**: 1-2ms，适合生产环境

#### 🛡️ 级别2 - 高级防护  
```go
auth := cert.NewAuthorizer().WithSecureDefaults().Build()
```
**高级反调试技术**：
- **时间差攻击检测** - 测量指令执行时间，检测单步调试
- **调试端口检查** - 通过`NtQueryInformationProcess`检查调试端口（Windows）
- **异常处理检测** - 利用异常处理机制检测调试器
- **硬件断点检测** - 检查调试寄存器`DR0-DR7`

**虚拟机检测**：
- **VMware检测** - 检查VMware特有设备和服务
- **VirtualBox检测** - 查找VBOX相关注册表项和文件
- **Hyper-V检测** - 检测Microsoft虚拟化标志
- **QEMU检测** - 识别QEMU/KVM环境特征

**沙箱检测**：
- **Cuckoo Sandbox** - 检测Cuckoo特有的文件和注册表
- **Joe Sandbox** - 识别Joe分析环境
- **Anubis检测** - 检查Anubis恶意软件分析平台

**性能开销**: 5-10ms，适合高价值软件保护

#### 🔒 级别3 - 关键防护
```go  
auth := cert.NewAuthorizer().WithCriticalSecurity().Build()
```
**进程保护技术**：
- **DLL注入检测** - 监控异常的内存映射和模块加载
- **代码注入检测** - 检查可执行区域的异常变化  
- **内存布局分析** - 检测内存映射异常
- **API Hook检测** - 识别API拦截和重定向

**内存保护机制**：
- **关键数据加密** - 使用XOR等算法加密敏感内存区域
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
| 技术 | 级别 | 平台 | 描述 |
|------|------|------|------|
| IsDebuggerPresent | 1+ | Windows | 最基础的调试器检测API |
| PEB检查 | 1+ | Windows | 检查进程环境块中的调试标志 |
| TracerPid | 1+ | Linux | 检查进程跟踪状态 |
| P_TRACED | 1+ | macOS | 检查进程跟踪标志 |
| 时间差攻击 | 2+ | 全平台 | 通过执行时间检测单步调试 |
| 调试端口检查 | 2+ | Windows | 通过NT API检查调试端口 |
| 异常处理检测 | 2+ | Windows | 利用结构化异常处理检测 |
| 硬件断点检测 | 2+ | x86/x64 | 检查调试寄存器状态 |

#### 环境检测
| 环境类型 | 检测级别 | 检测方法 |
|----------|----------|----------|
| VMware | 2+ | 注册表项、设备名称、MAC地址前缀 |
| VirtualBox | 2+ | 注册表项、文件系统、设备枚举 |
| Hyper-V | 2+ | 系统信息、特殊标志位 |
| QEMU/KVM | 2+ | CPUID指令、设备信息 |
| Cuckoo沙箱 | 2+ | 特有文件、注册表、网络配置 |
| Joe沙箱 | 2+ | 环境变量、文件系统特征 |

### 环境检测技术

#### 虚拟机检测
- **VMware**: 检测VMware特有设备和注册表
- **VirtualBox**: 检查VBOX相关特征
- **Hyper-V**: 检测Microsoft虚拟化标志
- **QEMU**: 检查QEMU/KVM环境特征

#### 沙箱检测  
- **Cuckoo Sandbox**: 检测Cuckoo特有的文件和环境
- **Joe Sandbox**: 检查Joe分析环境特征
- **Anubis**: 检测Anubis恶意软件分析环境

### 进程保护技术

#### 注入检测
- **DLL注入**: 监控异常的内存映射和模块加载
- **代码注入**: 检查可执行区域的异常变化
- **内存布局**: 分析内存布局异常

#### 内存保护
- **关键数据加密**: 使用XOR加密保护敏感内存
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

### 配置文件支持

```yaml
# config.yaml
version: "2.0.0"
enterprise_id: 62996
security:
  enable_anti_debug: true
  enable_time_validation: true
  require_hardware_binding: true
  max_clock_skew: "5m"
cache:
  ttl: "10m"
  max_size: 5000
  cleanup_interval: "30m"
```

## 🔧 高级功能

### 批量证书处理

```go
// 创建批量管理器
batchManager := cert.NewBatchManager(auth)

// 添加批量签发任务
requests := []*cert.ClientCertRequest{ /* ... */ }
results := batchManager.IssueBatch(requests)

// 并发验证多个证书
validationTasks := []cert.ValidationTask{ /* ... */ }
results := batchManager.ValidateBatch(validationTasks)
```

### 缓存优化

```go
// 创建缓存授权管理器
cachedAuth := cert.NewCachedAuthorizer(auth, cert.CacheConfig{
    TTL:             10 * time.Minute,
    MaxSize:         1000,
    CleanupInterval: 5 * time.Minute,
})

// 验证会自动使用缓存
err := cachedAuth.ValidateCert(certPEM, machineID)
```

### 模板系统

```go
// 使用预定义模板
template := cert.GetTemplate("enterprise")
template.MaxValidDays = 730 // 2年有效期

// 创建自定义模板
customTemplate := &cert.CertificateTemplate{
    DefaultValidDays: 365,
    KeySize:         2048,
    Organization:    "My Company",
    // ...
}

cert.RegisterTemplate("custom", customTemplate)
```

## 📊 错误处理

系统提供详细的错误分类和处理建议：

```go
err := auth.ValidateCert(certPEM, machineID)
if err != nil {
    if certErr, ok := err.(*cert.CertError); ok {
        fmt.Printf("错误类型: %s\n", certErr.GetCode())
        fmt.Printf("错误详情: %v\n", certErr.GetDetails())
        fmt.Printf("解决建议: %v\n", certErr.GetSuggestions())
    }
}
```

### 错误类型

- `ValidationError`: 证书验证错误（格式、过期等）
- `SecurityError`: 安全检查错误（调试器、沙箱等）
- `ConfigError`: 配置错误（CA缺失、参数无效等）
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

### 性能监控

```go
// 启用性能统计
auth.EnableMetrics(true)

// 获取统计信息
stats := auth.GetMetrics()
fmt.Printf("验证成功率: %.2f%%\n", stats.SuccessRate)
fmt.Printf("平均验证时间: %v\n", stats.AvgValidationTime)
```

## 🏗️ 系统集成

### Web API 集成

```go
func validateLicenseHandler(w http.ResponseWriter, r *http.Request) {
    certData := r.Header.Get("X-License-Cert")
    machineID := r.Header.Get("X-Machine-ID")
    
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
2. **批量处理**: 大规模证书操作使用批量API
3. **异步更新**: 吊销列表和配置使用异步更新
4. **连接池**: 网络请求使用连接池复用
5. **内存管理**: 及时清理不需要的证书数据

### 性能指标

- 证书验证: ~1-5ms（缓存命中）
- 证书签发: ~10-50ms
- 安全检查: ~5-20ms
- 批量处理: 1000个证书/秒

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

### 集群部署

```go
// 支持多实例部署
auth := cert.NewAuthorizer().
    WithSharedCache(redis.NewClient()). // 使用Redis共享缓存
    WithDistributedLock().              // 分布式锁
    Build()
```

## ⚠️ 重要安全说明

### CA 私钥保护

CA 私钥是整个系统的核心，必须严格保护：

- **加密存储**: 使用硬件安全模块(HSM)或加密文件系统
- **访问控制**: 限制访问权限，使用最小权限原则  
- **备份策略**: 安全的密钥备份和恢复机制
- **定期轮换**: 定期更换CA密钥（建议2-5年）
- **审计日志**: 记录所有密钥使用操作

### 安全最佳实践

1. **网络安全**: 使用HTTPS传输证书和验证请求
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

完整的API文档请参阅：
- [GoDoc](https://pkg.go.dev/github.com/darkit/machineid/cert)
- [示例代码](./examples.go)
- [配置参考](./config.go)

## 🔄 版本兼容性

- **Go版本**: 需要 Go 1.19+
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

- 🐛 [报告Bug](https://github.com/darkit/machineid/issues/new?template=bug_report.md)
- 💡 [功能建议](https://github.com/darkit/machineid/issues/new?template=feature_request.md)  
- 📧 技术支持: support@example.com
- 📚 [Wiki文档](https://github.com/darkit/machineid/wiki)

---

**注意**: 本解决方案专为合法的软件授权管理设计，请遵守当地法律法规，不得用于恶意目的。
