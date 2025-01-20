# Cert 软件授权管理解决方案包

`cert` 包提供了一个完整的证书管理解决方案，专门用于软件授权管理。它支持证书的签发、验证、吊销以及版本控制等功能。

## 主要特性

### 证书管理
- CA 证书生成和管理
- 客户端证书签发
- 证书验证和吊销
- 支持自定义 CA

### 安全特性
- 机器码绑定
- 防调试保护
- 时间篡改检测
- 版本控制

### 授权管理
- 证书吊销列表
- 版本强制更新
- 有效期管理
- 客户信息管理

## 安装

```bash
go get github.com/darkit/machineid/cert
```

## 快速开始

### 1. 创建授权管理器

```go
import "github.com/darkit/machineid/cert"

// 使用默认配置
auth, err := cert.New()

// 或使用自定义 CA
auth, err := cert.New(
    cert.WithCA(customCACert, customCAKey),
    cert.WithVersion("1.0.0"),
)
```

### 2. 生成新的 CA 证书

```go
caInfo := cert.CAInfo{
    CommonName:   "My Software CA",
    Organization: "My Company",
    Country:      "CN",
    Province:     "Guangdong",
    Locality:     "Shenzhen",
    ValidDays:    3650,  // 10年有效期
    KeySize:      4096,
}

err := auth.GenerateCA(caInfo)
```

### 3. 签发客户端证书

```go
clientInfo := cert.ClientInfo{
    MachineID:     machineID,
    ExpiryDate:    time.Now().AddDate(1, 0, 0),  // 一年有效期
    CompanyName:   "客户公司",
    Department:    "技术部",
    ContactPerson: "张三",
    ContactPhone:  "13800138000",
    ContactEmail:  "zhangsan@example.com",
    Version:       "1.0.0",
    MaxValidDays:  365,
}

certificate, err := auth.IssueClientCert(clientInfo)
```

### 4. 验证证书

```go
// 验证证书
err := auth.ValidateCert(certPEM, machineID)
```

### 5. 证书吊销管理

```go
// 设置吊销列表
auth, err := cert.New(
    cert.WithRevokeList([]byte(`{
        "updateTime": "2024-02-14T12:00:00Z",
        "minVersion": "1.0.0",
        "revokedCerts": {
            "123456": {
                "serialNumber": "123456",
                "revokeDate": "2024-02-14T12:00:00Z",
                "revokeReason": "security issue"
            }
        }
    }`)),
)

// 或设置动态更新函数
auth, err := cert.New(
    cert.WithRevokeListUpdater(func() ([]byte, error) {
        // 从远程服务器获取最新的吊销列表
        return http.Get("https://example.com/revoke-list")
    }),
)
```

## CA 证书和私钥说明

CA（Certificate Authority）由两个重要部分组成：
1. CA 证书（ca.crt）：公开部分，用于验证由该 CA 签发的证书
2. CA 私钥（ca.key）：私密部分，用于签发新的证书

### CA 私钥的重要性

CA 私钥（ca.key）是整个证书系统的核心，必须严格保护：
- 它用于签发所有客户端证书
- 如果泄露，攻击者可以签发任意伪造的证书
- 一旦泄露，所有已签发的证书都需要重新签发

## 平台支持

- Windows
- Linux
- macOS

## 版本控制

支持通过证书强制客户端版本更新：
- 可设置最低支持版本
- 支持按证书控制版本
- 支持全局版本策略

## 注意事项

1. 证书管理
   - 妥善保管 CA 私钥
   - 定期更新证书
   - 实施证书备份策略

2. 版本管理
   - 合理设置版本号
   - 谨慎使用强制更新
   - 做好版本兼容性测试

3. 性能考虑
   - 证书验证缓存
   - 吊销列表更新策略
   - 并发处理优化

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request！