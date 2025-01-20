# machineid

`machineid` 是一个跨平台的机器码生成包，用于获取设备的唯一标识符。它支持多种操作系统，并提供了安全的机器码保护机制。

## 主要特性

### 跨平台支持
- Windows (Win7+)
- Linux (Debian 8+, Ubuntu 14.04+)
- macOS (10.6+)
- FreeBSD (11+)
- AIX
- NetBSD
- OpenBSD
- DragonFly
- Solaris

### 核心功能
- 获取设备唯一标识
- 支持加密保护的机器码
- 容器环境识别
- MAC 地址绑定
- 无需管理员权限

### 安全特性
- HMAC-SHA256 加密保护
- UUID 生成
- 物理网卡绑定
- 容器 ID 识别

## 安装

```bash
go get github.com/darkit/machineid
```

## 快速开始

### 1. 获取原始机器码

```go
import "github.com/darkit/machineid"

id, err := machineid.ID()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Machine ID:", id)
```

### 2. 获取加密保护的机器码

```go
protectedID, err := machineid.ProtectedID("your.app.id")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Protected ID:", protectedID)
```

## 工作原理

### Windows
- 从注册表 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography` 读取 MachineGuid

### Linux
按以下顺序查找机器码：
1. `MACHINE_ID_FILE` 环境变量指定的文件
2. `/var/lib/dbus/machine-id`
3. `/etc/machine-id`
4. `$HOME/.config/machine-id`

### macOS
- 使用 `ioreg` 命令获取 IOPlatformUUID

### BSD 系统
- 从 `/etc/hostid` 读取
- 如果失败，使用 `kenv -q smbios.system.uuid`

### 容器环境
- 自动检测 Docker/Containerd 环境
- 使用容器 ID 作为机器标识

## 注意事项

1. 机器码稳定性
   - 原始机器码（ID）在操作系统重装前保持稳定
   - 原始机器码不受硬件更换影响
   - 系统更新通常不会改变原始机器码

2. 加密保护机器码（ProtectedID）
   - 与物理网卡 MAC 地址绑定
   - 更换网卡会导致加密保护的机器码发生变化
   - 建议在部署时考虑网卡更换的影响

3. 特殊情况
   - 虚拟机克隆会复制相同的机器码
   - 容器环境使用容器 ID
   - Linux 系统可使用 `dbus-uuidgen` 生成新 ID

4. 安全建议
   - 建议使用 `ProtectedID` 而不是原始 `ID`
   - 妥善保管应用 ID

## 性能考虑

- 缓存机制：首次获取后缓存结果
- 并发安全：支持并发访问
- 资源消耗：轻量级实现

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 参考资料

- [Machine ID 说明](https://github.com/denisbrodbeck/machineid/issues/5#issuecomment-523803164)
- [Unix Machine ID](https://unix.stackexchange.com/questions/144812/generate-consistent-machine-unique-id)