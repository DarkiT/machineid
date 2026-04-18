# Changelog

本文件记录 machineid 库的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added

- **provider / hint 生命周期治理** (`binding_provider.go`, `container_scope_common.go`)
  - 新增 `UnregisterBindingProvider()`、`ResetBindingProviders()`
  - 新增 `RegisterNamedContainerHintProvider()`、`UnregisterContainerHintProvider()`、`ResetContainerHintProviders()`
  - 测试隔离可显式清理进程级注册表，避免长生命周期用例串扰

- **容器 hint 合成策略控制面** (`container_binding.go`, `container_scope_common.go`)
  - 新增 `ContainerHintCombineMode`、`GetContainerHintCombineMode()`、`SetContainerHintCombineMode()`
  - 显式容器感知 API 支持通过 `ContainerBindingConfig.HintCombineMode` 按调用控制特征合成语义

- **吊销列表自动更新机制** (`cert/revoke.go`)
  - `StartAutoUpdate()` / `StopAutoUpdate()` 方法
  - 可配置更新间隔、重试策略、回调通知
  - `IsAutoUpdateRunning()` 状态查询
  - `UpdateRevokeList()` 手动触发更新

- **环境类型检测** (`cert/security.go`)
  - `DetectEnvironment()` 方法区分物理机/VM/容器/沙箱
  - `EnvironmentType` 枚举：`EnvTypePhysical`、`EnvTypeVM`、`EnvTypeContainer`、`EnvTypeSandbox`
  - 容器环境不再误判为沙箱

- **完善的 Windows 容器检测** (`id_windows.go`)
  - 扩展 Kubernetes 环境变量检测（`KUBERNETES_SERVICE_HOST`、`KUBERNETES_PORT`）
  - 添加 Containerd 环境变量检测（`CONTAINERD_NAMESPACE`、`CONTAINERD_ADDRESS`）
  - 添加 Windows 容器特定路径检测

- **自定义绑定 provider / hint 生命周期 API** (`binding_provider.go`, `container_scope_common.go`)
  - `RegisterBindingProvider()` / `UnregisterBindingProvider()` / `ResetBindingProviders()` 管理自定义绑定提供者
  - `RegisterContainerHintProvider()` / `RegisterNamedContainerHintProvider()` / `UnregisterContainerHintProvider()` / `ResetContainerHintProviders()` 管理容器稳定特征提供者
  - 具名 provider 支持按名称替换，便于应用初始化、热更新与测试清理

- **测试补充**
  - `cert/revoke_test.go`：吊销管理器完整测试（并发、自动更新、重试）
  - `cert/benchmark_test.go`：基准测试（缓存、批量操作、安全检查）
  - `container_scope_linux_test.go`、`id_binding_logic_test.go`、`id_linux_internal_test.go`、`id_binding_test.go`：覆盖 hint 合成模式、缓存清理、provider 生命周期与兼容迁移路径

### Changed

- **生产环境安全级别提升** (`cert/authorizer.go`)
  - `ForProduction()` 安全级别从 1 提升到 2（高级安全）
  - 启用完整反逆向保护、VM/沙箱检测
  - 如需保持旧行为，可使用 `WithSecurityLevel(1)` 显式覆盖

- **批量签发支持多线程** (`cert/batch.go`)
  - 移除强制单线程限制
  - 支持 `WithMaxWorkers(n)` 配置并发数
  - 竞态检测验证通过

- **错误缓存 TTL 优化** (`id.go`)
  - 分离成功和失败的缓存 TTL
  - 成功缓存：5 分钟（默认）
  - 错误缓存：10 秒（避免临时错误长期缓存）
  - 新增 `SetCacheTTL()` 配置函数

- **容器 ID 截取逻辑** (`container_id_parse.go`)
  - 改为从开头截取（保留容器 ID 有效部分）
  - 添加更多容器运行时前缀处理（Containerd、CRI-O、Podman）
  - 放宽十六进制限制，支持字母数字混合 ID

- **容器绑定最佳实践文档** (`README.md`, `cert/README.md`)
  - 明确底层 `ID()` fallback 才应使用进程级 `SetContainerHintCombineMode()`
  - 明确 `ProtectedIDWithContainerAware()` / `UniqueIDResult()` 应优先使用 `ContainerBindingConfig.HintCombineMode`
  - 明确内置 `defaultCACert` / `defaultCAKey` 仅用于开发、测试与兜底兼容，生产必须显式替换

- **容器 scoped ID hint 合成策略兼容迁移** (`container_scope_common.go`, `container_binding.go`, `id.go`)
  - 保持历史兼容：默认 `ContainerHintCombineFirst` 仅消费第一条非空 hint，避免旧 `container_scoped` 结果突变
  - 新增 `ContainerHintCombineAll`，按顺序合成全部非空且去重后的稳定特征，支持更稳定的容器派生 ID
  - `SetContainerHintCombineMode()` 切换策略时自动清理 ID 缓存，避免新旧模式混用

- **容器感知高层 API 的 hint 配置优先级** (`container_binding.go`, `id.go`)
  - `DefaultContainerBindingConfig()` 默认将 `HintCombineMode` 设为 `ContainerHintCombineAll`
  - `ProtectedIDWithContainerAware()` 及相关高层容器绑定路径优先读取 `ContainerBindingConfig.HintCombineMode`
  - 建议业务侧优先在 `ContainerBindingConfig` 中显式声明策略，而非依赖进程级全局模式，以降低迁移期兼容风险

### Fixed

- **VM 检测不再误判容器环境** (`cert/security.go`)
  - 分离容器检测与沙箱检测逻辑
  - Docker/Kubernetes/Containerd 环境正确识别为容器
  - 仅 Cuckoo/Joe Sandbox 等分析环境触发沙箱警告

- **容器 ID 解析支持更多格式** (`container_id_parse.go`)
  - 支持 `kubepods-burstable-`、`kubepods-besteffort-` 等 K8s 前缀
  - 支持 `cri-containerd-`、`crio-` 等运行时前缀
  - 正确处理 `.scope`、`.slice`、`.service` 后缀

- **容器 scoped ID 兼容迁移** (`container_scope_common.go`, `id.go`)
  - 保留默认单 hint 旧语义，避免静默 breaking change
  - 新增显式 `all hints` 合成路径，并在切换底层模式时自动清理 `ID()` 缓存
  - `ProtectedIDWithContainerAware(nil)` 与既有 `UniqueID` provider/mode 语义保持不变

### Performance

- **O(1) LRU 缓存驱逐** (`cert/cache.go`)
  - 使用 `container/list` 双向链表实现
  - 大缓存时驱逐性能稳定
  - 并发安全的缓存键生成

### Security

- **并发安全增强** (`cert/cache.go`)
  - 缓存键生成使用 `make` + `copy` 避免竞态
  - 在锁外计算 key，减少持锁时间

---

## 版本历史

### v1.0.0 (初始版本)

- 跨平台机器码生成（Windows/Linux/macOS）
- Ed25519 证书签发与验证
- 4 级安全防护系统
- 证书监控与吊销管理
- 批量证书处理
- 智能缓存机制
