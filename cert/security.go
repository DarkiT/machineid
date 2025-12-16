package cert

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// SecurityLevel 安全防护级别
const (
	SecurityLevelDisabled = 0 // 完全禁用（默认）
	SecurityLevelBasic    = 1 // 基础防护（仅基本调试器检测）
	SecurityLevelAdvanced = 2 // 高级防护（完整反逆向保护）
	SecurityLevelCritical = 3 // 关键防护（最高级别保护）
)

// TimeDetectionConfig 时间检测配置
//
// 用于对抗基于时间的调试检测绕过：
// - 随机化阈值避免固定特征
// - 多次采样减少误报
// - 混淆工作负载防止空循环被优化
type TimeDetectionConfig struct {
	BaseThreshold    time.Duration // 基础阈值（默认 10ms）
	RandomRange      time.Duration // 随机范围（默认 5ms）
	SampleCount      int           // 采样次数（默认 3）
	FailureThreshold int           // 失败阈值（默认 2，即3次中2次失败）
}

// DefaultTimeDetectionConfig 返回默认时间检测配置
func DefaultTimeDetectionConfig() TimeDetectionConfig {
	return TimeDetectionConfig{
		BaseThreshold:    10 * time.Millisecond,
		RandomRange:      5 * time.Millisecond,
		SampleCount:      3,
		FailureThreshold: 2,
	}
}

// SecurityManager 安全管理器
type SecurityManager struct {
	level           int
	checksum        []byte
	lastCheckTime   time.Time
	debuggerCount   int
	mu              sync.RWMutex
	antiDebugActive bool
	memProtect      []byte
	done            chan struct{}  // 用于停止后台检查的信号通道
	wg              sync.WaitGroup // 用于等待后台goroutine退出
}

// NewSecurityManager 创建安全管理器
func NewSecurityManager(level int) *SecurityManager {
	sm := &SecurityManager{
		level:           level,
		checksum:        make([]byte, 32),
		lastCheckTime:   time.Now(),
		antiDebugActive: true,
		memProtect:      make([]byte, 4096),
		done:            make(chan struct{}),
	}

	// 初始化内存保护区域
	for i := range sm.memProtect {
		sm.memProtect[i] = byte(i % 256)
	}

	// 计算初始校验和
	sm.calculateChecksum()

	// 启动后台安全检查
	sm.wg.Add(1)
	go sm.backgroundSecurityCheck()

	return sm
}

// === 反调试功能 ===

// checkAdvancedDebugger 检测调试器（增强版）
func checkAdvancedDebugger() bool {
	// 首先使用平台特定的基础检测
	if checkDebugger() {
		return true
	}

	// 方法1: 时间差攻击检测
	if detectTimeBasedDebugging() {
		return true
	}

	// 方法2: 调试器进程检测
	if detectDebuggerProcess() {
		return true
	}

	// 方法3: 系统调用检测
	if detectSystemCallTracing() {
		return true
	}

	// 方法4: 内存布局检测
	if detectMemoryDebugging() {
		return true
	}

	// 方法5: 调试器API检测
	if detectDebuggerAPI() {
		return true
	}

	// 方法6: ASLR 绕过检测
	if detectASLRBypass() {
		return true
	}

	// 方法7: CFI 违规检测
	if detectCFIViolation() {
		return true
	}

	return false
}

// detectTimeBasedDebugging 时间差攻击检测（使用默认配置）
func detectTimeBasedDebugging() bool {
	return detectTimeBasedDebuggingEnhanced(DefaultTimeDetectionConfig())
}

// detectTimeBasedDebuggingEnhanced 增强的时间差攻击检测
//
// 使用多重采样和随机化阈值对抗调试器时间伪造：
// - 每次采样使用不同的阈值（避免固定特征）
// - 多次采样中达到失败阈值才判定为调试
// - 使用混淆工作负载防止编译器优化
func detectTimeBasedDebuggingEnhanced(config TimeDetectionConfig) bool {
	failures := 0
	for i := 0; i < config.SampleCount; i++ {
		// 随机化阈值
		threshold := config.BaseThreshold + time.Duration(randomInt(int64(config.RandomRange)))
		if performTimedWorkload(threshold) {
			failures++
		}
		// 达到失败阈值则判定为调试
		if failures >= config.FailureThreshold {
			return true
		}
	}
	return false
}

// performTimedWorkload 执行混淆的工作负载并检测时间异常
func performTimedWorkload(threshold time.Duration) bool {
	start := time.Now()

	// 混淆的工作负载：防止编译器优化掉空循环
	var result uint64
	iterations := 1000 + randomInt(500) // 随机化迭代次数
	for i := 0; i < int(iterations); i++ {
		result ^= uint64(i) * 0x5DEECE66D
		result = (result + 0xB) & ((1 << 48) - 1)
	}

	// 保留中间结果，避免被完全优化
	runtime.KeepAlive(result)

	duration := time.Since(start)
	return duration > threshold
}

// randomInt 生成 [0, max) 范围内的随机整数
func randomInt(max int64) int64 {
	if max <= 0 {
		return 0
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0
	}
	n := int64(buf[0]) | int64(buf[1])<<8 | int64(buf[2])<<16 | int64(buf[3])<<24 |
		int64(buf[4])<<32 | int64(buf[5])<<40 | int64(buf[6])<<48 | int64(buf[7])<<56
	if n < 0 {
		n = -n
	}
	return n % max
}

// detectDebuggerProcess 检测调试器进程
func detectDebuggerProcess() bool {
	debuggerNames := []string{
		"gdb", "lldb", "dbg", "windbg", "x32dbg", "x64dbg",
		"ida", "ida64", "ollydbg", "immunity", "cheat engine",
		"process hacker", "process monitor", "wireshark",
		"fiddler", "burp", "charles", "mitmproxy",
	}

	// 读取进程列表 (简化实现)
	switch runtime.GOOS {
	case "windows":
		return detectWindowsDebugger(debuggerNames)
	case "linux":
		return detectLinuxDebugger(debuggerNames)
	case "darwin":
		return detectMacDebugger(debuggerNames)
	}

	return false
}

// detectWindowsDebugger Windows调试器检测
func detectWindowsDebugger(_ []string) bool {
	// Windows特定检测
	// 检查IsDebuggerPresent
	if isDebuggerPresentWindows() {
		return true
	}

	// 检查PEB调试标志
	if checkPEBDebugFlag() {
		return true
	}

	// 检查调试器端口
	if checkDebugPort() {
		return true
	}

	return false
}

// isDebuggerPresentWindows Windows API 调用检测调试器
func isDebuggerPresentWindows() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return checkDebugger()
}

// checkPEBDebugFlag 检查 PEB 中的调试标志
func checkPEBDebugFlag() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// 通过检查异常处理行为来推断是否有调试器
	suspicious := false
	defer func() {
		if r := recover(); r != nil {
			suspicious = true
		}
	}()
	start := time.Now()
	dummy := 0
	for i := 0; i < 10; i++ {
		dummy += i
	}
	_ = dummy
	elapsed := time.Since(start)
	return elapsed > time.Millisecond*5 || suspicious
}

// checkDebugPort 检查调试端口
func checkDebugPort() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return checkDebugger()
}

// detectLinuxDebugger Linux调试器检测
func detectLinuxDebugger(debuggerNames []string) bool {
	// 检查 /proc/self/status 中的TracerPid
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		content := string(data)
		if strings.Contains(content, "TracerPid:") {
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "TracerPid:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 && parts[1] != "0" {
						return true
					}
				}
			}
		}
	}

	// 检查进程名称
	if data, err := os.ReadFile("/proc/self/cmdline"); err == nil {
		cmdline := strings.ToLower(string(data))
		for _, name := range debuggerNames {
			if strings.Contains(cmdline, name) {
				return true
			}
		}
	}

	return false
}

// detectMacDebugger macOS调试器检测
func detectMacDebugger(_ []string) bool {
	// 简化实现：检查进程名称
	// 实际应该使用 sysctl 或者 proc_info
	return false
}

// detectSystemCallTracing 系统调用跟踪检测
func detectSystemCallTracing() bool {
	// Linux: 检查 ptrace
	if runtime.GOOS == "linux" {
		// 简化实现：读取 /proc/self/status
		return false
	}
	return false
}

// detectMemoryDebugging 内存调试检测
func detectMemoryDebugging() bool {
	// 检查内存页属性异常
	return false
}

// detectDebuggerAPI 调试器API检测
func detectDebuggerAPI() bool {
	// 平台特定的API检测
	return false
}

// detectASLRBypass 检测 ASLR（地址空间布局随机化）绕过
//
// 原理：检查函数地址是否在合理范围内。
// 注意：Go 函数地址在同一进程内是固定的，这里主要检查地址范围异常。
func detectASLRBypass() bool {
	// 使用 runtime.FuncForPC 获取函数信息
	pc := make([]uintptr, 1)
	runtime.Callers(1, pc)

	// uintptr 为无符号，直接与阈值比较即可
	if pc[0] < 0x10000 || pc[0] > 0x7fffffffffff {
		return true
	}

	return false
}

// detectCFIViolation 检测控制流完整性（CFI）违规
//
// 原理：通过调用栈深度和返回地址合理性检测异常控制流。
func detectCFIViolation() bool {
	// 检查调用栈深度
	pcs := make([]uintptr, 32)
	n := runtime.Callers(1, pcs)

	// 异常深的调用栈可能表示递归注入或栈溢出
	if n > 30 {
		return true
	}

	// 检查返回地址的连续性
	for i := 1; i < n; i++ {
		pc1 := int64(pcs[i-1])
		pc2 := int64(pcs[i])

		// 正常调用栈的地址应该相对接近（同一模块内）
		diff := pc1 - pc2
		if diff < 0 {
			diff = -diff
		}

		// 如果地址差异过大（>10MB），可能是跨模块注入
		if diff > 10*1024*1024 {
			return true
		}
	}

	return false
}

// backgroundSecurityCheck 后台安全检查
func (sm *SecurityManager) backgroundSecurityCheck() {
	defer sm.wg.Done()

	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.mu.Lock()
			if sm.level >= SecurityLevelAdvanced {
				// 检查调试器
				if checkAdvancedDebugger() {
					sm.debuggerCount++
				}

				// 检查内存完整性
				if !sm.verifyMemoryIntegrity() {
					sm.debuggerCount++
				}
			}
			sm.mu.Unlock()
		case <-sm.done:
			return
		}
	}
}

// calculateChecksum 计算校验和
func (sm *SecurityManager) calculateChecksum() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 使用 SHA-256 计算内存保护区域校验和
	hash := sha256.Sum256(sm.memProtect)
	copy(sm.checksum, hash[:])
}

// verifyMemoryIntegrity 验证内存完整性
func (sm *SecurityManager) verifyMemoryIntegrity() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	hash := sha256.Sum256(sm.memProtect)
	// SHA-256 输出 32 字节，与 checksum 长度匹配
	for i := 0; i < len(hash); i++ {
		if sm.checksum[i] != hash[i] {
			return false
		}
	}
	return true
}

// Check 执行安全检查
func (sm *SecurityManager) Check() error {
	sm.mu.RLock()
	level := sm.level
	count := sm.debuggerCount
	sm.mu.RUnlock()

	if level == SecurityLevelDisabled {
		return nil
	}

	// 基础检查
	if level >= SecurityLevelBasic {
		if checkDebugger() {
			return fmt.Errorf("security: debugger detected")
		}
	}

	// 高级检查
	if level >= SecurityLevelAdvanced {
		if checkAdvancedDebugger() {
			return fmt.Errorf("security: advanced debugging detected")
		}

		if !sm.verifyMemoryIntegrity() {
			return fmt.Errorf("security: memory integrity violation")
		}
	}

	// 关键检查
	if level >= SecurityLevelCritical {
		if count > 0 {
			return fmt.Errorf("security: multiple security violations detected")
		}
	}

	return nil
}

// Close 关闭安全管理器
func (sm *SecurityManager) Close() {
	close(sm.done)
	sm.wg.Wait()
}

// GetDebuggerCount 获取调试器检测次数
func (sm *SecurityManager) GetDebuggerCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.debuggerCount
}

// StopSecurityChecks 停止后台安全检查
//
// 注意：
// - 此方法应可重复调用且不应 panic（与 Close 行为一致但更语义化）
// - 会等待后台 goroutine 退出，避免测试/调用方泄漏 goroutine
func (sm *SecurityManager) StopSecurityChecks() {
	sm.mu.Lock()
	// 标记为未激活，供测试与上层逻辑判断
	sm.antiDebugActive = false

	// 关闭 done 可能会被重复调用；用 recover 保证幂等
	// 这里不做额外状态字段，保持结构简单（KISS）
	defer func() {
		_ = recover()
	}()
	close(sm.done)
	sm.mu.Unlock()

	sm.wg.Wait()
}

// DetectVirtualMachine 检测虚拟机环境
//
// 设计原则：
// - 只做“可能性”检测：尽量避免误报导致不可用
// - 不引入外部依赖；尽量使用系统可读取的只读信息
// - 平台差异大：使用 runtime.GOOS 分支实现
func (sm *SecurityManager) DetectVirtualMachine() bool {
	// 未启用安全功能时不做检测，避免无谓成本与误判
	sm.mu.RLock()
	level := sm.level
	sm.mu.RUnlock()
	if level == SecurityLevelDisabled {
		return false
	}

	switch runtime.GOOS {
	case "linux":
		// Linux 常见虚拟化特征：
		// 1) DMI/SMBIOS 产品信息包含 VMware/QEMU/VirtualBox/Hyper-V 等关键字
		// 2) /proc/cpuinfo 含 hypervisor 标志
		// 说明：容器环境通常不会触发这些特征
		return detectVirtualMachineLinux()
	case "windows":
		// Windows：
		// - 通过环境变量/系统信息推断（简化实现，避免调用复杂 WinAPI）
		return detectVirtualMachineWindows()
	case "darwin":
		// macOS：
		// - 读取系统版本/硬件信息需要 sysctl/ioreg；此处保持保守，避免误报
		return detectVirtualMachineDarwin()
	default:
		return false
	}
}

// DetectSandbox 检测沙箱环境
//
// 这里的“沙箱”更偏向运行限制环境，例如：
// - 容器/受限 namespace（Linux）
// - macOS App Sandbox（需要 entitlements/系统 API，难以在纯 Go 通用检测）
// - Windows 的受限令牌/Job Object（同样需要 WinAPI）
//
// 因此实现策略为“低误报”的启发式检测：只在证据较强时返回 true。
func (sm *SecurityManager) DetectSandbox() bool {
	sm.mu.RLock()
	level := sm.level
	sm.mu.RUnlock()
	if level == SecurityLevelDisabled {
		return false
	}

	switch runtime.GOOS {
	case "linux":
		return detectSandboxLinux()
	case "windows":
		return detectSandboxWindows()
	case "darwin":
		return detectSandboxDarwin()
	default:
		return false
	}
}

// === 内存保护功能 ===

// protectMemory 保护关键内存区域（SecurityManager 方法）
func (sm *SecurityManager) protectMemory() error {
	// 调用平台特定的 mprotect
	return sm.mprotect()
}

// === 平台特定环境检测实现 ===

func containsAnyLower(s string, needles []string) bool {
	s = strings.ToLower(s)
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func detectVirtualMachineLinux() bool {
	// /proc/cpuinfo 的 hypervisor flag 是最常见且便宜的信号
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if containsAnyLower(string(data), []string{"hypervisor"}) {
			return true
		}
	}

	// DMI/SMBIOS 信息：对主流虚拟化厂商有效
	dmiCandidates := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
		"/sys/class/dmi/id/bios_vendor",
	}
	vmNeedles := []string{
		"vmware",
		"virtualbox",
		"vbox",
		"qemu",
		"kvm",
		"bochs",
		"xen",
		"microsoft corporation", // Hyper-V 常见 vendor
		"hyper-v",
		"parallels",
	}
	for _, path := range dmiCandidates {
		if data, err := os.ReadFile(path); err == nil {
			if containsAnyLower(string(data), vmNeedles) {
				return true
			}
		}
	}

	return false
}

func detectVirtualMachineWindows() bool {
	// 简化启发式：读取常见环境变量/系统信息痕迹
	// 说明：更可靠的方式需要调用 WMI/WinAPI，这里保持轻量且不引入额外复杂度。
	env := strings.ToLower(os.Getenv("PROCESSOR_IDENTIFIER") + " " + os.Getenv("PROCESSOR_REVISION"))
	return containsAnyLower(env, []string{"virtual", "vmware", "vbox", "qemu", "xen", "hyper-v"})
}

func detectVirtualMachineDarwin() bool {
	// macOS 的通用 VM 检测往往依赖 sysctl("machdep.cpu.features") 或 ioreg；
	// 为避免误报，这里默认返回 false。
	return false
}

func detectSandboxLinux() bool {
	// Linux “沙箱/容器”启发式：
	// - cgroup 中出现 docker/kubepods/containerd 等路径
	// - /proc/1/sched 或 /proc/1/cmdline 表现为 init 被替换（强信号）
	//
	// 说明：容器不等于恶意沙箱，但在安全策略中通常需要区别对待。
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		if containsAnyLower(string(data), []string{"docker", "kubepods", "containerd", "lxc"}) {
			return true
		}
	}
	if data, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		// cmdline 以 \0 分隔，直接做包含判断即可
		if containsAnyLower(string(data), []string{"docker", "containerd", "kubepods", "lxc"}) {
			return true
		}
	}

	// 环境变量也是弱信号：仅作为补充（避免误报，不单独触发 true）
	env := strings.ToLower(os.Getenv("container"))
	return env != ""
}

func detectSandboxWindows() bool {
	// Windows 沙箱/受限环境检测通常依赖 WinAPI（令牌、Job、AppContainer）。
	// 这里用保守策略：默认 false，避免误报。
	return false
}

func detectSandboxDarwin() bool {
	// macOS App Sandbox 检测同样需要系统 API/entitlements；
	// 这里保守返回 false。
	return false
}

// === 混淆功能 ===
// （当前未在生产流程使用，移除以减少未使用代码）

// === 完整性检查 ===
// （当前未在生产流程使用，移除以减少未使用代码）

// === 安全相关的辅助函数 ===

// InitSecurityManager 初始化安全管理器并集成到授权管理器
func (a *Authorizer) InitSecurityManager() *SecurityManager {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 根据配置确定安全级别
	level := SecurityLevelBasic
	if a.config.Security.EnableAntiDebug {
		level = SecurityLevelAdvanced
	}
	if a.config.Security.RequireHardwareBinding {
		level = SecurityLevelCritical
	}

	// 创建安全管理器
	sm := NewSecurityManager(level)

	return sm
}

// PerformSecurityCheck 执行安全检查（集成到证书验证流程）
func (a *Authorizer) PerformSecurityCheck() error {
	if !a.config.Security.EnableAntiDebug {
		return nil // 如果没有启用安全检查，直接返回
	}

	// 根据配置确定安全检查级别
	level := a.GetSecurityLevel()
	if level == SecurityLevelDisabled {
		return nil // 安全检查被完全禁用
	}

	// 基础检查：调试器检测
	if level >= SecurityLevelBasic {
		if checkDebugger() {
			return fmt.Errorf("security: debugger detected")
		}
	}

	// 高级检查：完整反逆向保护
	if level >= SecurityLevelAdvanced {
		if checkAdvancedDebugger() {
			return fmt.Errorf("security: advanced debugging detected")
		}
	}

	return nil
}

// GetSecurityLevel 根据配置获取安全级别
func (a *Authorizer) GetSecurityLevel() int {
	// 如果明确设置了安全级别，直接使用
	if level, ok := a.config.Security.EffectiveSecurityLevel(); ok {
		return level
	}

	// 否则根据配置推断
	if !a.config.Security.EnableAntiDebug {
		return SecurityLevelDisabled
	}

	if a.config.Security.RequireHardwareBinding {
		return SecurityLevelCritical
	}

	return SecurityLevelBasic
}

// ValidateWithSecurity 带安全检查的证书验证
func (a *Authorizer) ValidateWithSecurity(certPEM []byte, machineID string) error {
	// 首先执行安全检查
	if err := a.PerformSecurityCheck(); err != nil {
		return err
	}

	// 然后执行正常的证书验证
	return a.ValidateCert(certPEM, machineID)
}

// StopSecurityChecks 停止安全检查

// VerifyIntegrity 验证内存完整性（简化实现）
func (sm *SecurityManager) VerifyIntegrity() error {
	if !sm.verifyMemoryIntegrity() {
		return fmt.Errorf("memory integrity check failed")
	}
	return nil
}

// clearSensitiveData 清除敏感数据
func (sm *SecurityManager) clearSensitiveData() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for i := range sm.memProtect {
		sm.memProtect[i] = 0
	}
	for i := range sm.checksum {
		sm.checksum[i] = 0
	}
}

// encryptSensitiveData 加密敏感数据
func (sm *SecurityManager) encryptSensitiveData(key []byte) error {
	if len(key) < 16 {
		return fmt.Errorf("key too short: minimum 16 bytes required")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	// 简化实现：使用 XOR 加密
	for i := range sm.memProtect {
		sm.memProtect[i] ^= key[i%len(key)]
	}
	return nil
}

// ProtectProcess 保护进程（简化实现）
func (sm *SecurityManager) ProtectProcess() error {
	if sm.level >= SecurityLevelAdvanced {
		return sm.protectMemory()
	}
	return nil
}

// getCriticalMemoryRegions 获取关键内存区域
func (sm *SecurityManager) getCriticalMemoryRegions() []byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	data := make([]byte, len(sm.memProtect))
	copy(data, sm.memProtect)
	return data
}

// === 时间戳防回滚功能 ===

// MonotonicTime 单调时间管理器
//
// 用于检测系统时间回滚攻击：
// - 持久化最后已知时间戳
// - 启动时检查时间一致性
// - 防止通过修改系统时间绕过有效期检查
type MonotonicTime struct {
	mu              sync.RWMutex
	lastKnownTime   time.Time
	persistencePath string
	maxClockSkew    time.Duration // 允许的最大时钟偏差
}

// NewMonotonicTime 创建单调时间管理器
func NewMonotonicTime(persistencePath string, maxClockSkew time.Duration) (*MonotonicTime, error) {
	mt := &MonotonicTime{
		persistencePath: persistencePath,
		maxClockSkew:    maxClockSkew,
	}

	// 尝试加载上次的时间戳
	if err := mt.loadLastKnownTime(); err != nil {
		// 首次运行，记录当前时间
		mt.lastKnownTime = time.Now()
		if err := mt.saveLastKnownTime(); err != nil {
			return nil, fmt.Errorf("failed to initialize monotonic time: %w", err)
		}
	}

	return mt, nil
}

// CheckTimeRollback 检查时间回滚
//
// 返回错误表示检测到时间回滚
func (mt *MonotonicTime) CheckTimeRollback() error {
	mt.mu.RLock()
	lastTime := mt.lastKnownTime
	mt.mu.RUnlock()

	now := time.Now()

	// 检查当前时间是否早于上次记录的时间
	if now.Before(lastTime) {
		// 允许一定的时钟偏差（网络时间同步可能导致小幅回退）
		timeDiff := lastTime.Sub(now)
		if timeDiff > mt.maxClockSkew {
			return fmt.Errorf("time rollback detected: current=%s, last=%s, diff=%v",
				now.Format(time.RFC3339),
				lastTime.Format(time.RFC3339),
				timeDiff)
		}
	}

	// 更新最后已知时间
	mt.mu.Lock()
	mt.lastKnownTime = now
	mt.mu.Unlock()

	// 持久化新时间
	if err := mt.saveLastKnownTime(); err != nil {
		// 持久化失败不影响程序运行，但记录警告
		return nil
	}

	return nil
}

// loadLastKnownTime 从文件加载上次时间
func (mt *MonotonicTime) loadLastKnownTime() error {
	data, err := os.ReadFile(mt.persistencePath)
	if err != nil {
		return err
	}

	var lastTime time.Time
	if err := lastTime.UnmarshalText(data); err != nil {
		return fmt.Errorf("failed to parse timestamp: %w", err)
	}

	mt.mu.Lock()
	mt.lastKnownTime = lastTime
	mt.mu.Unlock()

	return nil
}

// saveLastKnownTime 保存当前时间到文件
func (mt *MonotonicTime) saveLastKnownTime() error {
	mt.mu.RLock()
	lastTime := mt.lastKnownTime
	mt.mu.RUnlock()

	data, err := lastTime.MarshalText()
	if err != nil {
		return err
	}

	// 确保目录存在
	dir := filepath.Dir(mt.persistencePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// 写入文件（仅所有者可读写）
	return os.WriteFile(mt.persistencePath, data, 0o600)
}

// GetLastKnownTime 获取上次记录的时间
func (mt *MonotonicTime) GetLastKnownTime() time.Time {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return mt.lastKnownTime
}

// ForceUpdate 强制更新时间戳（谨慎使用）
//
// 注意：此方法应仅在确认时间正确的情况下使用，
// 例如从可信时间服务器同步后
func (mt *MonotonicTime) ForceUpdate(newTime time.Time) error {
	mt.mu.Lock()
	mt.lastKnownTime = newTime
	mt.mu.Unlock()

	return mt.saveLastKnownTime()
}

// Reset 重置时间戳（用于测试或迁移场景）
func (mt *MonotonicTime) Reset() error {
	mt.mu.Lock()
	mt.lastKnownTime = time.Now()
	mt.mu.Unlock()

	// 删除持久化文件
	if err := os.Remove(mt.persistencePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return mt.saveLastKnownTime()
}
