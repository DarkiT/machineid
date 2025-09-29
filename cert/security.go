package cert

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// SecurityLevel 安全防护级别
const (
	SecurityLevelDisabled = 0 // 完全禁用（默认）
	SecurityLevelBasic    = 1 // 基础防护（仅基本调试器检测）
	SecurityLevelAdvanced = 2 // 高级防护（完整反逆向保护）
	SecurityLevelCritical = 3 // 关键防护（最高级别保护）
)

// SecurityManager 安全管理器
type SecurityManager struct {
	level           int
	checksum        []byte
	lastCheckTime   time.Time
	debuggerCount   int
	mu              sync.RWMutex
	antiDebugActive bool
	memProtect      []byte
}

// NewSecurityManager 创建安全管理器
func NewSecurityManager(level int) *SecurityManager {
	sm := &SecurityManager{
		level:           level,
		checksum:        make([]byte, 32),
		lastCheckTime:   time.Now(),
		antiDebugActive: true,
		memProtect:      make([]byte, 4096),
	}

	// 初始化内存保护区域
	for i := range sm.memProtect {
		sm.memProtect[i] = byte(i % 256)
	}

	// 计算初始校验和
	sm.calculateChecksum()

	// 启动后台安全检查
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

	return false
}

// detectTimeBasedDebugging 时间差攻击检测
func detectTimeBasedDebugging() bool {
	// 记录开始时间
	start := time.Now()

	// 执行一些快速操作
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}

	// 检查执行时间
	duration := time.Since(start)

	// 如果执行时间异常长，可能正在被调试
	return duration > time.Millisecond*10
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

// detectLinuxDebugger Linux调试器检测
func detectLinuxDebugger(_ []string) bool {
	// 检查/proc/self/status中的TracerPid
	if checkLinuxTracerPid() {
		return true
	}

	// 检查ptrace
	if checkPtraceUsage() {
		return true
	}

	return false
}

// detectMacDebugger macOS调试器检测
func detectMacDebugger(_ []string) bool {
	// macOS特定检测逻辑
	return checkMacOSDebugging()
}

// detectSystemCallTracing 系统调用跟踪检测
func detectSystemCallTracing() bool {
	// 通过异常处理和系统调用监测调试器
	return checkSyscallInterception()
}

// detectMemoryDebugging 内存调试检测
func detectMemoryDebugging() bool {
	// 检查内存布局异常
	return checkMemoryLayout()
}

// detectDebuggerAPI 调试器API检测
func detectDebuggerAPI() bool {
	if runtime.GOOS == "windows" {
		// Windows调试器API检测
		return checkWindowsDebugAPI()
	}
	return false
}

// === 防篡改功能 ===

// CalculateChecksum 计算校验和
func (sm *SecurityManager) calculateChecksum() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 获取当前程序的内存映像
	data := sm.getCriticalMemoryRegions()
	hash := sha256.Sum256(data)
	copy(sm.checksum, hash[:])
	sm.lastCheckTime = time.Now()
}

// VerifyIntegrity 验证完整性
func (sm *SecurityManager) VerifyIntegrity() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// 计算当前校验和
	data := sm.getCriticalMemoryRegions()
	hash := sha256.Sum256(data)

	// 比较校验和
	for i, b := range hash {
		if i >= len(sm.checksum) || sm.checksum[i] != b {
			return NewSecurityError(ErrUnauthorizedAccess,
				"code integrity check failed - possible tampering detected", nil).
				WithDetail("expected_hash", fmt.Sprintf("%x", sm.checksum)).
				WithDetail("actual_hash", fmt.Sprintf("%x", hash)).
				WithSuggestion("程序可能被篡改，请重新安装原始版本")
		}
	}

	return nil
}

// getCriticalMemoryRegions 获取关键内存区域
func (sm *SecurityManager) getCriticalMemoryRegions() []byte {
	// 这里应该获取程序的关键部分
	// 为了演示，我们使用一些固定数据
	data := make([]byte, 0, 1024)

	// 添加当前函数的一些信息
	data = append(data, []byte("cert-security-check")...)
	data = append(data, sm.memProtect...)

	// 添加一些运行时信息
	runtime_info := fmt.Sprintf("%s-%s-%d",
		runtime.GOOS, runtime.GOARCH, runtime.NumGoroutine())
	data = append(data, []byte(runtime_info)...)

	return data
}

// === 环境检测 ===

// DetectVirtualMachine 检测虚拟机环境
func (sm *SecurityManager) DetectVirtualMachine() bool {
	// 检测VMware
	if sm.detectVMware() {
		return true
	}

	// 检测VirtualBox
	if sm.detectVirtualBox() {
		return true
	}

	// 检测Hyper-V
	if sm.detectHyperV() {
		return true
	}

	// 检测QEMU
	if sm.detectQEMU() {
		return true
	}

	return false
}

// detectVMware 检测VMware
func (sm *SecurityManager) detectVMware() bool {
	// 检查VMware特有的设备和注册表项
	vmwareIndicators := []string{
		"VMware",
		"vmware",
		"VBOX",
		"QEMU",
	}

	hostname, _ := os.Hostname()
	for _, indicator := range vmwareIndicators {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// detectVirtualBox 检测VirtualBox
func (sm *SecurityManager) detectVirtualBox() bool {
	// VirtualBox检测逻辑
	return sm.checkVirtualBoxArtifacts()
}

// detectHyperV 检测Hyper-V
func (sm *SecurityManager) detectHyperV() bool {
	// Hyper-V检测逻辑
	return sm.checkHyperVArtifacts()
}

// detectQEMU 检测QEMU
func (sm *SecurityManager) detectQEMU() bool {
	// QEMU检测逻辑
	return sm.checkQEMUArtifacts()
}

// DetectSandbox 检测沙箱环境
func (sm *SecurityManager) DetectSandbox() bool {
	// 检测各种沙箱特征
	if sm.detectCuckooSandbox() {
		return true
	}

	if sm.detectJoeSandbox() {
		return true
	}

	if sm.detectAnubis() {
		return true
	}

	return false
}

// === 进程保护 ===

// ProtectProcess 进程保护
func (sm *SecurityManager) ProtectProcess() error {
	if sm.level >= SecurityLevelAdvanced {
		// 启用反注入保护
		if err := sm.enableAntiInjection(); err != nil {
			return err
		}

		// 启用内存保护
		if err := sm.enableMemoryProtection(); err != nil {
			return err
		}
	}

	if sm.level >= SecurityLevelCritical {
		// 启用关键数据加密
		if err := sm.enableDataEncryption(); err != nil {
			return err
		}
	}

	return nil
}

// enableAntiInjection 启用反注入保护
func (sm *SecurityManager) enableAntiInjection() error {
	// DLL注入检测
	if sm.detectDLLInjection() {
		return NewSecurityError(ErrUnauthorizedAccess,
			"DLL injection detected", nil)
	}

	// 代码注入检测
	if sm.detectCodeInjection() {
		return NewSecurityError(ErrUnauthorizedAccess,
			"code injection detected", nil)
	}

	return nil
}

// enableMemoryProtection 启用内存保护
func (sm *SecurityManager) enableMemoryProtection() error {
	// 关键内存区域加密
	sm.encryptCriticalMemory()

	// 设置内存访问权限
	return sm.setMemoryPermissions()
}

// enableDataEncryption 启用数据加密
func (sm *SecurityManager) enableDataEncryption() error {
	// 生成加密密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}

	// 加密关键数据
	return sm.encryptSensitiveData(key)
}

// === 后台安全检查 ===

// backgroundSecurityCheck 后台安全检查
func (sm *SecurityManager) backgroundSecurityCheck() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for range ticker.C {
		if !sm.antiDebugActive {
			break
		}

		// 执行各种安全检查
		sm.performSecurityChecks()
	}
}

// performSecurityChecks 执行安全检查
func (sm *SecurityManager) performSecurityChecks() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 检测调试器
	if checkAdvancedDebugger() {
		sm.debuggerCount++
		if sm.debuggerCount > 3 {
			// 多次检测到调试器，执行防御措施
			sm.executeDefenseMeasures()
		}
	} else {
		// 重置计数器
		if sm.debuggerCount > 0 {
			sm.debuggerCount--
		}
	}

	// 验证完整性
	if time.Since(sm.lastCheckTime) > time.Minute*5 {
		if err := sm.VerifyIntegrity(); err != nil {
			sm.executeDefenseMeasures()
		}
	}

	// 检测虚拟机和沙箱
	if sm.level >= SecurityLevelAdvanced {
		if sm.DetectVirtualMachine() || sm.DetectSandbox() {
			// 在虚拟环境中运行，可以选择性地限制功能
			sm.handleVirtualEnvironment()
		}
	}
}

// executeDefenseMeasures 执行防御措施
func (sm *SecurityManager) executeDefenseMeasures() {
	// 可以选择不同的防御策略：
	// 1. 优雅退出
	// 2. 混淆输出
	// 3. 自毁功能
	// 4. 发送警报

	// 这里我们选择优雅退出并记录事件
	sm.logSecurityEvent("Defense measures activated - potential security threat detected")

	// 清理敏感数据
	sm.clearSensitiveData()

	// 可选择退出程序
	if sm.level >= SecurityLevelCritical {
		os.Exit(1)
	}
}

// handleVirtualEnvironment 处理虚拟环境
func (sm *SecurityManager) handleVirtualEnvironment() {
	// 在虚拟环境中的处理逻辑
	// 可以限制某些功能或提供模拟数据
	sm.logSecurityEvent("Virtual environment detected")
}

// logSecurityEvent 记录安全事件
func (sm *SecurityManager) logSecurityEvent(event string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[SECURITY] %s: %s\n", timestamp, event)
}

// clearSensitiveData 清理敏感数据
func (sm *SecurityManager) clearSensitiveData() {
	// 清零敏感内存区域
	for i := range sm.memProtect {
		sm.memProtect[i] = 0
	}
	for i := range sm.checksum {
		sm.checksum[i] = 0
	}
}

// StopSecurityChecks 停止安全检查
func (sm *SecurityManager) StopSecurityChecks() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.antiDebugActive = false
}

// === 特定平台实现 ===

// Windows特定实现
func isDebuggerPresentWindows() bool {
	// Windows API调用检测调试器
	if runtime.GOOS != "windows" {
		return false
	}

	// 使用已有的平台特定实现
	return checkDebugger()
}

func checkPEBDebugFlag() bool {
	// 检查PEB中的调试标志
	if runtime.GOOS != "windows" {
		return false
	}

	// Windows特定：检查PEB结构中的调试标志
	// 这需要直接内存访问，为安全考虑使用间接方法
	// 通过检查异常处理行为来推断是否有调试器
	defer func() {
		if r := recover(); r != nil {
			// 在调试器环境下异常处理可能不同
			// 这里可以进一步分析
		}
	}()

	// 简单的反调试技术：检查时间差异
	start := time.Now()
	for i := 0; i < 10; i++ {
		// 简单循环
	}
	duration := time.Since(start)

	// 如果执行时间异常长，可能在调试环境中
	return duration > time.Microsecond*100
}

func checkDebugPort() bool {
	// 检查调试端口
	if runtime.GOOS != "windows" {
		return false
	}

	// Windows特定：通过NtQueryInformationProcess检查调试端口
	// 这个功能已经在cert_windows.go中实现了
	return checkDebugger()
}

func checkWindowsDebugAPI() bool {
	// 检查Windows调试API
	if runtime.GOOS != "windows" {
		return false
	}

	// 检查是否有调试器API被调用
	// 这包括检查调试器相关的DLL是否被加载
	// 以及检查某些调试器特有的行为

	// 简单实现：检查是否有常见调试器进程
	return detectWindowsDebugger([]string{"windbg", "x32dbg", "x64dbg", "ollydbg"})
}

// Linux特定实现
func checkLinuxTracerPid() bool {
	// 检查/proc/self/status中的TracerPid
	if runtime.GOOS != "linux" {
		return false
	}

	// 使用已有的平台特定实现
	return checkDebugger()
}

func checkPtraceUsage() bool {
	// 检查ptrace使用情况
	if runtime.GOOS != "linux" {
		return false
	}

	// 检查ptrace系统调用的使用情况
	// 通过尝试ptrace自身来检测是否已被调试
	// 如果进程已经被ptrace，再次ptrace会失败

	// 这里使用更安全的方法：检查/proc/self/status
	// 以及检查父进程是否可疑
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	// 检查是否有tracer
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
		}
	}

	return false
}

// macOS特定实现
func checkMacOSDebugging() bool {
	// macOS调试检测
	if runtime.GOOS != "darwin" {
		return false
	}

	// 使用已有的平台特定实现
	return checkDebugger()
}

// 通用实现
func checkSyscallInterception() bool {
	// 系统调用拦截检测
	// 检查系统调用是否被拦截或监控

	// 方法：测量系统调用执行时间
	start := time.Now()

	// 执行一个简单的系统调用
	_ = os.Getpid()

	duration := time.Since(start)

	// 如果系统调用执行时间异常长，可能被拦截
	return duration > time.Microsecond*50
}

func checkMemoryLayout() bool {
	// 内存布局检测
	// 检查内存布局是否异常（可能表示在虚拟或调试环境中）

	// 创建一些变量检查它们的内存地址
	a := 1
	b := 2
	c := 3

	addr_a := uintptr(unsafe.Pointer(&a))
	addr_b := uintptr(unsafe.Pointer(&b))
	addr_c := uintptr(unsafe.Pointer(&c))

	// 检查地址间距是否异常
	// 正常情况下，连续声明的变量地址应该相对接近
	diff1 := addr_b - addr_a
	diff2 := addr_c - addr_b

	if diff1 < 0 {
		diff1 = -diff1
	}
	if diff2 < 0 {
		diff2 = -diff2
	}

	// 如果地址间距异常大，可能在特殊环境中
	return diff1 > 1024 || diff2 > 1024
}

// 虚拟机检测辅助函数
func (sm *SecurityManager) checkVirtualBoxArtifacts() bool {
	// VirtualBox检测特征
	vboxIndicators := []string{
		"VirtualBox",
		"VBOX",
		"vbox",
		"Oracle",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range vboxIndicators {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
			return true
		}
	}

	// 检查环境变量
	envVars := []string{
		"VBOX_MSI_INSTALL_PATH",
		"VBOX_INSTALL_PATH",
	}

	for _, envVar := range envVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	// Linux特定检查
	if runtime.GOOS == "linux" {
		// 检查/proc/cpuinfo
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "vbox") {
				return true
			}
		}

		// 检查/proc/modules
		if data, err := os.ReadFile("/proc/modules"); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "vbox") {
				return true
			}
		}
	}

	return false
}

func (sm *SecurityManager) checkHyperVArtifacts() bool {
	// Hyper-V检测特征
	hypervIndicators := []string{
		"Microsoft Corporation",
		"Hyper-V",
		"Virtual Machine",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range hypervIndicators {
		if strings.Contains(hostname, indicator) {
			return true
		}
	}

	// Windows特定检查
	if runtime.GOOS == "windows" {
		// 检查Hyper-V服务
		// 这里使用简化实现
		return false
	}

	// Linux下检查虚拟化标志
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			cpuinfo := strings.ToLower(string(data))
			if strings.Contains(cpuinfo, "hypervisor") ||
				strings.Contains(cpuinfo, "microsoft") {
				return true
			}
		}
	}

	return false
}

func (sm *SecurityManager) checkQEMUArtifacts() bool {
	// QEMU检测特征
	qemuIndicators := []string{
		"QEMU",
		"qemu",
		"Bochs",
		"bochs",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range qemuIndicators {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
			return true
		}
	}

	// Linux特定检查
	if runtime.GOOS == "linux" {
		// 检查/proc/cpuinfo
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			cpuinfo := strings.ToLower(string(data))
			for _, indicator := range qemuIndicators {
				if strings.Contains(cpuinfo, strings.ToLower(indicator)) {
					return true
				}
			}
		}

		// 检查设备管理器
		if data, err := os.ReadFile("/proc/scsi/scsi"); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "qemu") {
				return true
			}
		}
	}

	return false
}

// 沙箱检测辅助函数
func (sm *SecurityManager) detectCuckooSandbox() bool {
	// Cuckoo Sandbox检测特征
	cuckooIndicators := []string{
		"cuckoo",
		"sandbox",
		"malware",
		"analysis",
		"sample",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range cuckooIndicators {
		if strings.Contains(strings.ToLower(hostname), indicator) {
			return true
		}
	}

	// 检查用户名
	if user := os.Getenv("USER"); user != "" {
		for _, indicator := range cuckooIndicators {
			if strings.Contains(strings.ToLower(user), indicator) {
				return true
			}
		}
	}

	// Windows特定检查
	if runtime.GOOS == "windows" {
		// 检查Cuckoo特有的文件和目录
		cuckooArtifacts := []string{
			"C:\\cuckoo",
			"C:\\Python27\\Lib\\site-packages\\cuckoo",
			"C:\\analysis",
		}

		for _, artifact := range cuckooArtifacts {
			if _, err := os.Stat(artifact); err == nil {
				return true
			}
		}
	}

	return false
}

func (sm *SecurityManager) detectJoeSandbox() bool {
	// Joe Sandbox检测特征
	joeIndicators := []string{
		"joe",
		"joesandbox",
		"analysis",
		"sample",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range joeIndicators {
		if strings.Contains(strings.ToLower(hostname), indicator) {
			return true
		}
	}

	// 检查环境变量
	envVars := []string{
		"JOE_SANDBOX",
		"ANALYSIS",
	}

	for _, envVar := range envVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	// 检查文件系统特征
	if runtime.GOOS == "windows" {
		joeArtifacts := []string{
			"C:\\joesandbox",
			"C:\\analysis",
		}

		for _, artifact := range joeArtifacts {
			if _, err := os.Stat(artifact); err == nil {
				return true
			}
		}
	}

	return false
}

func (sm *SecurityManager) detectAnubis() bool {
	// Anubis沙箱检测特征
	anubisIndicators := []string{
		"anubis",
		"sandbox",
		"malware",
		"sample",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range anubisIndicators {
		if strings.Contains(strings.ToLower(hostname), indicator) {
			return true
		}
	}

	// 检查用户名和环境
	if user := os.Getenv("USER"); user != "" {
		for _, indicator := range anubisIndicators {
			if strings.Contains(strings.ToLower(user), indicator) {
				return true
			}
		}
	}

	// 检查系统特征
	// Anubis通常运行在Linux环境中
	if runtime.GOOS == "linux" {
		// 检查进程列表中是否有可疑进程
		if data, err := os.ReadFile("/proc/version"); err == nil {
			version := strings.ToLower(string(data))
			for _, indicator := range anubisIndicators {
				if strings.Contains(version, indicator) {
					return true
				}
			}
		}
	}

	return false
}

// 注入检测辅助函数
func (sm *SecurityManager) detectDLLInjection() bool {
	// DLL注入检测（主要针对Windows）
	if runtime.GOOS != "windows" {
		return false
	}

	// 检查异常的内存映射
	// 这里使用简化的检测方法：
	// 检查程序的内存使用情况是否异常

	// 记录开始的内存状态
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// 稍作等待
	time.Sleep(time.Millisecond * 10)

	// 再次检查内存
	runtime.ReadMemStats(&m2)

	// 如果内存使用突然大幅增加，可能有注入
	memIncrease := m2.Alloc - m1.Alloc

	// 阈值设定为1MB，超过这个值可能有问题
	return memIncrease > 1024*1024
}

func (sm *SecurityManager) detectCodeInjection() bool {
	// 代码注入检测
	// 检查进程内存中是否有异常的可执行区域

	// 方法：检查堆栈和堆的状态
	// 代码注入通常会改变这些区域的特性

	// 简化实现：检查goroutine数量是否异常
	numGoroutines := runtime.NumGoroutine()

	// 对于证书管理系统，正常情况下不应该有太多 goroutine
	// 如果数量异常多，可能有恶意代码注入
	return numGoroutines > 100
}

// 内存保护辅助函数
func (sm *SecurityManager) encryptCriticalMemory() {
	// 加密关键内存区域
	key := md5.Sum([]byte("cert-security-key"))
	for i := range sm.memProtect {
		sm.memProtect[i] ^= key[i%len(key)]
	}
}

func (sm *SecurityManager) setMemoryPermissions() error {
	// 设置内存页面权限
	if runtime.GOOS == "linux" {
		// Linux mprotect调用
		return sm.mprotectLinux()
	}
	return nil
}

func (sm *SecurityManager) mprotectLinux() error {
	// Linux内存保护
	ptr := uintptr(unsafe.Pointer(&sm.memProtect[0]))
	size := uintptr(len(sm.memProtect))

	// 设置为只读
	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, ptr, size, syscall.PROT_READ)
	if errno != 0 {
		return errno
	}

	return nil
}

func (sm *SecurityManager) encryptSensitiveData(key []byte) error {
	// 加密敏感数据
	if len(key) < 32 {
		return fmt.Errorf("encryption key must be at least 32 bytes")
	}

	// 加密关键内存区域
	for i := range sm.memProtect {
		sm.memProtect[i] ^= key[i%len(key)]
	}

	// 加密校验和
	for i := range sm.checksum {
		sm.checksum[i] ^= key[(i+16)%len(key)]
	}

	return nil
}

// === 集成函数 ===

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
	level := a.getSecurityLevel()
	if level == SecurityLevelDisabled {
		return nil // 安全检查被完全禁用
	}

	// 创建临时安全管理器进行检查
	sm := NewSecurityManager(level)
	defer sm.StopSecurityChecks()

	// 根据安全级别执行不同程度的检查
	switch level {
	case SecurityLevelBasic:
		// 基础级别：只检查简单调试器
		if checkDebugger() {
			return NewSecurityError(ErrDebuggerDetected,
				"debugging environment detected", nil).
				WithSuggestion("请在非调试环境下运行程序")
		}

	case SecurityLevelAdvanced:
		// 高级级别：完整反逆向检测
		if checkAdvancedDebugger() {
			return NewSecurityError(ErrDebuggerDetected,
				"advanced debugging environment detected", nil).
				WithSuggestion("请在非调试环境下运行程序")
		}

		// 检查虚拟机环境
		if sm.DetectVirtualMachine() {
			sm.logSecurityEvent("Virtual machine environment detected")
		}

		// 检查沙箱环境
		if sm.DetectSandbox() {
			return NewSecurityError(ErrUnauthorizedAccess,
				"sandbox environment detected", nil).
				WithSuggestion("程序不允许在沙箱环境中运行")
		}

	case SecurityLevelCritical:
		// 关键级别：最严格的检查
		if checkAdvancedDebugger() {
			return NewSecurityError(ErrDebuggerDetected,
				"critical security violation - debugging detected", nil).
				WithSuggestion("程序在关键模式下不允许调试")
		}

		if sm.DetectVirtualMachine() || sm.DetectSandbox() {
			return NewSecurityError(ErrUnauthorizedAccess,
				"critical security violation - virtual environment detected", nil).
				WithSuggestion("程序在关键模式下只能在物理机运行")
		}

		// 执行进程保护检查
		if err := sm.ProtectProcess(); err != nil {
			return err
		}
	}

	return nil
}

// getSecurityLevel 根据配置获取安全级别
func (a *Authorizer) getSecurityLevel() int {
	// 如果明确设置了安全级别，直接使用
	if level, ok := a.config.Security.GetSecurityLevel(); ok {
		return level
	}

	// 否则根据配置推断
	if !a.config.Security.EnableAntiDebug {
		return SecurityLevelDisabled
	}

	// 根据配置组合推断级别
	if a.config.Security.RequireHardwareBinding {
		return SecurityLevelCritical
	}

	if a.config.Security.EnableTimeValidation {
		return SecurityLevelAdvanced
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
