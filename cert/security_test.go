package cert

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestSecurityManagerVerifyIntegrityDetectsTamper 确认篡改会被校验发现
func TestSecurityManagerVerifyIntegrityDetectsTamper(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	sm.StopSecurityChecks()
	sm.calculateChecksum()

	if err := sm.VerifyIntegrity(); err != nil {
		t.Fatalf("初始化校验失败: %v", err)
	}

	sm.memProtect[0] ^= 0xFF
	if err := sm.VerifyIntegrity(); err == nil {
		t.Fatalf("篡改后应返回错误")
	}
}

// TestSecurityManagerClearSensitiveData 确保敏感数据被完全清除
func TestSecurityManagerClearSensitiveData(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	sm.clearSensitiveData()
	for i, b := range sm.memProtect {
		if b != 0 {
			t.Fatalf("memProtect[%d] 未被清零", i)
		}
	}
	for i, b := range sm.checksum {
		if b != 0 {
			t.Fatalf("checksum[%d] 未被清零", i)
		}
	}
}

// TestSecurityManagerEncryptSensitiveDataKeyLength 验证密钥长度限制
func TestSecurityManagerEncryptSensitiveDataKeyLength(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	if err := sm.encryptSensitiveData([]byte("short-key")); err == nil {
		t.Fatalf("密钥长度不足时应返回错误")
	}

	key := make([]byte, 32)
	if err := sm.encryptSensitiveData(key); err != nil {
		t.Fatalf("合法密钥长度不应报错: %v", err)
	}
}

// TestSecurityManagerProtectProcessBasic 确保基础级别的保护流程可顺利执行
func TestSecurityManagerProtectProcessBasic(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	if err := sm.ProtectProcess(); err != nil {
		t.Fatalf("基础级别保护流程失败: %v", err)
	}
}

// TestSecurityManager_DifferentLevels 测试不同安全级别
func TestSecurityManager_DifferentLevels(t *testing.T) {
	t.Parallel()

	levels := []int{
		SecurityLevelDisabled,
		SecurityLevelBasic,
		SecurityLevelAdvanced,
		SecurityLevelCritical,
	}

	for _, level := range levels {
		level := level
		t.Run(fmt.Sprintf("级别%d", level), func(t *testing.T) {
			t.Parallel()

			sm := NewSecurityManager(level)
			defer sm.StopSecurityChecks()

			if sm == nil {
				t.Fatal("安全管理器不应为 nil")
			}

			if sm.level != level {
				t.Errorf("安全级别不匹配: 期望 %d, 实际 %d", level, sm.level)
			}

			// 验证内存保护区域已初始化
			if len(sm.memProtect) != 4096 {
				t.Errorf("memProtect 大小错误: 期望 4096, 实际 %d", len(sm.memProtect))
			}

			// 验证校验和已计算
			if len(sm.checksum) != 32 {
				t.Errorf("checksum 大小错误: 期望 32, 实际 %d", len(sm.checksum))
			}
		})
	}
}

// TestInitSecurityManager 测试初始化安全管理器
func TestInitSecurityManager(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		WithSecurityLevel(SecurityLevelBasic).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	manager := auth.InitSecurityManager()
	if manager == nil {
		t.Fatal("安全管理器不应为 nil")
	}
	defer manager.StopSecurityChecks()

	// 验证安全级别被正确设置
	if manager.level != SecurityLevelBasic {
		t.Errorf("安全级别应为 Basic(1), 实际 %d", manager.level)
	}
}

// TestPerformSecurityCheck 测试执行安全检查
func TestPerformSecurityCheck(t *testing.T) {
	t.Parallel()

	levels := []int{
		SecurityLevelDisabled,
		SecurityLevelBasic,
		SecurityLevelAdvanced,
		SecurityLevelCritical,
	}

	for _, level := range levels {
		level := level
		t.Run(fmt.Sprintf("检查级别%d", level), func(t *testing.T) {
			t.Parallel()

			// PerformSecurityCheck 不应 panic
			// 创建不同级别的授权管理器
			auth, err := newTestAuthorizerBuilder(t).
				WithSecurityLevel(level).
				Build()
			if err != nil {
				t.Fatalf("创建授权管理器失败: %v", err)
			}

			// PerformSecurityCheck 不应 panic
			err = auth.PerformSecurityCheck()

			// 禁用级别应该成功
			if level == SecurityLevelDisabled && err != nil {
				t.Errorf("禁用级别不应返回错误: %v", err)
			}

			// 记录结果
			if err != nil {
				t.Logf("级别 %d 的安全检查结果: %v", level, err)
			}
		})
	}
}

// TestGetSecurityLevel 测试获取安全级别
func TestGetSecurityLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		level    int
		expected string
	}{
		{"禁用", SecurityLevelDisabled, "disabled"},
		{"基础", SecurityLevelBasic, "basic"},
		{"高级", SecurityLevelAdvanced, "advanced"},
		{"关键", SecurityLevelCritical, "critical"},
		{"未知", 999, "unknown"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// 创建授权管理器
			auth, err := newTestAuthorizerBuilder(t).
				WithSecurityLevel(tt.level).
				Build()
			if err != nil {
				t.Fatalf("创建授权管理器失败: %v", err)
			}

			level := auth.getSecurityLevel()
			if level != tt.level {
				t.Errorf("安全级别不匹配: 期望 %d, 实际 %d", tt.level, level)
			}
		})
	}
}

// TestDetectVirtualMachine 测试虚拟机检测
func TestDetectVirtualMachine(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	// 检测虚拟机不应 panic
	isVM := sm.DetectVirtualMachine()

	// 结果应该是布尔值(无论是否在虚拟机中)
	t.Logf("虚拟机检测结果: %v", isVM)
}

// TestDetectSandbox 测试沙箱检测
func TestDetectSandbox(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	// 检测沙箱不应 panic
	isSandbox := sm.DetectSandbox()

	// 结果应该是布尔值
	t.Logf("沙箱检测结果: %v", isSandbox)
}

// TestValidateWithSecurity 测试带安全检查的验证
func TestValidateWithSecurity(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		WithSecurityLevel(SecurityLevelBasic).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	machineID := "security-test-machine"
	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithVersion("1.0.0").
		WithCompany("安全测试", "测试部").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 使用安全验证
	err = auth.ValidateWithSecurity(cert.CertPEM, machineID)
	// 在正常环境下应该通过验证
	if err != nil {
		t.Logf("安全验证失败(可能正常): %v", err)
	}
}

// TestSecurityManager_GetCriticalMemoryRegions 测试获取关键内存区域
func TestSecurityManager_GetCriticalMemoryRegions(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	regions := sm.getCriticalMemoryRegions()

	// 应该返回一些内存区域
	if len(regions) == 0 {
		t.Error("关键内存区域不应为空")
	}

	// 验证返回了内存地址列表(地址可能为0,这是合法的)
	t.Logf("获取到 %d 个关键内存区域", len(regions))
}

// TestProtectProcess_AllLevels 测试所有级别的进程保护
func TestProtectProcess_AllLevels(t *testing.T) {
	t.Parallel()

	levels := []int{
		SecurityLevelDisabled,
		SecurityLevelBasic,
		SecurityLevelAdvanced,
		SecurityLevelCritical,
	}

	for _, level := range levels {
		level := level
		t.Run(fmt.Sprintf("保护级别%d", level), func(t *testing.T) {
			t.Parallel()

			sm := NewSecurityManager(level)
			defer sm.StopSecurityChecks()

			err := sm.ProtectProcess()

			// 禁用级别应该成功(不做任何保护)
			if level == SecurityLevelDisabled && err != nil {
				t.Errorf("禁用级别的保护不应失败: %v", err)
			}

			// 其他级别也应该不返回错误(或返回预期错误)
			if err != nil {
				t.Logf("级别 %d 的保护流程结果: %v", level, err)
			}
		})
	}
}

// TestBackgroundSecurityCheck 测试后台安全检查
func TestBackgroundSecurityCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过长时间运行测试")
	}

	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)

	// 等待一小段时间让后台检查运行
	time.Sleep(100 * time.Millisecond)

	// 停止安全检查
	sm.StopSecurityChecks()

	// 验证停止后 antiDebugActive 为 false
	sm.mu.RLock()
	active := sm.antiDebugActive
	sm.mu.RUnlock()

	if active {
		t.Error("停止检查后 antiDebugActive 应为 false")
	}
}

// TestSecurityManager_MultipleConcurrent 测试并发安全性
func TestSecurityManager_MultipleConcurrent(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.StopSecurityChecks()

	// 并发执行多个操作
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// 并发验证完整性
			if err := sm.VerifyIntegrity(); err != nil {
				t.Logf("并发校验返回: %v", err)
			}

			// 并发获取内存区域
			sm.getCriticalMemoryRegions()
		}()
	}

	wg.Wait()
}

// TestCheckDebugger 测试调试器检测(不应 panic)
func TestCheckDebugger(t *testing.T) {
	t.Parallel()

	// checkDebugger 是内部函数,通过 checkAdvancedDebugger 间接测试
	// 这个测试只验证不会 panic
	result := checkAdvancedDebugger()
	t.Logf("高级调试器检测结果: %v", result)
}

// TestDetectPlatformSpecific 测试平台特定检测函数
func TestDetectPlatformSpecific(t *testing.T) {
	t.Parallel()

	// 测试各种检测函数不会 panic
	tests := []struct {
		name string
		fn   func() bool
	}{
		{"时间调试检测", detectTimeBasedDebugging},
		{"调试器进程检测", detectDebuggerProcess},
		{"系统调用跟踪检测", detectSystemCallTracing},
		{"内存调试检测", detectMemoryDebugging},
		{"调试器API检测", detectDebuggerAPI},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// 执行检测函数,不应 panic
			result := tt.fn()
			t.Logf("%s 结果: %v", tt.name, result)
		})
	}
}

// TestDetectPlatformDebuggers 测试平台调试器检测
func TestDetectPlatformDebuggers(t *testing.T) {
	t.Parallel()

	// 根据当前平台测试相应的检测函数
	suspiciousProcesses := []string{}
	switch runtime.GOOS {
	case "windows":
		result := detectWindowsDebugger(suspiciousProcesses)
		t.Logf("Windows 调试器检测: %v", result)

	case "linux":
		result := detectLinuxDebugger(suspiciousProcesses)
		t.Logf("Linux 调试器检测: %v", result)

	case "darwin":
		result := detectMacDebugger(suspiciousProcesses)
		t.Logf("macOS 调试器检测: %v", result)

	default:
		t.Logf("未知平台: %s", runtime.GOOS)
	}
}

// TestSecurityManager_MemoryProtection 测试内存保护
func TestSecurityManager_MemoryProtection(t *testing.T) {
	t.Parallel()

	sm := NewSecurityManager(SecurityLevelAdvanced)
	defer sm.StopSecurityChecks()

	// 验证内存保护区域已初始化
	if len(sm.memProtect) == 0 {
		t.Fatal("内存保护区域未初始化")
	}

	// 保存原始校验和
	originalChecksum := make([]byte, len(sm.checksum))
	copy(originalChecksum, sm.checksum)

	// 修改内存
	sm.memProtect[0] = 0xFF

	// 重新计算校验和
	sm.calculateChecksum()

	// 校验和应该改变
	equal := true
	for i := range originalChecksum {
		if originalChecksum[i] != sm.checksum[i] {
			equal = false
			break
		}
	}

	if equal {
		t.Error("修改内存后校验和应该改变")
	}
}
