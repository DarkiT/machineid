package cert

import (
	"fmt"
	"log"
	"strings"
)

// DemoSecurityLevels 演示不同安全级别
func DemoSecurityLevels() {
	fmt.Println("=== 证书系统安全级别演示 ===\n")

	// 级别 0: 完全禁用（默认）
	fmt.Println("🔓 级别 0: 完全禁用安全检查（默认）")
	defaultAuth, _ := NewAuthorizer().Build()
	level := defaultAuth.getSecurityLevel()
	fmt.Printf("   - 安全级别: %d\n", level)
	fmt.Printf("   - 描述: 无任何安全检查，适合开发和测试\n")
	fmt.Printf("   - 性能影响: 无\n\n")

	// 级别 1: 基础防护
	fmt.Println("🛡️  级别 1: 基础安全防护")
	basicAuth, _ := NewAuthorizer().WithBasicSecurity().Build()
	level = basicAuth.getSecurityLevel()
	fmt.Printf("   - 安全级别: %d\n", level)
	fmt.Printf("   - 描述: 仅基础调试器检测\n")
	fmt.Printf("   - 检测项: 简单调试器（IsDebuggerPresent、TracerPid等）\n")
	fmt.Printf("   - 性能影响: 极小\n\n")

	// 级别 2: 高级防护
	fmt.Println("🛡️  级别 2: 高级安全防护")
	advancedAuth, _ := NewAuthorizer().WithSecureDefaults().Build()
	level = advancedAuth.getSecurityLevel()
	fmt.Printf("   - 安全级别: %d\n", level)
	fmt.Printf("   - 描述: 完整反逆向保护\n")
	fmt.Printf("   - 检测项: 高级调试器、虚拟机、沙箱、时间攻击\n")
	fmt.Printf("   - 性能影响: 小\n\n")

	// 级别 3: 关键防护
	fmt.Println("🔒 级别 3: 关键安全防护")
	criticalAuth, _ := NewAuthorizer().WithCriticalSecurity().Build()
	level = criticalAuth.getSecurityLevel()
	fmt.Printf("   - 安全级别: %d\n", level)
	fmt.Printf("   - 描述: 最高级别保护\n")
	fmt.Printf("   - 检测项: 所有检测 + 进程保护 + 内存加密\n")
	fmt.Printf("   - 性能影响: 中等\n\n")

	fmt.Println("💡 使用建议:")
	fmt.Println("   - 开发阶段: 级别 0 (默认)")
	fmt.Println("   - 测试阶段: 级别 0 或 1")
	fmt.Println("   - 生产环境: 级别 1 (推荐)")
	fmt.Println("   - 高价值软件: 级别 2 或 3")
}

// DemoSecurityConfiguration 演示不同配置方式
func DemoSecurityConfiguration() {
	fmt.Println("\n=== 安全配置方式演示 ===\n")

	// 方式1: 使用预设配置
	fmt.Println("📋 方式1: 使用预设配置")

	fmt.Println("   开发环境:")
	devAuth, _ := ForDevelopment().Build()
	printSecurityConfig(devAuth)

	fmt.Println("   生产环境:")
	prodAuth, _ := ForProduction().Build()
	printSecurityConfig(prodAuth)

	// 方式2: 显式设置安全级别
	fmt.Println("📋 方式2: 显式设置安全级别")

	fmt.Println("   禁用安全检查:")
	disabledAuth, _ := NewAuthorizer().DisableSecurity().Build()
	printSecurityConfig(disabledAuth)

	fmt.Println("   高级安全配置:")
	advancedAuth, _ := NewAuthorizer().WithSecurityLevel(2).Build()
	printSecurityConfig(advancedAuth)

	// 方式3: 便捷配置方法
	fmt.Println("📋 方式3: 便捷配置方法")

	fmt.Println("   宽松安全配置:")
	relaxedAuth, _ := NewAuthorizer().WithRelaxedSecurity().Build()
	printSecurityConfig(relaxedAuth)

	fmt.Println("   关键安全配置:")
	criticalAuth, _ := NewAuthorizer().WithCriticalSecurity().Build()
	printSecurityConfig(criticalAuth)
}

// printSecurityConfig 打印安全配置信息
func printSecurityConfig(auth *Authorizer) {
	level := auth.getSecurityLevel()
	config := auth.GetConfig()

	fmt.Printf("      安全级别: %d", level)
	switch level {
	case 0:
		fmt.Printf(" (禁用)")
	case 1:
		fmt.Printf(" (基础)")
	case 2:
		fmt.Printf(" (高级)")
	case 3:
		fmt.Printf(" (关键)")
	}
	fmt.Println()

	if explicitLevel, ok := config.Security.GetSecurityLevel(); ok {
		fmt.Printf("      显式级别: %d\n", explicitLevel)
	} else {
		fmt.Printf("      推断级别: 基于配置自动推断\n")
	}

	fmt.Printf("      反调试: %t\n", config.Security.EnableAntiDebug)
	fmt.Printf("      时间验证: %t\n", config.Security.EnableTimeValidation)
	fmt.Printf("      硬件绑定: %t\n\n", config.Security.RequireHardwareBinding)
}

// DemoSecurityCheck 演示安全检查过程
func DemoSecurityCheck() {
	fmt.Println("\n=== 安全检查演示 ===\n")

	// 测试不同安全级别的检查行为
	testCases := []struct {
		name string
		auth *Authorizer
	}{
		{"禁用安全检查", func() *Authorizer { a, _ := NewAuthorizer().DisableSecurity().Build(); return a }()},
		{"基础安全检查", func() *Authorizer { a, _ := NewAuthorizer().WithBasicSecurity().Build(); return a }()},
		{"高级安全检查", func() *Authorizer { a, _ := NewAuthorizer().WithSecureDefaults().Build(); return a }()},
		{"关键安全检查", func() *Authorizer { a, _ := NewAuthorizer().WithCriticalSecurity().Build(); return a }()},
	}

	for _, tc := range testCases {
		fmt.Printf("🔍 %s:\n", tc.name)

		err := tc.auth.PerformSecurityCheck()
		if err != nil {
			if IsSecurityError(err) {
				fmt.Printf("   ❌ 安全检查失败: %v\n", err)
			} else {
				fmt.Printf("   ⚠️  其他错误: %v\n", err)
			}
		} else {
			fmt.Printf("   ✅ 安全检查通过\n")
		}
		fmt.Println()
	}
}

// ShowUsageExamples 显示使用示例
func ShowUsageExamples() {
	fmt.Println("\n=== 使用示例 ===\n")

	fmt.Println("💻 开发和调试阶段:")
	fmt.Println(`
// 完全禁用安全检查，便于开发调试
auth := cert.NewAuthorizer().DisableSecurity().Build()
// 或使用预设
auth := cert.ForDevelopment().Build()`)

	fmt.Println("\n🏭 生产环境:")
	fmt.Println(`
// 基础安全检查，平衡安全性和兼容性
auth := cert.ForProduction().Build()
// 或显式设置
auth := cert.NewAuthorizer().WithSecurityLevel(1).Build()`)

	fmt.Println("\n💎 高价值软件:")
	fmt.Println(`
// 高级安全保护
auth := cert.NewAuthorizer().WithSecureDefaults().Build()
// 或关键级别保护
auth := cert.NewAuthorizer().WithCriticalSecurity().Build()`)

	fmt.Println("\n🔧 自定义配置:")
	fmt.Println(`
// 灵活配置
auth := cert.NewAuthorizer().
    WithSecurityLevel(2).                    // 设置安全级别
    EnableTimeValidation(true).              // 启用时间验证
    WithMaxClockSkew(1 * time.Minute).       // 设置时钟偏差
    Build()`)

	fmt.Println("\n📊 检查安全配置:")
	fmt.Println(`
level := auth.getSecurityLevel()             // 获取当前安全级别
config := auth.GetConfig()                   // 获取完整配置
err := auth.PerformSecurityCheck()           // 手动执行安全检查`)
}

// RunSecurityDemo 运行完整的安全功能演示
func RunSecurityDemo() {
	log.Println("开始安全功能演示...")

	DemoSecurityLevels()
	DemoSecurityConfiguration()
	DemoSecurityCheck()
	ShowUsageExamples()

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("🎯 总结:")
	fmt.Println("   - 默认禁用安全检查，开发友好")
	fmt.Println("   - 通过安全级别灵活控制保护程度")
	fmt.Println("   - 支持多种配置方式满足不同需求")
	fmt.Println("   - 性能影响可控，适合生产使用")
}
