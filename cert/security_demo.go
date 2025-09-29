package cert

import (
	"fmt"
	"log"
)

// DemoSecurityFeatures 演示安全功能
func DemoSecurityFeatures() {
	fmt.Println("=== 证书授权系统安全功能演示 ===")

	// 1. 创建生产环境配置（默认启用安全功能）
	auth, err := ForProduction().Build()
	if err != nil {
		log.Fatal("创建授权管理器失败:", err)
	}

	fmt.Println("✅ 生产环境配置已创建")
	fmt.Printf("   - 反调试检测: %t\n", auth.config.Security.EnableAntiDebug)
	fmt.Printf("   - 时间验证: %t\n", auth.config.Security.EnableTimeValidation)
	fmt.Printf("   - 硬件绑定: %t\n", auth.config.Security.RequireHardwareBinding)

	// 2. 演示安全检查
	fmt.Println("\n🔍 执行安全检查...")
	if err := auth.PerformSecurityCheck(); err != nil {
		fmt.Printf("❌ 安全检查失败: %v\n", err)
		return
	}
	fmt.Println("✅ 安全检查通过")

	// 3. 创建安全管理器
	fmt.Println("\n🛡️ 初始化安全管理器...")
	sm := auth.InitSecurityManager()
	defer sm.StopSecurityChecks()

	fmt.Printf("   - 安全级别: %d\n", sm.level)
	fmt.Println("   - 后台安全检查已启动")

	// 4. 演示环境检测
	fmt.Println("\n🔍 环境检测结果:")
	if sm.DetectVirtualMachine() {
		fmt.Println("   ⚠️  检测到虚拟机环境")
	} else {
		fmt.Println("   ✅ 物理机环境")
	}

	if sm.DetectSandbox() {
		fmt.Println("   ❌ 检测到沙箱环境")
	} else {
		fmt.Println("   ✅ 非沙箱环境")
	}

	fmt.Println("\n🎯 安全功能已自动集成到证书验证流程")
	fmt.Println("   调用 ValidateCert() 时会自动执行所有安全检查")
}

// ShowSecurityConfig 显示安全配置
func ShowSecurityConfig() {
	fmt.Println("=== 安全配置选项 ===")

	// 开发环境（宽松安全）
	devAuth, _ := ForDevelopment().Build()
	fmt.Println("📝 开发环境配置:")
	fmt.Printf("   - 反调试: %t\n", devAuth.config.Security.EnableAntiDebug)
	fmt.Printf("   - 时间验证: %t\n", devAuth.config.Security.EnableTimeValidation)
	fmt.Printf("   - 硬件绑定: %t\n", devAuth.config.Security.RequireHardwareBinding)

	// 生产环境（严格安全）
	prodAuth, _ := ForProduction().Build()
	fmt.Println("\n🏭 生产环境配置:")
	fmt.Printf("   - 反调试: %t\n", prodAuth.config.Security.EnableAntiDebug)
	fmt.Printf("   - 时间验证: %t\n", prodAuth.config.Security.EnableTimeValidation)
	fmt.Printf("   - 硬件绑定: %t\n", prodAuth.config.Security.RequireHardwareBinding)

	// 自定义安全配置
	customAuth, _ := NewAuthorizer().
		WithSecureDefaults(). // 启用所有安全功能
		Build()

	fmt.Println("\n🔒 自定义安全配置:")
	fmt.Printf("   - 反调试: %t\n", customAuth.config.Security.EnableAntiDebug)
	fmt.Printf("   - 时间验证: %t\n", customAuth.config.Security.EnableTimeValidation)
	fmt.Printf("   - 硬件绑定: %t\n", customAuth.config.Security.RequireHardwareBinding)
}
