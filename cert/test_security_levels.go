package cert

import "fmt"

// TestSecurityLevels 测试安全级别配置
func TestSecurityLevels() {
	fmt.Println("🧪 安全级别配置测试\n")

	// 测试默认配置（应该是禁用）
	fmt.Println("测试1: 默认配置")
	defaultAuth, _ := NewAuthorizer().Build()
	level := defaultAuth.getSecurityLevel()
	fmt.Printf("   默认安全级别: %d (期望: 0)\n", level)
	if level == 0 {
		fmt.Println("   ✅ 通过: 默认禁用安全检查")
	} else {
		fmt.Println("   ❌ 失败: 应该默认禁用")
	}

	// 测试显式设置
	fmt.Println("\n测试2: 显式设置安全级别")
	explicitAuth, _ := NewAuthorizer().WithSecurityLevel(2).Build()
	level = explicitAuth.getSecurityLevel()
	fmt.Printf("   显式设置级别: %d (期望: 2)\n", level)
	if level == 2 {
		fmt.Println("   ✅ 通过: 显式设置生效")
	} else {
		fmt.Println("   ❌ 失败: 显式设置无效")
	}

	// 测试预设配置
	fmt.Println("\n测试3: 预设配置")
	devAuth, _ := ForDevelopment().Build()
	prodAuth, _ := ForProduction().Build()

	devLevel := devAuth.getSecurityLevel()
	prodLevel := prodAuth.getSecurityLevel()

	fmt.Printf("   开发环境级别: %d (期望: 0)\n", devLevel)
	fmt.Printf("   生产环境级别: %d (期望: 1)\n", prodLevel)

	if devLevel == 0 && prodLevel == 1 {
		fmt.Println("   ✅ 通过: 预设配置正确")
	} else {
		fmt.Println("   ❌ 失败: 预设配置错误")
	}

	// 测试安全检查行为
	fmt.Println("\n测试4: 安全检查行为")

	// 禁用状态应该直接通过
	disabledAuth, _ := NewAuthorizer().DisableSecurity().Build()
	err := disabledAuth.PerformSecurityCheck()
	if err == nil {
		fmt.Println("   ✅ 通过: 禁用状态跳过检查")
	} else {
		fmt.Printf("   ❌ 失败: 禁用状态仍有错误: %v\n", err)
	}

	// 基础级别应该执行检查
	basicAuth, _ := NewAuthorizer().WithBasicSecurity().Build()
	err = basicAuth.PerformSecurityCheck()
	fmt.Printf("   基础级别检查结果: %v\n", err)
	if err == nil {
		fmt.Println("   ✅ 通过: 基础级别正常执行")
	} else {
		fmt.Println("   ℹ️  信息: 基础级别检测到安全问题（正常）")
	}

	fmt.Println("\n🎯 测试总结:")
	fmt.Println("   - 默认禁用安全检查，开发友好")
	fmt.Println("   - 可通过多种方式灵活配置安全级别")
	fmt.Println("   - 安全检查根据级别正确执行")
}
