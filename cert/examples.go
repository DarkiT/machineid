package cert

import (
	"fmt"
	"time"
)

// 这个文件展示了新的优雅API设计的使用示例

// Example1_BasicUsage 基本使用示例
func Example1_BasicUsage() {
	// 使用Builder模式创建授权管理器
	auth, err := NewAuthorizer().
		WithVersion("1.0.0").
		EnableAntiDebug(true).
		EnableTimeValidation(true).
		WithCacheSize(1000).
		Build()
	if err != nil {
		fmt.Printf("创建授权管理器失败: %v\n", err)
		return
	}

	// 创建客户端证书请求
	request, err := NewClientRequest().
		WithMachineID("machine-12345").
		WithExpiry(time.Now().AddDate(1, 0, 0)). // 1年有效期
		WithCompany("示例科技有限公司", "研发部").
		WithAddress("中国", "广东省", "深圳市", "南山区科技园").
		WithContact("张三", "13800138000", "zhang.san@example.com").
		WithVersion("1.0.0").
		WithValidityDays(365).
		Build()
	if err != nil {
		fmt.Printf("创建证书请求失败: %v\n", err)
		return
	}

	// 签发证书
	cert, err := auth.IssueClientCert(request)
	if err != nil {
		fmt.Printf("签发证书失败: %v\n", err)
		return
	}

	fmt.Printf("证书签发成功，机器ID: %s\n", cert.MachineID)

	// 验证证书
	if err := auth.ValidateCert(cert.CertPEM, cert.MachineID); err != nil {
		fmt.Printf("证书验证失败: %v\n", err)
		return
	}

	fmt.Println("证书验证成功")
}

// Example2_WithCache 使用缓存的示例
func Example2_WithCache() {
	// 创建带缓存的授权管理器
	cachedAuth, err := NewAuthorizer().
		WithCacheTTL(10 * time.Minute).
		WithCacheSize(5000).
		BuildWithCache()
	if err != nil {
		fmt.Printf("创建缓存授权管理器失败: %v\n", err)
		return
	}

	// 模拟证书验证（会被缓存）
	certPEM := []byte("模拟证书数据")
	machineID := "test-machine"

	// 第一次验证（缓存未命中）
	start := time.Now()
	err1 := cachedAuth.ValidateCert(certPEM, machineID)
	duration1 := time.Since(start)

	// 第二次验证（缓存命中）
	start = time.Now()
	err2 := cachedAuth.ValidateCert(certPEM, machineID)
	duration2 := time.Since(start)

	fmt.Printf("第一次验证: %v, 耗时: %v\n", err1, duration1)
	fmt.Printf("第二次验证: %v, 耗时: %v\n", err2, duration2)

	// 获取缓存统计
	stats := cachedAuth.GetCacheStats()
	fmt.Printf("缓存命中率: %.2f%%\n", cachedAuth.GetCacheHitRate()*100)
	fmt.Printf("缓存大小: %d/%d\n", stats.Size, stats.MaxSize)
}

// Example3_BatchOperations 批量操作示例
func Example3_BatchOperations() {
	auth, err := NewAuthorizer().Build()
	if err != nil {
		fmt.Printf("创建授权管理器失败: %v\n", err)
		return
	}

	// 准备多个证书请求
	requests := make([]*ClientCertRequest, 5)
	for i := 0; i < 5; i++ {
		request, err := NewClientRequest().
			WithMachineID(fmt.Sprintf("batch-machine-%d", i+1)).
			WithExpiry(time.Now().AddDate(1, 0, 0)).
			WithCompany("批量测试公司", "技术部").
			WithVersion("1.0.0").
			WithValidityDays(365).
			Build()
		if err != nil {
			fmt.Printf("创建第%d个证书请求失败: %v\n", i+1, err)
			return
		}
		requests[i] = request
	}

	// 执行批量签发
	results := auth.NewBatchIssue().
		AddRequests(requests...).
		WithMaxWorkers(3).
		Execute()

	// 统计结果
	stats := GetIssueStats(results)
	fmt.Printf("批量签发完成:\n")
	fmt.Printf("总数: %d, 成功: %d, 失败: %d\n", stats.Total, stats.Success, stats.Failed)
	fmt.Printf("平均耗时: %v, 最大耗时: %v\n", stats.AvgDuration, stats.MaxDuration)

	// 批量验证
	validations := make([]CertValidation, 0)
	for _, result := range results {
		if result.Error == nil && result.Certificate != nil {
			validations = append(validations, CertValidation{
				CertPEM:   result.Certificate.CertPEM,
				MachineID: result.Certificate.MachineID,
			})
		}
	}

	validationResults := auth.NewBatchValidate().
		AddValidations(validations...).
		Execute()

	validationStats := GetValidationStats(validationResults)
	fmt.Printf("批量验证完成:\n")
	fmt.Printf("总数: %d, 成功: %d, 失败: %d\n",
		validationStats.Total, validationStats.Success, validationStats.Failed)
}

// Example4_ConfigurationFile 配置文件示例
func Example4_ConfigurationFile() {
	// 生成默认配置文件
	configPath := "./cert.config.json"
	if err := GenerateDefaultConfig(configPath); err != nil {
		fmt.Printf("生成配置文件失败: %v\n", err)
		return
	}

	fmt.Printf("默认配置文件已生成: %s\n", configPath)

	// 从配置文件创建授权管理器
	auth, err := FromConfigFile(configPath)
	if err != nil {
		fmt.Printf("从配置文件创建授权管理器失败: %v\n", err)
		return
	}

	built, err := auth.Build()
	if err != nil {
		fmt.Printf("构建授权管理器失败: %v\n", err)
		return
	}

	config := built.GetConfig()
	fmt.Printf("配置加载成功，版本: %s, 企业ID: %d\n", config.Version, config.EnterpriseID)
}

// Example5_PresetConfigurations 预设配置示例
func Example5_PresetConfigurations() {
	// 开发环境配置
	devAuth, err := ForDevelopment().Build()
	if err != nil {
		fmt.Printf("创建开发环境授权管理器失败: %v\n", err)
		return
	}
	devConfig := devAuth.GetConfig()
	fmt.Printf("开发环境配置 - 反调试: %t, 时间验证: %t\n",
		devConfig.Security.EnableAntiDebug, devConfig.Security.EnableTimeValidation)

	// 生产环境配置
	prodAuth, err := ForProduction().Build()
	if err != nil {
		fmt.Printf("创建生产环境授权管理器失败: %v\n", err)
		return
	}
	prodConfig := prodAuth.GetConfig()
	fmt.Printf("生产环境配置 - 反调试: %t, 硬件绑定: %t\n",
		prodConfig.Security.EnableAntiDebug, prodConfig.Security.RequireHardwareBinding)

	// 测试环境配置
	testAuth, err := ForTesting().Build()
	if err != nil {
		fmt.Printf("创建测试环境授权管理器失败: %v\n", err)
		return
	}
	testConfig := testAuth.GetConfig()
	fmt.Printf("测试环境配置 - 时钟偏差: %v, 缓存大小: %d\n",
		testConfig.Security.MaxClockSkew, testConfig.Cache.MaxSize)
}

// Example6_CertificateInspection 证书检查示例
func Example6_CertificateInspection() {
	// 创建证书检查器
	inspector := NewCertificateInspector()

	// 模拟证书数据（实际使用中应该是真实的证书PEM）
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIFoDCCA4igAwIBAgIIGBxYISs1axgwDQYJKoZIhvcNAQELBQAwbTELMAkGA1UE
BhMCQ04xEjAQBgNVBAgTCUd1YW5nZG9uZzESMBAGA1UEBxMJR3Vhbmd6aG91MRgw
FgYDVQQKDA/lrZDor7Tlt6XkvZzlrqQxHDAaBgNVBAMTE1pTdHVkaW8gU29mdHdh
cmUgQ0EwIBcNMjUwMTIwMDgwNzM1WhgPMjEyNDEyMjcwODA3MzVaMG0xCzAJBgNV
BAYTAkNOMRIwEAYDVQQIEwlHdWFuZ2RvbmcxEjAQBgNVBAcTCUd1YW5nemhvdTEY
MBYGA1UECgwP5a2Q6K+05bel5L2c5a6kMRwwGgYDVQQDExNaU3R1ZGlvIFNvZnR3
YXJlIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw17CSfhk2REC
1b5A0nmH04ho+/pyEIFB1u5DVISQWOIRWNquInIjb74XqLZIjRUptnp+C+KnN0vr
-----END CERTIFICATE-----`)

	// 检查证书信息
	info, err := inspector.InspectPEM(certPEM)
	if err != nil {
		fmt.Printf("证书检查失败: %v\n", err)
		return
	}

	fmt.Printf("证书信息:\n")
	fmt.Printf("主题: %s\n", info.Subject)
	fmt.Printf("颁发者: %s\n", info.Issuer)
	fmt.Printf("序列号: %s\n", info.SerialNumber)
	fmt.Printf("有效期: %s - %s\n",
		info.NotBefore.Format("2006-01-02 15:04:05"),
		info.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("是否为CA: %t\n", info.IsCA)
	fmt.Printf("签名算法: %s\n", info.SignatureAlgorithm)
	fmt.Printf("密钥用途: %v\n", info.KeyUsage)
}

// Example7_PerformanceMonitoring 性能监控示例
func Example7_PerformanceMonitoring() {
	monitor := NewPerformanceMonitor()

	// 模拟操作并记录性能
	for i := 0; i < 10; i++ {
		start := time.Now()

		// 模拟证书签发操作
		time.Sleep(time.Millisecond * time.Duration(50+i*5))

		duration := time.Since(start)
		monitor.RecordOperation("issue_certificate", duration)
	}

	// 模拟验证操作
	for i := 0; i < 20; i++ {
		start := time.Now()

		// 模拟证书验证操作
		time.Sleep(time.Millisecond * time.Duration(10+i))

		duration := time.Since(start)
		monitor.RecordOperation("validate_certificate", duration)
	}

	// 获取统计信息
	stats := monitor.GetStats()
	for operation, stat := range stats {
		fmt.Printf("操作: %s\n", operation)
		fmt.Printf("  次数: %d\n", stat.Count)
		fmt.Printf("  平均耗时: %v\n", stat.AvgTime)
		fmt.Printf("  最小耗时: %v\n", stat.MinTime)
		fmt.Printf("  最大耗时: %v\n", stat.MaxTime)
		fmt.Printf("  总耗时: %v\n", stat.TotalTime)
		fmt.Println()
	}
}

// Example8_ErrorHandling 错误处理示例
func Example8_ErrorHandling() {
	// 创建一个会产生错误的请求
	request := &ClientCertRequest{
		Identity: &Identity{
			MachineID: "short", // 太短的机器ID，会导致验证错误
		},
		// 缺少必需的Company字段
	}

	auth, _ := NewAuthorizer().Build()

	// 尝试签发证书
	_, err := auth.IssueClientCert(request)
	if err != nil {
		// 检查错误类型
		if IsValidationError(err) {
			fmt.Println("这是一个验证错误")

			// 获取详细错误信息
			if certErr, ok := err.(*CertError); ok {
				fmt.Printf("错误类型: %s\n", certErr.GetCode())
				fmt.Printf("错误消息: %s\n", certErr.Error())
				fmt.Printf("解决建议:\n")
				for _, suggestion := range certErr.GetSuggestions() {
					fmt.Printf("  - %s\n", suggestion)
				}

				// 获取错误详情
				if details := certErr.GetDetails(); len(details) > 0 {
					fmt.Printf("错误详情:\n")
					for key, value := range details {
						fmt.Printf("  %s: %v\n", key, value)
					}
				}
			}
		}
	}
}

// Example9_SystemInfoCollection 系统信息收集示例
func Example9_SystemInfoCollection() {
	collector := NewSystemInfoCollector()
	sysInfo := collector.GetSystemInfo()

	fmt.Printf("系统信息:\n")
	fmt.Printf("操作系统: %v\n", sysInfo["os"])
	fmt.Printf("架构: %v\n", sysInfo["arch"])
	fmt.Printf("CPU核数: %v\n", sysInfo["num_cpu"])
	fmt.Printf("主机名: %v\n", sysInfo["hostname"])
	fmt.Printf("系统启动时间: %v\n", sysInfo["boot_time"])

	// 验证机器ID格式
	validIDs := []string{
		"machine-12345678",
		"ABC123DEF456",
		"machine-1,machine-2,machine-3",
	}

	invalidIDs := []string{
		"short",
		"machine@123",
		"",
	}

	fmt.Println("\n机器ID验证测试:")
	for _, id := range validIDs {
		fmt.Printf("%s: %t\n", id, IsValidMachineID(id))
	}

	fmt.Println("无效机器ID:")
	for _, id := range invalidIDs {
		fmt.Printf("%s: %t\n", id, IsValidMachineID(id))
	}
}

// Example10_ExtractClientInfo 客户信息提取示例
func Example10_ExtractClientInfo() {
	// 创建授权管理器
	auth, err := NewAuthorizer().Build()
	if err != nil {
		fmt.Printf("创建授权管理器失败: %v\n", err)
		return
	}

	// 生成CA证书
	caInfo := CAInfo{
		CommonName:   "Example CA",
		Organization: "示例公司",
		Country:      "CN",
		Province:     "广东省",
		Locality:     "深圳市",
		ValidDays:    365,
		KeySize:      2048,
	}

	err = auth.GenerateCA(caInfo)
	if err != nil {
		fmt.Printf("生成CA证书失败: %v\n", err)
		return
	}

	// 创建包含完整客户信息的证书请求
	request, err := NewClientRequest().
		WithMachineID("DEMO1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890").
		WithExpiry(time.Now().AddDate(2, 0, 0)).
		WithCompany("示例科技有限公司", "研发中心").
		WithContact("李经理", "13912345678", "li.manager@example.com").
		WithVersion("2.1.0").
		WithValidityDays(730).
		Build()
	if err != nil {
		fmt.Printf("创建证书请求失败: %v\n", err)
		return
	}

	// 签发证书
	cert, err := auth.IssueClientCert(request)
	if err != nil {
		fmt.Printf("签发证书失败: %v\n", err)
		return
	}

	fmt.Println("证书签发成功，现在提取其中的客户信息：")

	// 提取客户信息
	clientInfo, err := auth.ExtractClientInfo(cert.CertPEM)
	if err != nil {
		fmt.Printf("提取客户信息失败: %v\n", err)
		return
	}

	// 显示提取的客户信息
	fmt.Println("\n=== 证书中的客户信息 ===")
	fmt.Printf("机器ID: %s\n", clientInfo.MachineID)
	fmt.Printf("公司名称: %s\n", clientInfo.CompanyName)
	fmt.Printf("部门: %s\n", clientInfo.Department)
	fmt.Printf("联系人: %s\n", clientInfo.ContactPerson)
	fmt.Printf("联系电话: %s\n", clientInfo.ContactPhone)
	fmt.Printf("联系邮箱: %s\n", clientInfo.ContactEmail)
	fmt.Printf("国家: %s\n", clientInfo.Country)
	fmt.Printf("省份: %s\n", clientInfo.Province)
	fmt.Printf("城市: %s\n", clientInfo.City)
	fmt.Printf("程序版本: %s\n", clientInfo.Version)
	fmt.Printf("证书有效期: %d天\n", clientInfo.ValidityPeriodDays)
	fmt.Printf("到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02 15:04:05"))

	fmt.Println("\n这些信息可以用于：")
	fmt.Println("1. 客户管理和联系")
	fmt.Println("2. 许可证审计和跟踪")
	fmt.Println("3. 技术支持和版本控制")
	fmt.Println("4. 合规性检查和报告")
}

// Example11_CertificateWatching 证书监控示例
func Example11_CertificateWatching() {
	fmt.Println("=== 证书监控功能演示 ===\n")

	// 创建授权管理器
	auth, err := NewAuthorizer().Build()
	if err != nil {
		fmt.Printf("创建授权管理器失败: %v\n", err)
		return
	}

	// 生成CA证书
	caInfo := CAInfo{
		CommonName:   "Monitoring Demo CA",
		Organization: "监控演示公司",
		Country:      "CN",
		Province:     "广东省",
		Locality:     "深圳市",
		ValidDays:    365,
		KeySize:      2048,
	}

	err = auth.GenerateCA(caInfo)
	if err != nil {
		fmt.Printf("生成CA证书失败: %v\n", err)
		return
	}

	// 创建一个快到期的证书（30分钟后过期，用于演示）
	expiringTime := time.Now().Add(30 * time.Minute)

	request, err := NewClientRequest().
		WithMachineID("MONITOR1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890").
		WithExpiry(expiringTime).
		WithCompany("监控测试公司", "技术部").
		WithContact("监控员", "13900139000", "monitor@example.com").
		WithVersion("1.0.0").
		WithValidityDays(1). // 1天有效期
		Build()
	if err != nil {
		fmt.Printf("创建证书请求失败: %v\n", err)
		return
	}

	// 签发证书
	cert, err := auth.IssueClientCert(request)
	if err != nil {
		fmt.Printf("签发证书失败: %v\n", err)
		return
	}

	fmt.Println("✅ 已创建一个30分钟后过期的测试证书")

	// 定义监控回调函数
	watchCallback := func(event WatchEvent, clientInfo *ClientInfo, err error) {
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("\n🚨 [%s] 监控事件: %s\n", timestamp, event)

		if clientInfo != nil {
			fmt.Printf("   📋 客户信息:\n")
			fmt.Printf("      公司: %s (%s)\n", clientInfo.CompanyName, clientInfo.Department)
			fmt.Printf("      联系人: %s (%s)\n", clientInfo.ContactPerson, clientInfo.ContactEmail)
			fmt.Printf("      到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02 15:04:05"))

			// 计算剩余时间
			timeLeft := clientInfo.ExpiryDate.Sub(time.Now())
			if timeLeft > 0 {
				fmt.Printf("      剩余时间: %v\n", timeLeft.Round(time.Second))
			} else {
				fmt.Printf("      已过期: %v\n", (-timeLeft).Round(time.Second))
			}
		}

		if err != nil {
			fmt.Printf("   ❌ 错误信息: %v\n", err)
		}

		fmt.Printf("   💡 建议操作: ")
		switch event {
		case WatchEventExpiring:
			fmt.Println("证书即将到期，请准备续期")
		case WatchEventExpired:
			fmt.Println("证书已过期，请立即续期或停止服务")
		case WatchEventInvalid:
			fmt.Println("证书无效，请检查证书文件")
		case WatchEventRevoked:
			fmt.Println("证书已被吊销，请联系颁发机构")
		}
		fmt.Println()
	}

	// 启动证书监控
	fmt.Println("\n🔄 启动证书监控...")
	fmt.Println("   - 检查间隔: 5秒")
	fmt.Println("   - 预警期: 25分钟")
	fmt.Println("   - 监控事件: 即将到期、已到期、无效、吊销")

	// 创建监控器（5秒检查间隔，25分钟预警期）
	watcher, err := auth.Watch(cert.CertPEM, request.Identity.MachineID, watchCallback,
		5*time.Second,  // 检查间隔
		25*time.Minute) // 预警期
	if err != nil {
		fmt.Printf("启动监控失败: %v\n", err)
		return
	}

	fmt.Println("✅ 监控已启动，等待事件...")

	// 运行30秒监控演示
	fmt.Println("\n⏳ 运行30秒监控演示（预期会触发到期预警）...")
	time.Sleep(30 * time.Second)

	// 显示监控统计
	stats := watcher.GetStats()
	fmt.Printf("\n📊 监控统计信息:\n")
	fmt.Printf("   检查次数: %v\n", stats["check_count"])
	fmt.Printf("   最后检查时间: %v\n", stats["last_check"])
	fmt.Printf("   运行状态: %v\n", stats["is_running"])
	fmt.Printf("   检查间隔: %v\n", stats["check_interval"])

	if stats["last_error"] != nil {
		fmt.Printf("   最后错误: %v\n", stats["last_error"])
	}

	// 停止监控
	watcher.Stop()
	fmt.Println("\n✅ 监控已停止")

	// 演示监控管理器
	fmt.Println("\n=== 监控管理器演示 ===")

	manager := NewWatcherManager()

	// 添加多个监控器
	watcher1, _ := auth.Watch(cert.CertPEM, request.Identity.MachineID, watchCallback, time.Minute)
	watcher2, _ := auth.Watch(cert.CertPEM, request.Identity.MachineID, watchCallback, 30*time.Second)

	manager.AddWatcher("cert1", watcher1)
	manager.AddWatcher("cert2", watcher2)

	fmt.Println("✅ 已添加2个监控器到管理器")

	// 获取所有统计信息
	allStats := manager.GetAllStats()
	fmt.Printf("📊 管理器统计:\n")
	for id, stat := range allStats {
		fmt.Printf("   %s: 运行状态=%v, 检查次数=%v\n",
			id, stat["is_running"], stat["check_count"])
	}

	// 停止所有监控
	manager.StopAll()
	fmt.Println("✅ 已停止所有监控器")

	fmt.Println("\n=== 监控演示完成 ===")

	fmt.Println("\n💡 监控功能特点:")
	fmt.Println("   1. 自动定期检查证书状态")
	fmt.Println("   2. 可配置的检查间隔和预警期")
	fmt.Println("   3. 支持多种监控事件（到期、吊销等）")
	fmt.Println("   4. 线程安全的监控管理器")
	fmt.Println("   5. 详细的统计信息和错误重试机制")
}
