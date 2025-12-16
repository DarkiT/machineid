package main

import (
	"fmt"
	"time"

	"github.com/darkit/machineid"
	"github.com/darkit/machineid/cert"
)

func main() {
	fmt.Println("=== 证书授权管理系统演示 ===")

	// 使用新的优雅API创建授权管理器
	auth, err := cert.NewAuthorizer().
		WithRuntimeVersion("1.0.0").
		EnableAntiDebug(false). // 开发环境关闭反调试
		EnableTimeValidation(true).
		WithCacheSize(1000).
		Build()
	if err != nil {
		fmt.Printf("创建授权管理器失败: %v\n", err)
		return
	}

	// 生成CA证书
	caInfo := cert.CAInfo{
		CommonName:   "ZStudio Software",
		Organization: "子说工作室",
		Country:      "CN",
		Province:     "Guangdong",
		Locality:     "Guangzhou",
		ValidDays:    36500, // 100年有效期
	}

	err = auth.GenerateCA(caInfo)
	if err != nil {
		fmt.Printf("生成CA证书失败: %v\n", err)
		return
	}

	err = auth.SaveCA(".")
	if err != nil {
		fmt.Printf("保存CA证书失败: %v\n", err)
		return
	}
	fmt.Println("✓ CA证书生成并保存成功")

	// 获取受保护的机器ID及绑定信息
	bindingResult, err := machineid.ProtectedIDResult("zstudio.cert.auth")
	if err != nil {
		fmt.Printf("获取机器ID失败: %v\n", err)
		return
	}
	machineID := bindingResult.Hash
	fmt.Printf("机器ID: %s\n", machineID)
	fmt.Printf("绑定模式: %s (提供者: %s)\n", bindingResult.Mode, bindingResult.Provider)

	// 使用新的客户端证书构建器
	request, err := cert.NewClientRequest().
		WithMachineID(machineID).
		WithBindingResult(bindingResult).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithCompany("XX广州分公司", "技术部").
		WithContact("张三", "13800138000", "zhang.san@example.com").
		WithMinClientVersion("1.0.0").
		WithValidityDays(365).
		Build()
	if err != nil {
		fmt.Printf("创建证书请求失败: %v\n", err)
		return
	}

	// 签发证书
	certificate, err := auth.IssueClientCert(request)
	if err != nil {
		fmt.Printf("签发证书失败: %v\n", err)
		return
	}
	fmt.Println("✓ 客户端证书签发成功")

	// 保存证书
	err = auth.SaveClientCert(certificate, ".")
	if err != nil {
		fmt.Printf("保存证书失败: %v\n", err)
		return
	}
	fmt.Println("✓ 证书保存成功")

	// 验证证书
	err = auth.ValidateCert(certificate.CertPEM, certificate.MachineID)
	if err != nil {
		fmt.Printf("证书验证失败: %v\n", err)
		return
	}
	fmt.Println("✓ 证书验证成功")

	// 证书信息检查
	inspector := cert.NewCertificateInspector()
	certInfo, err := inspector.InspectPEM(certificate.CertPEM)
	if err != nil {
		fmt.Printf("证书检查失败: %v\n", err)
		return
	}

	fmt.Printf("\n=== 证书信息 ===\n")
	fmt.Printf("主题: %s\n", certInfo.Subject)
	fmt.Printf("序列号: %s\n", certInfo.SerialNumber)
	fmt.Printf("有效期: %s 至 %s\n",
		certInfo.NotBefore.Format("2006-01-02 15:04:05"),
		certInfo.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("密钥用途: %v\n", certInfo.KeyUsage)

	// 提取客户信息
	fmt.Println("\n=== 提取客户信息 ===")
	clientInfo, err := auth.ExtractClientInfo(certificate.CertPEM)
	if err != nil {
		fmt.Printf("提取客户信息失败: %v\n", err)
	} else {
		fmt.Printf("机器ID: %s\n", clientInfo.MachineID)
		fmt.Printf("公司名称: %s\n", clientInfo.CompanyName)
		fmt.Printf("部门: %s\n", clientInfo.Department)
		fmt.Printf("联系人: %s\n", clientInfo.ContactPerson)
		fmt.Printf("联系电话: %s\n", clientInfo.ContactPhone)
		fmt.Printf("联系邮箱: %s\n", clientInfo.ContactEmail)
		fmt.Printf("国家: %s\n", clientInfo.Country)
		fmt.Printf("省份: %s\n", clientInfo.Province)
		fmt.Printf("城市: %s\n", clientInfo.City)
		fmt.Printf("详细地址: %s\n", clientInfo.Address)
		fmt.Printf("最低客户端版本: %s\n", clientInfo.MinClientVersion)
		fmt.Printf("绑定模式: %s\n", clientInfo.BindingMode)
		fmt.Printf("绑定提供者: %s\n", clientInfo.BindingProvider)
		fmt.Printf("证书有效期: %d天\n", clientInfo.ValidityPeriodDays)
		fmt.Printf("到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02 15:04:05"))
	}

	// 授权机制验证测试
	fmt.Println("\n=== 授权机制验证测试 ===")

	fmt.Println("测试1: 使用正确的机器ID验证证书")
	err = auth.ValidateCert(certificate.CertPEM, machineID)
	if err != nil {
		fmt.Printf("❌ 验证失败 (应该成功): %v\n", err)
	} else {
		fmt.Println("✅ 验证成功 - 证书与当前机器ID匹配")
	}

	fmt.Println("\n测试2: 使用错误的机器ID验证证书")
	fakeMachineID := "FAKE1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB"
	err = auth.ValidateCert(certificate.CertPEM, fakeMachineID)
	if err != nil {
		fmt.Printf("✅ 验证失败 (预期结果): %v\n", err)
	} else {
		fmt.Println("❌ 验证成功 (不应该成功) - 存在安全问题!")
	}

	fmt.Println("\n测试3: 使用空机器ID验证证书")
	err = auth.ValidateCert(certificate.CertPEM, "")
	if err != nil {
		fmt.Printf("✅ 验证失败 (预期结果): %v\n", err)
	} else {
		fmt.Println("❌ 验证成功 (不应该成功) - 存在安全问题!")
	}

	fmt.Println("\n测试4: 创建另一台机器的证书并交叉验证")
	anotherMachineID := "ANOTHER1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"

	anotherRequest, err := cert.NewClientRequest().
		WithMachineID(anotherMachineID).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithCompany("另一台机器公司", "测试部门").
		WithContact("另一个用户", "13900139000", "another@example.com").
		WithMinClientVersion("1.0.0").
		WithValidityDays(365).
		Build()
	if err != nil {
		fmt.Printf("创建另一台机器证书请求失败: %v\n", err)
		return
	}

	anotherCert, err := auth.IssueClientCert(anotherRequest)
	if err != nil {
		fmt.Printf("为另一台机器签发证书失败: %v\n", err)
		return
	}

	fmt.Println("尝试用另一台机器的证书在当前机器验证:")
	err = auth.ValidateCert(anotherCert.CertPEM, machineID)
	if err != nil {
		fmt.Printf("✅ 验证失败 (预期结果): %v\n", err)
	} else {
		fmt.Println("❌ 验证成功 (不应该成功) - 存在安全问题!")
	}

	fmt.Println("\n=== 授权机制验证完成 ===")

	// 授权监控演示
	fmt.Println("\n=== 授权监控演示 ===")

	// 设置监控回调函数
	watchCallback := func(event cert.WatchEvent, clientInfo *cert.ClientInfo, err error) {
		fmt.Printf("📋 监控事件: %s\n", event)
		if clientInfo != nil {
			fmt.Printf("   客户: %s (%s)\n", clientInfo.CompanyName, clientInfo.ContactPerson)
			fmt.Printf("   到期时间: %s\n", clientInfo.ExpiryDate.Format("2006-01-02 15:04:05"))
		}
		if err != nil {
			fmt.Printf("   错误: %v\n", err)
		}
		fmt.Println()
	}

	// 启动证书监控（使用较短的间隔进行演示）
	watcher, err := auth.Watch(certificate.CertPEM, machineID, watchCallback, 10*time.Second, 24*time.Hour)
	if err != nil {
		fmt.Printf("启动监控失败: %v\n", err)
	} else {
		fmt.Printf("✅ 证书监控已启动\n")
		fmt.Printf("   检查间隔: 10秒（演示用）\n")
		fmt.Printf("   预警期: 24小时\n")
		fmt.Println("   监控器将定期检查证书有效性和到期状态...")

		// 运行15秒演示监控功能
		fmt.Println("\n🔄 运行15秒监控演示...")
		time.Sleep(15 * time.Second)

		// 获取监控统计
		stats := watcher.Stats()
		fmt.Printf("\n📊 监控统计:\n")
		fmt.Printf("   检查次数: %v\n", stats["check_count"])
		fmt.Printf("   最后检查: %v\n", stats["last_check"])
		fmt.Printf("   运行状态: %v\n", stats["is_running"])

		// 停止监控
		watcher.Stop()
		fmt.Println("✅ 监控已停止")
	}

	fmt.Println("\n=== 演示完成 ===")
}
