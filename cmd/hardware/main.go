package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/darkit/machineid"
)

func main() {
	fmt.Println("=== machineid 包功能测试 ===")

	// 测试基础机器码
	fmt.Println("\n1. 基础机器码:")
	id, err := machineid.ID()
	if err != nil {
		log.Printf("获取机器码失败: %v", err)
	} else {
		fmt.Printf("机器码: %s\n", id)
	}

	fmt.Println("\n1.1 机器码来源诊断:")
	inspection, err := machineid.InspectID()
	if err != nil {
		log.Printf("获取机器码来源失败: %v", err)
	} else {
		inspectJSON, _ := json.MarshalIndent(inspection, "", "  ")
		fmt.Printf("%s\n", inspectJSON)
		if len(inspection.FallbackChain) > 0 {
			chain := make([]string, 0, len(inspection.FallbackChain))
			for _, stage := range inspection.FallbackChain {
				chain = append(chain, string(stage))
			}
			fmt.Printf("回退链路: %s\n", strings.Join(chain, " -> "))
		}
	}

	// 测试智能保护ID
	fmt.Println("\n2. 智能保护ID:")
	protectedResult, err := machineid.ProtectedIDResult("TestApp")
	if err != nil {
		log.Printf("获取保护ID失败: %v", err)
	} else {
		fmt.Printf("保护ID: %s\n", protectedResult.Hash)
		fmt.Printf("绑定模式: %s (提供者: %s)\n", protectedResult.Mode, protectedResult.Provider)
	}

	fmt.Println("\n3. 唯一性模式对比:")
	hostUnique, err := machineid.UniqueIDResult("TestApp", &machineid.UniqueIDOptions{
		EnableContainer: true,
		Mode:            machineid.UniqueIDModeHost,
	})
	if err != nil {
		log.Printf("获取宿主唯一机器码失败: %v", err)
	} else {
		fmt.Printf("宿主唯一: %s\n", hostUnique.Hash)
		fmt.Printf("  模式: %s | 提供者: %s | 容器策略: %s\n", hostUnique.Mode, hostUnique.Provider, hostUnique.ContainerMode)
	}

	containerUnique, err := machineid.UniqueIDResult("TestApp", &machineid.UniqueIDOptions{
		EnableContainer: true,
		Mode:            machineid.UniqueIDModeContainer,
	})
	if err != nil {
		log.Printf("获取容器唯一机器码失败: %v", err)
	} else {
		fmt.Printf("容器唯一: %s\n", containerUnique.Hash)
		fmt.Printf("  模式: %s | 提供者: %s | 容器策略: %s\n", containerUnique.Mode, containerUnique.Provider, containerUnique.ContainerMode)
	}

	// 测试完整系统信息
	fmt.Println("\n4. 完整系统信息:")
	info, err := machineid.GetInfo("TestApp")
	if err != nil {
		log.Printf("获取系统信息失败: %v", err)
	} else {
		infoJson, _ := json.MarshalIndent(info, "", "  ")
		fmt.Printf("%s\n", infoJson)
	}

	// 测试MAC地址
	fmt.Println("\n5. MAC地址:")
	mac, err := machineid.GetMACAddress()
	if err != nil {
		log.Printf("获取MAC地址失败: %v", err)
	} else {
		fmt.Printf("MAC地址: %s\n", mac)
	}

	// 测试容器检测
	fmt.Println("\n6. 容器环境检测:")
	isContainer := machineid.IsContainer()
	fmt.Printf("是否容器: %t\n", isContainer)

	fmt.Println("\n=== 测试完成 ===")
}
