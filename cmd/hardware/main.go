package main

import (
	"encoding/json"
	"fmt"
	"log"

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

	// 测试智能保护ID
	fmt.Println("\n2. 智能保护ID:")
	protectedID, err := machineid.ProtectedID("TestApp")
	if err != nil {
		log.Printf("获取保护ID失败: %v", err)
	} else {
		fmt.Printf("保护ID: %s\n", protectedID)
	}

	// 测试完整系统信息
	fmt.Println("\n3. 完整系统信息:")
	info, err := machineid.GetInfo("TestApp")
	if err != nil {
		log.Printf("获取系统信息失败: %v", err)
	} else {
		infoJson, _ := json.MarshalIndent(info, "", "  ")
		fmt.Printf("%s\n", infoJson)
	}

	// 测试MAC地址
	fmt.Println("\n4. MAC地址:")
	mac, err := machineid.GetMACAddress()
	if err != nil {
		log.Printf("获取MAC地址失败: %v", err)
	} else {
		fmt.Printf("MAC地址: %s\n", mac)
	}

	// 测试容器检测
	fmt.Println("\n5. 容器环境检测:")
	isContainer := machineid.IsContainer()
	fmt.Printf("是否容器: %t\n", isContainer)

	fmt.Println("\n=== 测试完成 ===")
}
