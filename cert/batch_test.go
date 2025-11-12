package cert

import (
	"fmt"
	"testing"
	"time"
)

// TestBatchManager_NewBatchManager 测试创建批量管理器
func TestBatchManager_NewBatchManager(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	bm := auth.NewBatchManager()
	if bm == nil {
		t.Fatal("批量管理器不应为 nil")
	}

	if bm.maxWorkers != 10 {
		t.Errorf("默认工作器数量应为 10，实际为 %d", bm.maxWorkers)
	}

	if bm.auth != auth {
		t.Error("批量管理器应引用授权管理器")
	}
}

// TestBatchManager_WithMaxWorkers 测试设置并发工作器数量
func TestBatchManager_WithMaxWorkers(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	tests := []struct {
		name     string
		workers  int
		expected int
	}{
		{"设置为1", 1, 1},
		{"设置为5", 5, 5},
		{"设置为20", 20, 20},
		{"设置为0(无效)", 0, 10},   // 应保持默认值
		{"设置为负数(无效)", -1, 10}, // 应保持默认值
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			bm := auth.NewBatchManager().WithMaxWorkers(tt.workers)
			if bm.maxWorkers != tt.expected {
				t.Errorf("期望工作器数量 %d，实际 %d", tt.expected, bm.maxWorkers)
			}
		})
	}
}

// TestBatchManager_IssueMultipleCerts_Empty 测试空请求列表
func TestBatchManager_IssueMultipleCerts_Empty(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	bm := auth.NewBatchManager()
	results := bm.IssueMultipleCerts(nil)

	if results != nil {
		t.Errorf("空请求应返回 nil，实际返回 %v", results)
	}

	results = bm.IssueMultipleCerts([]*ClientCertRequest{})
	if results != nil {
		t.Errorf("空请求列表应返回 nil，实际返回 %v", results)
	}
}

// TestBatchManager_IssueMultipleCerts_Success 测试批量签发证书成功
func TestBatchManager_IssueMultipleCerts_Success(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 准备多个证书请求
	var requests []*ClientCertRequest
	for i := 0; i < 5; i++ {
		req, err := NewClientRequest().
			WithMachineID(fmt.Sprintf("batch-machine-%d", i)).
			WithExpiry(time.Now().AddDate(1, 0, 0)).
			WithVersion("1.0.0").
			WithCompany("批量测试公司", "研发部").
			WithValidityDays(365).
			Build()
		if err != nil {
			t.Fatalf("构建请求 %d 失败: %v", i, err)
		}
		requests = append(requests, req)
	}

	// 批量签发
	bm := auth.NewBatchManager()
	results := bm.IssueMultipleCerts(requests)

	// 验证结果
	if len(results) != len(requests) {
		t.Fatalf("结果数量不匹配: 期望 %d, 实际 %d", len(requests), len(results))
	}

	for i, result := range results {
		if result.Index != i {
			t.Errorf("结果 %d 的索引不匹配: 期望 %d, 实际 %d", i, i, result.Index)
		}

		if result.Error != nil {
			t.Errorf("结果 %d 签发失败: %v", i, result.Error)
		}

		if result.Certificate == nil {
			t.Errorf("结果 %d 的证书为 nil", i)
		}

		if result.Duration == 0 {
			t.Errorf("结果 %d 的耗时应该大于 0", i)
		}
	}
}

// TestBatchManager_IssueMultipleCerts_Concurrent 测试并发签发
func TestBatchManager_IssueMultipleCerts_Concurrent(t *testing.T) {
	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 准备大量请求
	var requests []*ClientCertRequest
	for i := 0; i < 8; i++ {
		req, err := NewClientRequest().
			WithMachineID(fmt.Sprintf("concurrent-%d", i)).
			WithExpiry(time.Now().AddDate(1, 0, 0)).
			WithVersion("1.0.0").
			WithCompany("并发测试", "测试部").
			WithValidityDays(365).
			Build()
		if err != nil {
			t.Fatalf("构建请求失败: %v", err)
		}
		requests = append(requests, req)
	}

	// 批量签发
	bm := auth.NewBatchManager().WithMaxWorkers(3)
	start := time.Now()
	results := bm.IssueMultipleCerts(requests)
	duration := time.Since(start)

	// 验证结果
	if len(results) != len(requests) {
		t.Fatalf("结果数量不匹配")
	}

	successCount := 0
	for _, result := range results {
		if result.Error == nil {
			successCount++
		}
	}

	if successCount != len(requests) {
		t.Errorf("成功数量不匹配: 期望 %d, 实际 %d", len(requests), successCount)
	}

	t.Logf("批量签发 %d 个证书耗时: %v", len(requests), duration)
}

// TestBatchManager_ValidateMultipleCerts_Empty 测试空验证列表
func TestBatchManager_ValidateMultipleCerts_Empty(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	bm := auth.NewBatchManager()
	results := bm.ValidateMultipleCerts(nil)

	if results != nil {
		t.Errorf("空验证列表应返回 nil")
	}

	results = bm.ValidateMultipleCerts([]CertValidation{})
	if results != nil {
		t.Errorf("空验证列表应返回 nil")
	}
}

// TestBatchManager_ValidateMultipleCerts_Success 测试批量验证证书
func TestBatchManager_ValidateMultipleCerts_Success(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 先签发一些证书
	var validations []CertValidation
	for i := 0; i < 5; i++ {
		machineID := fmt.Sprintf("validate-machine-%d", i)
		req, err := NewClientRequest().
			WithMachineID(machineID).
			WithExpiry(time.Now().AddDate(1, 0, 0)).
			WithVersion("1.0.0").
			WithCompany("验证测试", "测试部").
			WithValidityDays(365).
			Build()
		if err != nil {
			t.Fatalf("构建请求失败: %v", err)
		}

		cert, err := auth.IssueClientCert(req)
		if err != nil {
			t.Fatalf("签发证书失败: %v", err)
		}

		validations = append(validations, CertValidation{
			CertPEM:   cert.CertPEM,
			MachineID: machineID,
		})
	}

	// 批量验证
	bm := auth.NewBatchManager()
	results := bm.ValidateMultipleCerts(validations)

	// 验证结果
	if len(results) != len(validations) {
		t.Fatalf("结果数量不匹配: 期望 %d, 实际 %d", len(validations), len(results))
	}

	for i, result := range results {
		if result.Index != i {
			t.Errorf("结果 %d 的索引不匹配", i)
		}

		if !result.Valid {
			t.Errorf("结果 %d 应该有效，错误: %v", i, result.Error)
		}

		if result.MachineID == "" {
			t.Errorf("结果 %d 的机器 ID 为空", i)
		}

		if result.Duration == 0 {
			t.Errorf("结果 %d 的耗时应该大于 0", i)
		}
	}
}

// TestBatchIssueBuilder_Basic 测试批量签发构建器基本功能
func TestBatchIssueBuilder_Basic(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	builder := auth.NewBatchIssue()
	if builder == nil {
		t.Fatal("构建器不应为 nil")
	}

	if builder.bm == nil {
		t.Fatal("构建器应包含批量管理器")
	}

	if len(builder.requests) != 0 {
		t.Error("初始请求列表应为空")
	}
}

// TestBatchIssueBuilder_AddRequest 测试添加单个请求
func TestBatchIssueBuilder_AddRequest(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	req, err := NewClientRequest().
		WithMachineID("test-machine-add").
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithVersion("1.0.0").
		WithCompany("测试", "部门").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建请求失败: %v", err)
	}

	builder := auth.NewBatchIssue().AddRequest(req)
	if len(builder.requests) != 1 {
		t.Errorf("添加后请求数量应为 1，实际为 %d", len(builder.requests))
	}

	// 测试添加 nil 请求
	builder = builder.AddRequest(nil)
	if len(builder.requests) != 1 {
		t.Error("添加 nil 请求不应增加数量")
	}
}

// TestBatchIssueBuilder_AddRequests 测试添加多个请求
func TestBatchIssueBuilder_AddRequests(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	var requests []*ClientCertRequest
	for i := 0; i < 3; i++ {
		req, err := NewClientRequest().
			WithMachineID(fmt.Sprintf("test-multi-%d", i)).
			WithExpiry(time.Now().AddDate(1, 0, 0)).
			WithVersion("1.0.0").
			WithCompany("测试", "部门").
			WithValidityDays(365).
			Build()
		if err != nil {
			t.Fatalf("构建请求失败: %v", err)
		}
		requests = append(requests, req)
	}

	builder := auth.NewBatchIssue().AddRequests(requests...)
	if len(builder.requests) != 3 {
		t.Errorf("添加后请求数量应为 3，实际为 %d", len(builder.requests))
	}
}

// TestBatchIssueBuilder_WithMaxWorkers 测试设置工作器数量
func TestBatchIssueBuilder_WithMaxWorkers(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	builder := auth.NewBatchIssue().WithMaxWorkers(5)
	if builder.bm.maxWorkers != 5 {
		t.Errorf("工作器数量应为 5，实际为 %d", builder.bm.maxWorkers)
	}
}

// TestBatchIssueBuilder_Execute 测试执行批量签发
func TestBatchIssueBuilder_Execute(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 准备请求
	req1, _ := NewClientRequest().
		WithMachineID("exec-test-1").
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithVersion("1.0.0").
		WithCompany("测试", "部门").
		WithValidityDays(365).
		Build()

	req2, _ := NewClientRequest().
		WithMachineID("exec-test-2").
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithVersion("1.0.0").
		WithCompany("测试", "部门").
		WithValidityDays(365).
		Build()

	// 执行批量签发
	results := auth.NewBatchIssue().
		AddRequest(req1).
		AddRequest(req2).
		WithMaxWorkers(2).
		Execute()

	if len(results) != 2 {
		t.Fatalf("结果数量应为 2，实际为 %d", len(results))
	}

	for i, result := range results {
		if result.Error != nil {
			t.Errorf("结果 %d 签发失败: %v", i, result.Error)
		}
		if result.Certificate == nil {
			t.Errorf("结果 %d 的证书为 nil", i)
		}
	}
}

// TestBatchValidateBuilder_Basic 测试批量验证构建器基本功能
func TestBatchValidateBuilder_Basic(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	builder := auth.NewBatchValidate()
	if builder == nil {
		t.Fatal("构建器不应为 nil")
	}

	if builder.bm == nil {
		t.Fatal("构建器应包含批量管理器")
	}

	if len(builder.validations) != 0 {
		t.Error("初始验证列表应为空")
	}
}

// TestBatchValidateBuilder_AddValidation 测试添加验证请求
func TestBatchValidateBuilder_AddValidation(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	testCert := []byte("test-cert-pem")
	testMachine := "test-machine"

	builder := auth.NewBatchValidate().AddValidation(testCert, testMachine)
	if len(builder.validations) != 1 {
		t.Errorf("添加后验证数量应为 1，实际为 %d", len(builder.validations))
	}

	if string(builder.validations[0].CertPEM) != string(testCert) {
		t.Error("证书 PEM 不匹配")
	}

	if builder.validations[0].MachineID != testMachine {
		t.Error("机器 ID 不匹配")
	}
}

// TestBatchValidateBuilder_AddValidations 测试添加多个验证请求
func TestBatchValidateBuilder_AddValidations(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	validations := []CertValidation{
		{CertPEM: []byte("cert1"), MachineID: "machine1"},
		{CertPEM: []byte("cert2"), MachineID: "machine2"},
		{CertPEM: []byte("cert3"), MachineID: "machine3"},
	}

	builder := auth.NewBatchValidate().AddValidations(validations...)
	if len(builder.validations) != 3 {
		t.Errorf("添加后验证数量应为 3，实际为 %d", len(builder.validations))
	}
}

// TestBatchValidateBuilder_Execute 测试执行批量验证
func TestBatchValidateBuilder_Execute(t *testing.T) {

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 先签发证书
	req, _ := NewClientRequest().
		WithMachineID("validate-exec-test").
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithVersion("1.0.0").
		WithCompany("测试", "部门").
		WithValidityDays(365).
		Build()

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 执行批量验证
	results := auth.NewBatchValidate().
		AddValidation(cert.CertPEM, "validate-exec-test").
		WithMaxWorkers(1).
		Execute()

	if len(results) != 1 {
		t.Fatalf("结果数量应为 1，实际为 %d", len(results))
	}

	if !results[0].Valid {
		t.Errorf("验证应该成功，错误: %v", results[0].Error)
	}
}

// TestGetIssueStats 测试获取签发统计
func TestGetIssueStats(t *testing.T) {

	tests := []struct {
		name    string
		results []BatchResult
		want    BatchStats
	}{
		{
			name:    "空结果",
			results: nil,
			want:    BatchStats{},
		},
		{
			name: "单个成功",
			results: []BatchResult{
				{Index: 0, Error: nil, Duration: 100 * time.Millisecond},
			},
			want: BatchStats{
				Total:         1,
				Success:       1,
				Failed:        0,
				TotalDuration: 100 * time.Millisecond,
				AvgDuration:   100 * time.Millisecond,
				MaxDuration:   100 * time.Millisecond,
				MinDuration:   100 * time.Millisecond,
			},
		},
		{
			name: "混合结果",
			results: []BatchResult{
				{Index: 0, Error: nil, Duration: 100 * time.Millisecond},
				{Index: 1, Error: fmt.Errorf("error"), Duration: 50 * time.Millisecond},
				{Index: 2, Error: nil, Duration: 150 * time.Millisecond},
			},
			want: BatchStats{
				Total:         3,
				Success:       2,
				Failed:        1,
				TotalDuration: 300 * time.Millisecond,
				AvgDuration:   100 * time.Millisecond,
				MaxDuration:   150 * time.Millisecond,
				MinDuration:   50 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			stats := GetIssueStats(tt.results)

			if stats.Total != tt.want.Total {
				t.Errorf("Total: 期望 %d, 实际 %d", tt.want.Total, stats.Total)
			}
			if stats.Success != tt.want.Success {
				t.Errorf("Success: 期望 %d, 实际 %d", tt.want.Success, stats.Success)
			}
			if stats.Failed != tt.want.Failed {
				t.Errorf("Failed: 期望 %d, 实际 %d", tt.want.Failed, stats.Failed)
			}
			if stats.TotalDuration != tt.want.TotalDuration {
				t.Errorf("TotalDuration: 期望 %v, 实际 %v", tt.want.TotalDuration, stats.TotalDuration)
			}
			if stats.AvgDuration != tt.want.AvgDuration {
				t.Errorf("AvgDuration: 期望 %v, 实际 %v", tt.want.AvgDuration, stats.AvgDuration)
			}
			if stats.MaxDuration != tt.want.MaxDuration {
				t.Errorf("MaxDuration: 期望 %v, 实际 %v", tt.want.MaxDuration, stats.MaxDuration)
			}
			if stats.MinDuration != tt.want.MinDuration {
				t.Errorf("MinDuration: 期望 %v, 实际 %v", tt.want.MinDuration, stats.MinDuration)
			}
		})
	}
}

// TestGetValidationStats 测试获取验证统计
func TestGetValidationStats(t *testing.T) {

	tests := []struct {
		name    string
		results []ValidationResult
		want    BatchStats
	}{
		{
			name:    "空结果",
			results: nil,
			want:    BatchStats{},
		},
		{
			name: "单个成功",
			results: []ValidationResult{
				{Index: 0, Valid: true, Duration: 50 * time.Millisecond},
			},
			want: BatchStats{
				Total:         1,
				Success:       1,
				Failed:        0,
				TotalDuration: 50 * time.Millisecond,
				AvgDuration:   50 * time.Millisecond,
				MaxDuration:   50 * time.Millisecond,
				MinDuration:   50 * time.Millisecond,
			},
		},
		{
			name: "混合结果",
			results: []ValidationResult{
				{Index: 0, Valid: true, Duration: 100 * time.Millisecond},
				{Index: 1, Valid: false, Duration: 50 * time.Millisecond},
				{Index: 2, Valid: true, Duration: 75 * time.Millisecond},
			},
			want: BatchStats{
				Total:         3,
				Success:       2,
				Failed:        1,
				TotalDuration: 225 * time.Millisecond,
				AvgDuration:   75 * time.Millisecond,
				MaxDuration:   100 * time.Millisecond,
				MinDuration:   50 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			stats := GetValidationStats(tt.results)

			if stats.Total != tt.want.Total {
				t.Errorf("Total: 期望 %d, 实际 %d", tt.want.Total, stats.Total)
			}
			if stats.Success != tt.want.Success {
				t.Errorf("Success: 期望 %d, 实际 %d", tt.want.Success, stats.Success)
			}
			if stats.Failed != tt.want.Failed {
				t.Errorf("Failed: 期望 %d, 实际 %d", tt.want.Failed, stats.Failed)
			}
		})
	}
}
