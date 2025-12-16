package cert

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestClientRequestBuilderBuildSuccess 验证构建器能够完整生成请求并保留输入数据
func TestClientRequestBuilderBuildSuccess(t *testing.T) {
	t.Parallel()

	expiry := time.Now().Add(48 * time.Hour)
	req, err := NewClientRequest().
		WithMachineID("machine-12345678").
		WithExpiry(expiry).
		WithCompany("星火科技", "平台组").
		WithAddress("CN", "GD", "SZ", "科苑路").
		WithContact("张三", "18800000000", "ops@example.com").
		WithMinClientVersion("1.2.3").
		WithValidityDays(90).
		Build()
	if err != nil {
		t.Fatalf("构建请求失败: %v", err)
	}

	if req.Identity == nil || req.Company == nil || req.Technical == nil {
		t.Fatalf("关键字段未初始化: %+v", req)
	}
	if !req.Identity.ExpiryDate.Equal(expiry) {
		t.Fatalf("过期时间被意外修改: 期望 %v, 实际 %v", expiry, req.Identity.ExpiryDate)
	}
	if req.Technical.ValidityPeriodDays != 90 {
		t.Fatalf("有效期天数错误: 期望 90, 实际 %d", req.Technical.ValidityPeriodDays)
	}
	if got := req.MachineIDs(); !reflect.DeepEqual(got, []string{"machine-12345678"}) {
		t.Fatalf("机器ID解析错误: %v", got)
	}
}

// TestClientRequestBuilderTemplate 验证模板可以自动填充有效期等信息
func TestClientRequestBuilderTemplate(t *testing.T) {
	t.Parallel()

	req, err := NewClientRequest().
		WithMachineID("machine-87654321").
		WithCompany("凌云科技", "安全部").
		WithContact("李四", "020-88886666", "contact@example.com").
		WithMinClientVersion("3.2.1").
		WithTemplate("client-long").
		Build()
	if err != nil {
		t.Fatalf("应用模板失败: %v", err)
	}

	if req.Identity == nil || req.Identity.ExpiryDate.IsZero() {
		t.Fatalf("模板未设置过期时间: %+v", req)
	}
	if req.Technical.ValidityPeriodDays != 1095 {
		t.Fatalf("模板未写入有效期天数: 期望 1095, 实际 %d", req.Technical.ValidityPeriodDays)
	}
	// 允许小幅时间误差
	remainingDays := int(time.Until(req.Identity.ExpiryDate).Hours() / 24)
	if remainingDays < 1094 || remainingDays > 1096 {
		t.Fatalf("模板设置的有效期不在预期范围: %d 天", remainingDays)
	}
}

// TestClientCertRequestValidateErrors 针对不同输入验证校验失败路径
func TestClientCertRequestValidateErrors(t *testing.T) {
	t.Parallel()

	base := func() *ClientCertRequest {
		return &ClientCertRequest{
			Identity: &Identity{
				MachineID:  "machine-ABCDEFG",
				ExpiryDate: time.Now().Add(24 * time.Hour),
			},
			Company:   &Company{Name: "极客", Department: "技术"},
			Technical: &Technical{MinClientVersion: "1.0.0"},
		}
	}

	cases := []struct {
		name    string
		mutator func(req *ClientCertRequest)
		want    string
	}{
		{
			name: "缺少过期时间",
			mutator: func(req *ClientCertRequest) {
				req.Identity.ExpiryDate = time.Time{}
			},
			want: "expiry date is required",
		},
		{
			name: "过期时间已过去",
			mutator: func(req *ClientCertRequest) {
				req.Identity.ExpiryDate = time.Now().Add(-time.Hour)
			},
			want: "expiry date cannot be in the past",
		},
		{
			name: "缺少公司",
			mutator: func(req *ClientCertRequest) {
				req.Company = nil
			},
			want: "company information is required",
		},
		{
			name: "版本为空",
			mutator: func(req *ClientCertRequest) {
				req.Technical.MinClientVersion = ""
			},
			want: "minimum client version is required",
		},
		{
			name: "机器ID过短",
			mutator: func(req *ClientCertRequest) {
				req.Identity.MachineID = "short"
			},
			want: "machine ID 'short' is too short",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := base()
			tc.mutator(req)
			err := req.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("未命中预期错误: got=%v want~=%s", err, tc.want)
			}
		})
	}
}

// TestClientCertRequestMachineIDs 验证多机器ID解析
func TestClientCertRequestMachineIDs(t *testing.T) {
	t.Parallel()

	req := &ClientCertRequest{
		Identity: &Identity{MachineID: "node-1111 , node-2222,,node-3333"},
	}
	got := req.MachineIDs()
	want := []string{"node-1111", "node-2222", "node-3333"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("解析结果不正确: got=%v want=%v", got, want)
	}
}

// TestClientCertRequestSetDefaults 验证默认值填充逻辑
func TestClientCertRequestSetDefaults(t *testing.T) {
	t.Parallel()

	req := &ClientCertRequest{
		Identity: &Identity{
			MachineID:  "node-9999",
			ExpiryDate: time.Now().Add(72 * time.Hour),
		},
		Company:   &Company{Name: "星火", Department: ""},
		Technical: &Technical{MinClientVersion: "1.0.0"},
	}

	req.SetDefaults()

	if req.Technical.ValidityPeriodDays < 2 {
		t.Fatalf("有效期天数应根据过期时间计算，当前=%d", req.Technical.ValidityPeriodDays)
	}
	if req.Company.Department == "" {
		t.Fatalf("默认部门未设置")
	}
}
