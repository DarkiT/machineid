package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	machineid "github.com/darkit/machineid"
)

// TestIssueClientCert_Success 测试正常的证书签发流程
func TestIssueClientCert_Success(t *testing.T) {
	tests := []struct {
		name       string
		machineID  string
		appVersion string
	}{
		{
			name:       "标准机器ID",
			machineID:  "test-machine-001",
			appVersion: "1.0.0",
		},
		{
			name:       "复杂机器ID",
			machineID:  "ABC-1234_def",
			appVersion: "2.0.0",
		},
		{
			name:       "长机器ID",
			machineID:  "production-server-datacenter-001",
			appVersion: "3.5.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建授权管理器
			auth, err := newTestAuthorizerBuilder(t).
				Build()
			if err != nil {
				t.Fatalf("创建授权管理器失败: %v", err)
			}

			// 创建证书请求
			expiryDate := time.Now().AddDate(1, 0, 0) // 1年后过期
			req, err := NewClientRequest().
				WithMachineID(tt.machineID).
				WithExpiry(expiryDate).
				WithMinClientVersion(tt.appVersion).
				WithCompany("测试公司", "研发部").
				WithValidityDays(365).
				Build()
			if err != nil {
				t.Fatalf("构建证书请求失败: %v", err)
			}

			// 签发证书
			cert, err := auth.IssueClientCert(req)
			if err != nil {
				t.Fatalf("签发证书失败: %v", err)
			}

			// 验证证书不为空
			if cert == nil {
				t.Fatal("签发的证书为 nil")
			}

			// 验证证书内容不为空
			if len(cert.CertPEM) == 0 {
				t.Error("证书 PEM 为空")
			}

			// 验证证书可以解析
			block, _ := pem.Decode(cert.CertPEM)
			if block == nil {
				t.Fatal("无法解码证书 PEM")
			}

			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("解析证书失败: %v", err)
			}

			// 验证证书的基本信息
			if x509Cert.Subject.CommonName == "" {
				t.Error("证书 CommonName 为空")
			}

			// 验证证书有效期
			now := time.Now()
			if now.Before(x509Cert.NotBefore) {
				t.Error("证书还未生效")
			}
			if now.After(x509Cert.NotAfter) {
				t.Error("证书已过期")
			}

			// 验证密钥使用
			if x509Cert.KeyUsage == 0 {
				t.Error("证书密钥用途为空")
			}
		})
	}
}

// TestIssueClientCert_InvalidRequest 测试无效的证书请求
func TestIssueClientCert_InvalidRequest(t *testing.T) {
	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	tests := []struct {
		name        string
		setupReq    func() (*ClientCertRequest, error)
		expectError bool
	}{
		{
			name: "空机器ID",
			setupReq: func() (*ClientCertRequest, error) {
				return NewClientRequest().
					WithMachineID("").
					WithExpiry(time.Now().AddDate(1, 0, 0)).
					WithCompany("测试公司", "研发部").
					Build()
			},
			expectError: true,
		},
		{
			name: "机器ID过短",
			setupReq: func() (*ClientCertRequest, error) {
				return NewClientRequest().
					WithMachineID("abc").
					WithExpiry(time.Now().AddDate(1, 0, 0)).
					WithCompany("测试公司", "研发部").
					Build()
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建证书请求
			req, err := tt.setupReq()
			// 如果构建请求就失败了
			if err != nil {
				if !tt.expectError {
					t.Fatalf("构建请求失败: %v", err)
				}
				return
			}

			// 尝试签发证书
			cert, err := auth.IssueClientCert(req)

			// 验证错误
			if tt.expectError {
				if err == nil {
					t.Error("期望签发失败，但成功了")
					if cert != nil {
						t.Logf("意外签发的证书: %+v", cert)
					}
				}
			} else {
				if err != nil {
					t.Errorf("签发失败: %v", err)
				}
			}
		})
	}
}

// TestValidateCert_Success 测试正常的证书验证流程
func TestValidateCert_Success(t *testing.T) {
	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	machineID := "test-machine-valid"
	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}

	// 验证证书
	err = auth.ValidateCert(cert.CertPEM, machineID)
	if err != nil {
		t.Errorf("验证证书失败: %v", err)
	}
}

// TestValidateCert_WrongMachineID 测试错误的机器ID验证
func TestValidateCert_WrongMachineID(t *testing.T) {
	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	correctMachineID := "correct-machine-id"
	req, err := NewClientRequest().
		WithMachineID(correctMachineID).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithMinClientVersion("1.0.0").
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}

	// 使用错误的机器ID验证
	wrongMachineID := "wrong-machine-id"
	err = auth.ValidateCert(cert.CertPEM, wrongMachineID)
	if err == nil {
		t.Error("期望验证失败（错误的机器ID），但成功了")
	}
}

// TestValidateCert_InvalidPEM 测试无效的PEM格式
func TestValidateCert_InvalidPEM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		certPEM []byte
	}{
		{
			name:    "空PEM",
			certPEM: []byte{},
		},
		{
			name:    "无效的PEM格式",
			certPEM: []byte("这不是一个有效的PEM格式"),
		},
		{
			name: "错误的PEM头",
			certPEM: []byte(`-----BEGIN INVALID-----
MIIBkTCB+wIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJDTjEQMA4GA1UE
-----END INVALID-----`),
		},
	}

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// 验证无效的证书
			err := auth.ValidateCert(tt.certPEM, "test-machine")
			if err == nil {
				t.Error("期望验证失败（无效的PEM），但成功了")
			}
		})
	}
}

// TestExtractClientInfo_Success 测试成功提取客户端信息
func TestExtractClientInfo_Success(t *testing.T) {
	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	expectedMachineID := "extract-test-machine"
	expectedVersion := "1.0.0"

	req, err := NewClientRequest().
		WithMachineID(expectedMachineID).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithMinClientVersion(expectedVersion).
		WithCompany("测试公司", "研发部").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}

	// 提取客户端信息
	info, err := auth.ExtractClientInfo(cert.CertPEM)
	if err != nil {
		t.Fatalf("提取客户端信息失败: %v", err)
	}

	// 验证提取的信息
	if info == nil {
		t.Fatal("提取的客户端信息为 nil")
	}

	// 验证版本信息（根据实际实现调整）
	if info.MinClientVersion != expectedVersion {
		t.Errorf("版本信息不匹配: 期望 %q, 实际 %q", expectedVersion, info.MinClientVersion)
	}
}

// TestExtractClientInfo_InvalidCert 测试从无效证书提取信息
func TestExtractClientInfo_InvalidCert(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 尝试从无效证书提取信息
	invalidPEM := []byte("invalid certificate data")
	info, err := auth.ExtractClientInfo(invalidPEM)

	if err == nil {
		t.Error("期望提取失败（无效证书），但成功了")
		if info != nil {
			t.Logf("意外提取的信息: %+v", info)
		}
	}
}

func TestBindingInfoRoundTrip(t *testing.T) {
	t.Parallel()

	auth, err := newTestAuthorizerBuilder(t).Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	binding := &machineid.BindingResult{
		Hash:     "binding-machine-id",
		Mode:     machineid.BindingModeMAC,
		Provider: "eth0",
	}

	req, err := NewClientRequest().
		WithMachineID(binding.Hash).
		WithBindingResult(binding).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithCompany("绑定测试", "研发").
		WithMinClientVersion("1.0.0").
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	certificate, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	info, err := auth.ExtractClientInfo(certificate.CertPEM)
	if err != nil {
		t.Fatalf("提取客户端信息失败: %v", err)
	}

	if info.BindingMode != string(binding.Mode) {
		t.Fatalf("绑定模式不匹配: 期望 %s, 实际 %s", binding.Mode, info.BindingMode)
	}
	if info.BindingProvider != binding.Provider {
		t.Fatalf("绑定提供者不匹配: 期望 %s, 实际 %s", binding.Provider, info.BindingProvider)
	}
}

// TestCertificateLifecycle 测试完整的证书生命周期
func TestCertificateLifecycle(t *testing.T) {
	// 1. 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	machineID := "lifecycle-test-machine"
	appVersion := "1.0.0"

	// 2. 构建证书请求
	req, err := NewClientRequest().
		WithMachineID(machineID).
		WithExpiry(time.Now().AddDate(1, 0, 0)).
		WithMinClientVersion(appVersion).
		WithCompany("生命周期测试公司", "测试部门").
		WithValidityDays(365).
		Build()
	if err != nil {
		t.Fatalf("构建证书请求失败: %v", err)
	}

	// 3. 签发证书
	cert, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	// 4. 验证证书
	err = auth.ValidateCert(cert.CertPEM, machineID)
	if err != nil {
		t.Errorf("验证证书失败: %v", err)
	}

	// 5. 提取客户端信息
	info, err := auth.ExtractClientInfo(cert.CertPEM)
	if err != nil {
		t.Fatalf("提取客户端信息失败: %v", err)
	}

	// 6. 验证提取的信息
	if info.MinClientVersion != appVersion {
		t.Errorf("版本信息不匹配: 期望 %q, 实际 %q", appVersion, info.MinClientVersion)
	}

	// 7. 再次验证以确保一致性
	err = auth.ValidateCert(cert.CertPEM, machineID)
	if err != nil {
		t.Errorf("第二次验证证书失败: %v", err)
	}
}

// TestConcurrentCertIssue 测试并发签发证书
func TestConcurrentCertIssue(t *testing.T) {
	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 并发签发证书
	concurrency := 4
	done := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		i := i
		go func() {
			machineID := fmt.Sprintf("concurrent-machine-%d", i)
			req, err := NewClientRequest().
				WithMachineID(machineID).
				WithExpiry(time.Now().AddDate(1, 0, 0)).
				WithMinClientVersion("1.0.0").
				WithCompany("并发测试公司", "测试部门").
				WithValidityDays(365).
				Build()
			if err != nil {
				done <- err
				return
			}

			_, err = auth.IssueClientCert(req)
			done <- err
		}()
	}

	// 等待所有 goroutine 完成
	for i := 0; i < concurrency; i++ {
		if err := <-done; err != nil {
			t.Errorf("并发签发证书失败: %v", err)
		}
	}
}
