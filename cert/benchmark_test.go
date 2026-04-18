//go:build !go1.25
// +build !go1.25

// 注意：基准测试在 Go 1.25+ 的实验性 greenteagc GC 下存在 runtime SIGSEGV 问题
// 在稳定版本的 Go 中运行基准测试

package cert

import (
	"testing"
	"time"
)

func BenchmarkValidationCache_Get(b *testing.B) {
	cache := NewValidationCache(CacheConfig{
		TTL:             5 * time.Minute,
		MaxSize:         1000,
		CleanupInterval: time.Minute,
	})
	defer cache.Close()

	certPEM := []byte("test-cert-pem-data")
	machineID := "TEST_MACHINE_ID"

	// 预填充缓存
	cache.Put(certPEM, machineID, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(certPEM, machineID)
	}
}

func BenchmarkValidationCache_Put(b *testing.B) {
	cache := NewValidationCache(CacheConfig{
		TTL:             5 * time.Minute,
		MaxSize:         10000,
		CleanupInterval: time.Minute,
	})
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		certPEM := []byte("test-cert-pem-data-" + string(rune(i%256)))
		machineID := "MACHINE_" + string(rune(i%256))
		cache.Put(certPEM, machineID, nil)
	}
}

func BenchmarkValidationCache_Eviction(b *testing.B) {
	cache := NewValidationCache(CacheConfig{
		TTL:             5 * time.Minute,
		MaxSize:         100, // 小缓存触发频繁驱逐
		CleanupInterval: time.Minute,
	})
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		certPEM := []byte("test-cert-pem-data-" + string(rune(i%256)))
		machineID := "MACHINE_" + string(rune(i%256))
		cache.Put(certPEM, machineID, nil)
	}
}

func BenchmarkBatchIssue_SingleWorker(b *testing.B) {
	certPEM, keyPEM := getTestCA(b)
	auth, err := NewAuthorizer().
		WithCA(certPEM, keyPEM).
		WithRuntimeVersion("bench").
		Build()
	if err != nil {
		b.Fatalf("创建授权管理器失败: %v", err)
	}

	requests := make([]*ClientCertRequest, 10)
	for i := range requests {
		req, err := NewClientRequest().
			WithMachineID("BENCH_MACHINE_"+string(rune('A'+i))).
			WithExpiry(time.Now().Add(24*time.Hour)).
			WithCompany("Bench Co", "Bench Dept").
			WithMinClientVersion("0.0.0").
			WithValidityDays(1).
			Build()
		if err != nil {
			b.Fatalf("构建请求失败: %v", err)
		}
		requests[i] = req
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm := auth.NewBatchManager().WithMaxWorkers(1)
		bm.IssueMultipleCerts(requests)
	}
}

func BenchmarkBatchIssue_MultiWorker(b *testing.B) {
	certPEM, keyPEM := getTestCA(b)
	auth, err := NewAuthorizer().
		WithCA(certPEM, keyPEM).
		WithRuntimeVersion("bench").
		Build()
	if err != nil {
		b.Fatalf("创建授权管理器失败: %v", err)
	}

	requests := make([]*ClientCertRequest, 10)
	for i := range requests {
		req, err := NewClientRequest().
			WithMachineID("BENCH_MACHINE_"+string(rune('A'+i))).
			WithExpiry(time.Now().Add(24*time.Hour)).
			WithCompany("Bench Co", "Bench Dept").
			WithMinClientVersion("0.0.0").
			WithValidityDays(1).
			Build()
		if err != nil {
			b.Fatalf("构建请求失败: %v", err)
		}
		requests[i] = req
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm := auth.NewBatchManager().WithMaxWorkers(4)
		bm.IssueMultipleCerts(requests)
	}
}

func BenchmarkBatchValidate(b *testing.B) {
	certPEM, keyPEM := getTestCA(b)
	auth, err := NewAuthorizer().
		WithCA(certPEM, keyPEM).
		WithRuntimeVersion("bench").
		Build()
	if err != nil {
		b.Fatalf("创建授权管理器失败: %v", err)
	}

	// 预先签发证书
	validations := make([]CertValidation, 10)
	for i := range validations {
		machineID := "BENCH_MACHINE_" + string(rune('A'+i))
		req, err := NewClientRequest().
			WithMachineID(machineID).
			WithExpiry(time.Now().Add(24*time.Hour)).
			WithCompany("Bench Co", "Bench Dept").
			WithMinClientVersion("0.0.0").
			WithValidityDays(1).
			Build()
		if err != nil {
			b.Fatalf("构建请求失败: %v", err)
		}
		cert, err := auth.IssueClientCert(req)
		if err != nil {
			b.Fatalf("签发证书失败: %v", err)
		}
		validations[i] = CertValidation{
			CertPEM:   cert.CertPEM,
			MachineID: machineID,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm := auth.NewBatchManager().WithMaxWorkers(4)
		bm.ValidateMultipleCerts(validations)
	}
}

func BenchmarkRevokeManager_IsRevoked(b *testing.B) {
	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		b.Fatalf("创建吊销管理器失败: %v", err)
	}

	// 预填充吊销列表
	for i := 0; i < 1000; i++ {
		rm.AddRevocation("SERIAL_"+string(rune(i%256)), "测试")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.IsRevoked("SERIAL_" + string(rune(i%256)))
	}
}

func BenchmarkSecurityManager_Check(b *testing.B) {
	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.Check()
	}
}

func BenchmarkSecurityManager_DetectEnvironment(b *testing.B) {
	sm := NewSecurityManager(SecurityLevelBasic)
	defer sm.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.DetectEnvironment()
	}
}
