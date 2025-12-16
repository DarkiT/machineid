package cert

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestValidationCachePutAndGet 验证基础的读写流程和统计信息
func TestValidationCachePutAndGet(t *testing.T) {
	t.Parallel()

	cache := NewValidationCache(CacheConfig{
		TTL:             time.Minute,
		MaxSize:         10,
		CleanupInterval: 0,
	})

	cert := []byte("cert-A")
	machine := "machine-A"
	if _, found := cache.Get(cert, machine); found {
		t.Fatalf("空缓存不应命中")
	}

	sentinel := errors.New("verify failed")
	cache.Put(cert, machine, sentinel)

	result, found := cache.Get(cert, machine)
	if !found {
		t.Fatalf("缓存应命中")
	}
	if result != sentinel {
		t.Fatalf("返回的错误与存储的不一致: %v", result)
	}

	stats := cache.Stats()
	if stats.Hits == 0 || stats.Misses == 0 {
		t.Fatalf("命中/未命中统计异常: %+v", stats)
	}
}

// TestValidationCacheLRUEviction 验证超过容量时按 LRU 驱逐
func TestValidationCacheLRUEviction(t *testing.T) {
	t.Parallel()

	cache := NewValidationCache(CacheConfig{TTL: time.Minute, MaxSize: 2})
	cache.Put([]byte("cert-1"), "m1", nil)
	cache.Put([]byte("cert-2"), "m2", nil)
	if _, found := cache.Get([]byte("cert-1"), "m1"); !found {
		t.Fatalf("预期命中 cert-1")
	} // 提升优先级
	cache.Put([]byte("cert-3"), "m3", nil)

	key2 := cache.generateKey([]byte("cert-2"), "m2")
	cache.mu.RLock()
	_, exists := cache.entries[key2]
	cache.mu.RUnlock()
	if exists {
		t.Fatalf("最近最少使用的条目应被驱逐")
	}
	if cache.Size() != 2 {
		t.Fatalf("驱逐后大小应为2，当前=%d", cache.Size())
	}
}

// TestValidationCacheExpirationCleanup 验证 TTL 到期后清理
func TestValidationCacheExpirationCleanup(t *testing.T) {
	t.Parallel()

	cache := NewValidationCache(CacheConfig{TTL: 20 * time.Millisecond, MaxSize: 5})
	cache.Put([]byte("cert-exp"), "m-exp", nil)
	time.Sleep(40 * time.Millisecond)
	cache.cleanup()

	if cache.Size() != 0 {
		t.Fatalf("过期清理后缓存应为空")
	}
	if cache.Stats().Evicted == 0 {
		t.Fatalf("应统计一次驱逐")
	}
}

// TestValidationCacheConcurrentAccess 确保并发访问下无异常
func TestValidationCacheConcurrentAccess(t *testing.T) {
	t.Parallel()

	cache := NewValidationCache(CacheConfig{TTL: time.Second, MaxSize: 50})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cert := []byte(fmt.Sprintf("cert-%d", i%10))
			machine := fmt.Sprintf("machine-%d", i%7)
			cache.Put(cert, machine, nil)
			if err, _ := cache.Get(cert, machine); err != nil {
				t.Errorf("缓存读取返回错误: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if cache.Size() > cache.config.MaxSize {
		t.Fatalf("缓存大小不应超过上限: size=%d", cache.Size())
	}
	if rate := cache.HitRate(); rate <= 0 {
		t.Fatalf("命中率应大于0，当前=%f", rate)
	}
}

// TestValidationCacheClear 测试清空缓存功能
func TestValidationCacheClear(t *testing.T) {
	t.Parallel()

	cache := NewValidationCache(CacheConfig{TTL: time.Minute, MaxSize: 10})

	// 添加多个条目
	for i := 0; i < 5; i++ {
		cert := []byte(fmt.Sprintf("cert-%d", i))
		machine := fmt.Sprintf("machine-%d", i)
		cache.Put(cert, machine, nil)
	}

	// 验证条目已添加
	if cache.Size() != 5 {
		t.Fatalf("期望缓存大小为 5，实际为 %d", cache.Size())
	}

	// 清空缓存
	cache.Clear()

	// 验证缓存已清空
	if cache.Size() != 0 {
		t.Fatalf("清空后缓存大小应为 0，实际为 %d", cache.Size())
	}

	// 验证统计信息
	stats := cache.Stats()
	if stats.Size != 0 {
		t.Errorf("清空后统计的大小应为 0，实际为 %d", stats.Size)
	}
}

// TestValidationCacheHitRate 测试命中率计算
func TestValidationCacheHitRate(t *testing.T) {
	t.Parallel()

	cache := NewValidationCache(CacheConfig{TTL: time.Minute, MaxSize: 10})

	// 添加条目
	cache.Put([]byte("cert-1"), "machine-1", nil)
	cache.Put([]byte("cert-2"), "machine-2", errors.New("validation failed"))

	// 命中缓存
	if _, found := cache.Get([]byte("cert-1"), "machine-1"); !found {
		t.Fatalf("预期命中 cert-1")
	}
	if _, found := cache.Get([]byte("cert-1"), "machine-1"); !found {
		t.Fatalf("预期命中 cert-1 第二次")
	}
	if _, found := cache.Get([]byte("cert-2"), "machine-2"); !found {
		t.Fatalf("预期命中 cert-2")
	}

	// 未命中缓存
	if _, found := cache.Get([]byte("cert-3"), "machine-3"); found {
		t.Fatalf("应当未命中 cert-3")
	}

	// 验证命中率
	hitRate := cache.HitRate()
	expectedRate := 3.0 / 4.0 // 3 次命中，1 次未命中

	if hitRate < expectedRate-0.01 || hitRate > expectedRate+0.01 {
		t.Errorf("命中率不正确: 期望 %.2f, 实际 %.2f", expectedRate, hitRate)
	}
}

// TestCachedAuthorizer_WithCache 测试带缓存的授权器
func TestCachedAuthorizer_WithCache(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		WithCacheTTL(5 * time.Minute).
		WithCacheSize(100).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 添加缓存功能
	cachedAuth := auth.WithCache()
	if cachedAuth == nil {
		t.Fatal("带缓存的授权器不应为 nil")
	}

	// 验证缓存已初始化
	if cachedAuth.cache == nil {
		t.Fatal("缓存未初始化")
	}
}

// TestCachedAuthorizer_ValidateCert 测试带缓存的证书验证
func TestCachedAuthorizer_ValidateCert(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		WithCacheTTL(5 * time.Minute).
		WithCacheSize(100).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	machineID := "cached-test-machine"
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
		t.Fatalf("签发证书失败: %v", err)
	}

	// 创建带缓存的授权器
	cachedAuth := auth.WithCache()

	// 第一次验证 - 应该未命中缓存
	err = cachedAuth.ValidateCert(cert.CertPEM, machineID)
	if err != nil {
		t.Errorf("第一次验证失败: %v", err)
	}

	// 第二次验证 - 应该命中缓存
	err = cachedAuth.ValidateCert(cert.CertPEM, machineID)
	if err != nil {
		t.Errorf("第二次验证失败: %v", err)
	}

	// 验证缓存统计
	stats := cachedAuth.CacheStats()
	if stats.Hits != 1 {
		t.Errorf("期望 1 次缓存命中，实际 %d 次", stats.Hits)
	}

	if stats.Misses != 1 {
		t.Errorf("期望 1 次缓存未命中，实际 %d 次", stats.Misses)
	}
}

// TestCachedAuthorizer_CacheHitRate 测试获取缓存命中率
func TestCachedAuthorizer_CacheHitRate(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	machineID := "hitrate-test-machine"
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
		t.Fatalf("签发证书失败: %v", err)
	}

	// 创建带缓存的授权器
	cachedAuth := auth.WithCache()

	// 第一次验证 - 未命中
	if err := cachedAuth.ValidateCert(cert.CertPEM, machineID); err != nil {
		t.Fatalf("首次验证不应失败: %v", err)
	}

	// 多次验证 - 命中
	for i := 0; i < 9; i++ {
		if err := cachedAuth.ValidateCert(cert.CertPEM, machineID); err != nil {
			t.Fatalf("缓存命中时不应失败: %v", err)
		}
	}

	// 验证命中率
	hitRate := cachedAuth.CacheHitRate()
	expectedRate := 9.0 / 10.0 // 9 次命中，1 次未命中

	if hitRate < expectedRate-0.01 || hitRate > expectedRate+0.01 {
		t.Errorf("命中率不正确: 期望 %.2f, 实际 %.2f", expectedRate, hitRate)
	}
}

// TestCachedAuthorizer_ClearCache 测试清空缓存
func TestCachedAuthorizer_ClearCache(t *testing.T) {
	t.Parallel()

	// 创建授权管理器
	auth, err := newTestAuthorizerBuilder(t).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 签发测试证书
	machineID := "clear-test-machine"
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
		t.Fatalf("签发证书失败: %v", err)
	}

	// 创建带缓存的授权器
	cachedAuth := auth.WithCache()

	// 验证并缓存结果
	if err := cachedAuth.ValidateCert(cert.CertPEM, machineID); err != nil {
		t.Fatalf("验证失败: %v", err)
	}

	// 验证缓存有数据
	stats := cachedAuth.CacheStats()
	if stats.Size == 0 {
		t.Fatal("缓存应该有数据")
	}

	// 清空缓存
	cachedAuth.ClearCache()

	// 验证缓存已清空
	stats = cachedAuth.CacheStats()
	if stats.Size != 0 {
		t.Errorf("清空后缓存大小应为 0，实际为 %d", stats.Size)
	}
}

// TestAuthorizerBuilder_WithCacheConfig 测试缓存配置构建器
func TestAuthorizerBuilder_WithCacheConfig(t *testing.T) {
	t.Parallel()

	config := CacheConfig{
		TTL:             10 * time.Minute,
		MaxSize:         200,
		CleanupInterval: 2 * time.Minute,
	}

	builder := newTestAuthorizerBuilder(t).
		WithCacheConfig(config)

	// 验证配置已设置
	if builder.config.Cache.TTL != config.TTL {
		t.Errorf("缓存 TTL 不匹配: 期望 %v, 实际 %v", config.TTL, builder.config.Cache.TTL)
	}

	if builder.config.Cache.MaxSize != config.MaxSize {
		t.Errorf("缓存大小不匹配: 期望 %d, 实际 %d", config.MaxSize, builder.config.Cache.MaxSize)
	}

	if builder.config.Cache.CleanupInterval != config.CleanupInterval {
		t.Errorf("清理间隔不匹配: 期望 %v, 实际 %v", config.CleanupInterval, builder.config.Cache.CleanupInterval)
	}
}

// TestAuthorizerBuilder_BuildWithCache 测试构建带缓存的授权器
func TestAuthorizerBuilder_BuildWithCache(t *testing.T) {
	t.Parallel()

	cachedAuth, err := newTestAuthorizerBuilder(t).
		WithCacheTTL(5 * time.Minute).
		WithCacheSize(100).
		BuildWithCache()
	if err != nil {
		t.Fatalf("构建带缓存的授权器失败: %v", err)
	}

	if cachedAuth == nil {
		t.Fatal("带缓存的授权器不应为 nil")
	}

	if cachedAuth.cache == nil {
		t.Fatal("缓存未初始化")
	}

	// 验证可以正常使用
	stats := cachedAuth.CacheStats()
	if stats.MaxSize != 100 {
		t.Errorf("缓存最大大小不匹配: 期望 100, 实际 %d", stats.MaxSize)
	}
}

// TestValidationCache_CleanupLoop 测试自动清理循环
func TestValidationCache_CleanupLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过长时间运行测试")
	}

	t.Parallel()

	// 创建一个清理间隔很短的缓存
	cache := NewValidationCache(CacheConfig{
		TTL:             100 * time.Millisecond,
		MaxSize:         10,
		CleanupInterval: 50 * time.Millisecond,
	})

	// 添加一些会过期的条目
	for i := 0; i < 5; i++ {
		cert := []byte(fmt.Sprintf("cert-%d", i))
		machine := fmt.Sprintf("machine-%d", i)
		cache.Put(cert, machine, nil)
	}

	// 验证条目已添加
	if cache.Size() != 5 {
		t.Fatalf("期望缓存大小为 5，实际为 %d", cache.Size())
	}

	// 等待条目过期和自动清理
	time.Sleep(200 * time.Millisecond)

	// 验证过期条目已被清理
	if cache.Size() != 0 {
		t.Errorf("过期条目应该被自动清理，当前大小: %d", cache.Size())
	}

	// 验证统计信息
	stats := cache.Stats()
	if stats.Evicted == 0 {
		t.Error("应该有驱逐统计")
	}
}
