package cert

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ValidationCache 验证缓存
type ValidationCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	config  CacheConfig
	stats   CacheStats
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Result    error     // 验证结果（nil表示验证成功）
	ExpiresAt time.Time // 过期时间
	HitCount  int64     // 命中次数
	CreatedAt time.Time // 创建时间
	LastHit   time.Time // 最后命中时间
}

// CacheStats 缓存统计
type CacheStats struct {
	Hits    int64 // 缓存命中次数
	Misses  int64 // 缓存未命中次数
	Evicted int64 // 被驱逐的条目数
	Size    int   // 当前缓存大小
	MaxSize int   // 最大缓存大小
}

// NewValidationCache 创建新的验证缓存
func NewValidationCache(config CacheConfig) *ValidationCache {
	cache := &ValidationCache{
		entries: make(map[string]*CacheEntry),
		config:  config,
		stats: CacheStats{
			MaxSize: config.MaxSize,
		},
	}

	// 启动清理协程
	if config.CleanupInterval > 0 {
		go cache.cleanupLoop()
	}

	return cache
}

// Get 从缓存获取验证结果
func (vc *ValidationCache) Get(certPEM []byte, machineID string) (error, bool) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	key := vc.generateKey(certPEM, machineID)
	entry, exists := vc.entries[key]

	if !exists {
		vc.stats.Misses++
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(entry.ExpiresAt) {
		vc.stats.Misses++
		// 异步清理过期条目
		go vc.removeEntry(key)
		return nil, false
	}

	// 更新统计信息
	vc.stats.Hits++
	entry.HitCount++
	entry.LastHit = time.Now()

	return entry.Result, true
}

// Put 将验证结果存储到缓存
func (vc *ValidationCache) Put(certPEM []byte, machineID string, result error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	key := vc.generateKey(certPEM, machineID)

	// 检查缓存容量
	if len(vc.entries) >= vc.config.MaxSize {
		vc.evictLRU()
	}

	// 创建新条目
	entry := &CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(vc.config.TTL),
		HitCount:  0,
		CreatedAt: time.Now(),
		LastHit:   time.Now(),
	}

	vc.entries[key] = entry
	vc.stats.Size = len(vc.entries)
}

// generateKey 生成缓存键
func (vc *ValidationCache) generateKey(certPEM []byte, machineID string) string {
	hash := sha256.Sum256(append(certPEM, []byte(machineID)...))
	return fmt.Sprintf("%x", hash)
}

// evictLRU 驱逐最近最少使用的条目
func (vc *ValidationCache) evictLRU() {
	if len(vc.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// 找到最旧的条目
	for key, entry := range vc.entries {
		if oldestKey == "" || entry.LastHit.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastHit
		}
	}

	// 删除最旧的条目
	if oldestKey != "" {
		delete(vc.entries, oldestKey)
		vc.stats.Evicted++
		vc.stats.Size = len(vc.entries)
	}
}

// removeEntry 异步移除条目
func (vc *ValidationCache) removeEntry(key string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	delete(vc.entries, key)
	vc.stats.Size = len(vc.entries)
}

// cleanupLoop 清理过期条目的循环
func (vc *ValidationCache) cleanupLoop() {
	ticker := time.NewTicker(vc.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		vc.cleanup()
	}
}

// cleanup 清理过期条目
func (vc *ValidationCache) cleanup() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	// 收集过期键
	for key, entry := range vc.entries {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// 删除过期条目
	for _, key := range expiredKeys {
		delete(vc.entries, key)
		vc.stats.Evicted++
	}

	vc.stats.Size = len(vc.entries)
}

// GetStats 获取缓存统计信息
func (vc *ValidationCache) GetStats() CacheStats {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	stats := vc.stats
	stats.Size = len(vc.entries)
	return stats
}

// Clear 清空缓存
func (vc *ValidationCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.entries = make(map[string]*CacheEntry)
	vc.stats.Size = 0
}

// Size 获取当前缓存大小
func (vc *ValidationCache) Size() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.entries)
}

// GetHitRate 获取缓存命中率
func (vc *ValidationCache) GetHitRate() float64 {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	total := vc.stats.Hits + vc.stats.Misses
	if total == 0 {
		return 0.0
	}
	return float64(vc.stats.Hits) / float64(total)
}

// CachedAuthorizer 带缓存的授权器包装
type CachedAuthorizer struct {
	*Authorizer
	cache *ValidationCache
}

// WithCache 为授权器添加缓存功能
func (a *Authorizer) WithCache() *CachedAuthorizer {
	cache := NewValidationCache(a.config.Cache)
	return &CachedAuthorizer{
		Authorizer: a,
		cache:      cache,
	}
}

// ValidateCert 带缓存的证书验证
func (ca *CachedAuthorizer) ValidateCert(certPEM []byte, machineID string) error {
	// 尝试从缓存获取结果
	if result, found := ca.cache.Get(certPEM, machineID); found {
		return result
	}

	// 缓存未命中，执行实际验证
	result := ca.Authorizer.ValidateCert(certPEM, machineID)

	// 将结果存储到缓存
	ca.cache.Put(certPEM, machineID, result)

	return result
}

// GetCacheStats 获取缓存统计
func (ca *CachedAuthorizer) GetCacheStats() CacheStats {
	return ca.cache.GetStats()
}

// ClearCache 清空验证缓存
func (ca *CachedAuthorizer) ClearCache() {
	ca.cache.Clear()
}

// GetCacheHitRate 获取缓存命中率
func (ca *CachedAuthorizer) GetCacheHitRate() float64 {
	return ca.cache.GetHitRate()
}

// 添加缓存配置构建器方法
func (b *AuthorizerBuilder) WithCacheConfig(config CacheConfig) *AuthorizerBuilder {
	b.config.Cache = config
	return b
}

// WithCache 构建带缓存的授权器
func (b *AuthorizerBuilder) BuildWithCache() (*CachedAuthorizer, error) {
	auth, err := b.Build()
	if err != nil {
		return nil, err
	}
	return auth.WithCache(), nil
}
