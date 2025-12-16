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
	done    chan struct{} // 用于关闭清理协程
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
		done: make(chan struct{}),
	}

	// 启动清理协程
	if config.CleanupInterval > 0 {
		go cache.cleanupLoop()
	}

	return cache
}

// Get 从缓存获取验证结果
func (vc *ValidationCache) Get(certPEM []byte, machineID string) (error, bool) {
	key := vc.generateKey(certPEM, machineID)
	now := time.Now()

	vc.mu.Lock()
	defer vc.mu.Unlock()

	entry, exists := vc.entries[key]

	if !exists {
		vc.stats.Misses++
		return nil, false
	}

	// 检查是否过期
	if now.After(entry.ExpiresAt) {
		vc.stats.Misses++
		delete(vc.entries, key)
		vc.stats.Size = len(vc.entries)
		return nil, false
	}

	// 更新统计信息
	vc.stats.Hits++
	entry.HitCount++
	entry.LastHit = now

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

// cleanupLoop 清理过期条目的循环
func (vc *ValidationCache) cleanupLoop() {
	ticker := time.NewTicker(vc.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-vc.done:
			return
		case <-ticker.C:
			vc.cleanup()
		}
	}
}

// Close 关闭缓存并停止清理协程
func (vc *ValidationCache) Close() {
	select {
	case <-vc.done:
		// 已经关闭
	default:
		close(vc.done)
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

// Stats 获取缓存统计信息
func (vc *ValidationCache) Stats() CacheStats {
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

// HitRate 获取缓存命中率
func (vc *ValidationCache) HitRate() float64 {
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

// CacheStats 获取缓存统计
func (ca *CachedAuthorizer) CacheStats() CacheStats {
	return ca.cache.Stats()
}

// ClearCache 清空验证缓存
func (ca *CachedAuthorizer) ClearCache() {
	ca.cache.Clear()
}

// CacheHitRate 获取缓存命中率
func (ca *CachedAuthorizer) CacheHitRate() float64 {
	return ca.cache.HitRate()
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

// === 签名缓存功能 ===

// SignedCacheEntry 带签名的缓存条目
//
// 用于离线验证场景，确保缓存数据的完整性和真实性
type SignedCacheEntry struct {
	*CacheEntry
	Signature  string    // HMAC-SHA256 签名
	MachineID  string    // 机器ID（用于验证）
	SignedAt   time.Time // 签名时间
	DataHash   string    // 数据哈希（用于检测篡改）
	SnapshotID string    // 关联的硬件快照ID（可选）
}

// SignedValidationCache 带签名的验证缓存
type SignedValidationCache struct {
	*ValidationCache
	signKey []byte // 签名密钥
}

// NewSignedValidationCache 创建带签名的验证缓存
func NewSignedValidationCache(config CacheConfig, signKey []byte) *SignedValidationCache {
	return &SignedValidationCache{
		ValidationCache: NewValidationCache(config),
		signKey:         signKey,
	}
}

// StoreWithSignature 带签名存储缓存条目
//
// 参数：
//   - certPEM: 证书PEM数据
//   - machineID: 机器ID
//   - result: 验证结果
//   - snapshotID: 关联的硬件快照ID（可选）
//
// 返回签名后的缓存条目
func (svc *SignedValidationCache) StoreWithSignature(
	certPEM []byte,
	machineID string,
	result error,
	snapshotID string,
) (*SignedCacheEntry, error) {
	// 创建基础缓存条目
	entry := &CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(svc.config.TTL),
		HitCount:  0,
		CreatedAt: time.Now(),
		LastHit:   time.Now(),
	}

	// 计算数据哈希
	dataHash := svc.generateKey(certPEM, machineID)

	// 计算签名
	signatureData := fmt.Sprintf("%s|%s|%s|%s",
		dataHash,
		machineID,
		entry.CreatedAt.Format(time.RFC3339),
		entry.ExpiresAt.Format(time.RFC3339),
	)

	h := sha256.New()
	h.Write(svc.signKey)
	h.Write([]byte(signatureData))
	signature := fmt.Sprintf("%x", h.Sum(nil))

	// 创建签名缓存条目
	signedEntry := &SignedCacheEntry{
		CacheEntry: entry,
		Signature:  signature,
		MachineID:  machineID,
		SignedAt:   time.Now(),
		DataHash:   dataHash,
		SnapshotID: snapshotID,
	}

	// 存储到缓存
	svc.mu.Lock()
	defer svc.mu.Unlock()

	key := svc.generateKey(certPEM, machineID)

	// 检查缓存容量
	if len(svc.entries) >= svc.config.MaxSize {
		svc.evictLRU()
	}

	svc.entries[key] = entry
	svc.stats.Size = len(svc.entries)

	return signedEntry, nil
}

// GetWithVerification 验证后获取缓存条目
//
// 参数：
//   - certPEM: 证书PEM数据
//   - machineID: 机器ID
//   - signedEntry: 之前存储的签名条目
//
// 返回验证结果和是否有效
func (svc *SignedValidationCache) GetWithVerification(
	certPEM []byte,
	machineID string,
	signedEntry *SignedCacheEntry,
) (error, bool) {
	if signedEntry == nil {
		return nil, false
	}

	// 验证机器ID
	if signedEntry.MachineID != machineID {
		return fmt.Errorf("machine ID mismatch"), false
	}

	// 验证是否过期
	if time.Now().After(signedEntry.ExpiresAt) {
		return fmt.Errorf("cache entry expired"), false
	}

	// 计算数据哈希
	dataHash := svc.generateKey(certPEM, machineID)

	// 验证数据完整性
	if signedEntry.DataHash != dataHash {
		return fmt.Errorf("data hash mismatch: cache tampered"), false
	}

	// 重新计算签名并验证
	signatureData := fmt.Sprintf("%s|%s|%s|%s",
		signedEntry.DataHash,
		signedEntry.MachineID,
		signedEntry.CreatedAt.Format(time.RFC3339),
		signedEntry.ExpiresAt.Format(time.RFC3339),
	)

	h := sha256.New()
	h.Write(svc.signKey)
	h.Write([]byte(signatureData))
	expectedSignature := fmt.Sprintf("%x", h.Sum(nil))

	if signedEntry.Signature != expectedSignature {
		return fmt.Errorf("signature verification failed"), false
	}

	// 签名验证通过，更新统计信息
	svc.mu.Lock()
	defer svc.mu.Unlock()

	svc.stats.Hits++
	signedEntry.HitCount++
	signedEntry.LastHit = time.Now()

	return signedEntry.Result, true
}

// ExportSignedEntry 导出签名缓存条目（用于持久化）
func (svc *SignedValidationCache) ExportSignedEntry(
	certPEM []byte,
	machineID string,
) (*SignedCacheEntry, error) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()

	key := svc.generateKey(certPEM, machineID)
	entry, exists := svc.entries[key]

	if !exists {
		return nil, fmt.Errorf("entry not found in cache")
	}

	// 构建签名条目
	dataHash := svc.generateKey(certPEM, machineID)

	signatureData := fmt.Sprintf("%s|%s|%s|%s",
		dataHash,
		machineID,
		entry.CreatedAt.Format(time.RFC3339),
		entry.ExpiresAt.Format(time.RFC3339),
	)

	h := sha256.New()
	h.Write(svc.signKey)
	h.Write([]byte(signatureData))
	signature := fmt.Sprintf("%x", h.Sum(nil))

	return &SignedCacheEntry{
		CacheEntry: entry,
		Signature:  signature,
		MachineID:  machineID,
		SignedAt:   time.Now(),
		DataHash:   dataHash,
	}, nil
}
