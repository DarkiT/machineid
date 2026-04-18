package cert

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ValidationCache 验证缓存（使用 O(1) LRU 驱逐算法）
type ValidationCache struct {
	mu      sync.RWMutex
	entries map[string]*list.Element // key -> list element
	lruList *list.List               // 双向链表，头部是最近使用的
	config  CacheConfig
	stats   CacheStats
	done    chan struct{} // 用于关闭清理协程
}

// cacheItem 缓存项（存储在链表中）
type cacheItem struct {
	key   string
	entry *CacheEntry
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
		entries: make(map[string]*list.Element),
		lruList: list.New(),
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
	// 在锁外计算 key，避免持锁时间过长
	// 注意：generateKey 内部使用 copy 避免并发问题
	key := generateCacheKey(certPEM, machineID)
	now := time.Now()

	vc.mu.Lock()
	defer vc.mu.Unlock()

	elem, exists := vc.entries[key]
	if !exists {
		vc.stats.Misses++
		return nil, false
	}

	item := elem.Value.(*cacheItem)

	// 检查是否过期
	if now.After(item.entry.ExpiresAt) {
		vc.stats.Misses++
		vc.lruList.Remove(elem)
		delete(vc.entries, key)
		vc.stats.Size = vc.lruList.Len()
		return nil, false
	}

	// 移动到链表头部（最近使用）
	vc.lruList.MoveToFront(elem)

	// 更新统计信息
	vc.stats.Hits++
	item.entry.HitCount++
	item.entry.LastHit = now

	return item.entry.Result, true
}

// Put 将验证结果存储到缓存
func (vc *ValidationCache) Put(certPEM []byte, machineID string, result error) {
	key := generateCacheKey(certPEM, machineID)

	vc.mu.Lock()
	defer vc.mu.Unlock()

	// 如果已存在，更新并移到头部
	if elem, exists := vc.entries[key]; exists {
		item := elem.Value.(*cacheItem)
		item.entry.Result = result
		item.entry.ExpiresAt = time.Now().Add(vc.config.TTL)
		item.entry.LastHit = time.Now()
		vc.lruList.MoveToFront(elem)
		return
	}

	// 检查缓存容量，驱逐最旧条目
	for vc.lruList.Len() >= vc.config.MaxSize {
		vc.evictLRU()
	}

	// 创建新条目
	now := time.Now()
	entry := &CacheEntry{
		Result:    result,
		ExpiresAt: now.Add(vc.config.TTL),
		HitCount:  0,
		CreatedAt: now,
		LastHit:   now,
	}

	// 添加到链表头部
	item := &cacheItem{key: key, entry: entry}
	elem := vc.lruList.PushFront(item)
	vc.entries[key] = elem
	vc.stats.Size = vc.lruList.Len()
}

// generateCacheKey 生成缓存键（并发安全）
func generateCacheKey(certPEM []byte, machineID string) string {
	// 创建新的切片避免并发修改问题
	data := make([]byte, len(certPEM)+len(machineID))
	copy(data, certPEM)
	copy(data[len(certPEM):], machineID)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// generateKey 生成缓存键（保留方法以兼容签名缓存）
func (vc *ValidationCache) generateKey(certPEM []byte, machineID string) string {
	return generateCacheKey(certPEM, machineID)
}

// evictLRU 驱逐最近最少使用的条目（O(1) 时间复杂度）
func (vc *ValidationCache) evictLRU() {
	// 从链表尾部移除（最久未使用）
	elem := vc.lruList.Back()
	if elem == nil {
		return
	}

	item := elem.Value.(*cacheItem)
	vc.lruList.Remove(elem)
	delete(vc.entries, item.key)
	vc.stats.Evicted++
	vc.stats.Size = vc.lruList.Len()
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

	// 遍历链表，移除过期条目
	var next *list.Element
	for elem := vc.lruList.Front(); elem != nil; elem = next {
		next = elem.Next()
		item := elem.Value.(*cacheItem)
		if now.After(item.entry.ExpiresAt) {
			vc.lruList.Remove(elem)
			delete(vc.entries, item.key)
			vc.stats.Evicted++
		}
	}

	vc.stats.Size = vc.lruList.Len()
}

// Stats 获取缓存统计信息
func (vc *ValidationCache) Stats() CacheStats {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	stats := vc.stats
	stats.Size = vc.lruList.Len()
	return stats
}

// Clear 清空缓存
func (vc *ValidationCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.entries = make(map[string]*list.Element)
	vc.lruList.Init()
	vc.stats.Size = 0
}

// Size 获取当前缓存大小
func (vc *ValidationCache) Size() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.lruList.Len()
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
	now := time.Now()
	// 创建基础缓存条目
	entry := &CacheEntry{
		Result:    result,
		ExpiresAt: now.Add(svc.config.TTL),
		HitCount:  0,
		CreatedAt: now,
		LastHit:   now,
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
		SignedAt:   now,
		DataHash:   dataHash,
		SnapshotID: snapshotID,
	}

	// 存储到缓存
	svc.mu.Lock()
	defer svc.mu.Unlock()

	key := svc.generateKey(certPEM, machineID)

	// 检查缓存容量，驱逐最旧条目
	for svc.lruList.Len() >= svc.config.MaxSize {
		svc.evictLRU()
	}

	// 添加到链表头部
	item := &cacheItem{key: key, entry: entry}
	elem := svc.lruList.PushFront(item)
	svc.entries[key] = elem
	svc.stats.Size = svc.lruList.Len()

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
	elem, exists := svc.entries[key]

	if !exists {
		return nil, fmt.Errorf("entry not found in cache")
	}

	item := elem.Value.(*cacheItem)
	entry := item.entry

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
