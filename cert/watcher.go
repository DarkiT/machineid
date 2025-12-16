package cert

import (
	"context"
	"sync"
	"time"
)

// WatchEvent 监控事件类型
type WatchEvent string

const (
	WatchEventExpiring WatchEvent = "expiring" // 即将到期
	WatchEventExpired  WatchEvent = "expired"  // 已到期
	WatchEventInvalid  WatchEvent = "invalid"  // 证书无效
	WatchEventRevoked  WatchEvent = "revoked"  // 证书被吊销
)

// WatchCallback 监控回调函数类型
type WatchCallback func(event WatchEvent, clientInfo *ClientInfo, err error)

// WatchConfig 监控配置
type WatchConfig struct {
	// CheckInterval 检查间隔，默认1小时
	CheckInterval time.Duration

	// ExpiryWarningPeriod 到期预警时间，默认7天
	ExpiryWarningPeriod time.Duration

	// EnableExpiryWarning 是否启用到期预警
	EnableExpiryWarning bool

	// EnableRevocationCheck 是否启用吊销检查
	EnableRevocationCheck bool

	// MaxRetries 检查失败时的最大重试次数
	MaxRetries int

	// RetryInterval 重试间隔
	RetryInterval time.Duration
}

// DefaultWatchConfig 返回默认监控配置
func DefaultWatchConfig() *WatchConfig {
	return &WatchConfig{
		CheckInterval:         time.Hour,          // 每小时检查一次
		ExpiryWarningPeriod:   7 * 24 * time.Hour, // 7天预警
		EnableExpiryWarning:   true,
		EnableRevocationCheck: true,
		MaxRetries:            3,
		RetryInterval:         5 * time.Minute,
	}
}

// CertWatcher 证书监控器
type CertWatcher struct {
	auth      *Authorizer
	certPEM   []byte
	machineID string
	callback  WatchCallback
	config    *WatchConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex

	isRunning  bool
	lastCheck  time.Time
	lastError  error
	checkCount int64
}

// NewCertWatcher 创建证书监控器
func NewCertWatcher(auth *Authorizer, certPEM []byte, machineID string, callback WatchCallback) *CertWatcher {
	return &CertWatcher{
		auth:      auth,
		certPEM:   certPEM,
		machineID: machineID,
		callback:  callback,
		config:    DefaultWatchConfig(),
	}
}

// WithConfig 设置监控配置
func (w *CertWatcher) WithConfig(config *WatchConfig) *CertWatcher {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config = config
	return w
}

// WithCheckInterval 设置检查间隔
func (w *CertWatcher) WithCheckInterval(interval time.Duration) *CertWatcher {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.CheckInterval = interval
	return w
}

// WithExpiryWarning 设置到期预警
func (w *CertWatcher) WithExpiryWarning(period time.Duration) *CertWatcher {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.ExpiryWarningPeriod = period
	w.config.EnableExpiryWarning = true
	return w
}

// Start 启动监控
func (w *CertWatcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isRunning {
		return NewConfigError(ErrInvalidConfig, "watcher is already running", nil)
	}

	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.isRunning = true

	w.wg.Add(1)
	go w.watchLoop()

	return nil
}

// Stop 停止监控
func (w *CertWatcher) Stop() {
	w.mu.Lock()
	if !w.isRunning {
		w.mu.Unlock()
		return
	}

	w.cancel()
	w.isRunning = false
	w.mu.Unlock()

	w.wg.Wait()
}

// IsRunning 检查是否正在运行
func (w *CertWatcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.isRunning
}

// Stats 获取监控统计信息
func (w *CertWatcher) Stats() map[string]interface{} {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return map[string]interface{}{
		"is_running":     w.isRunning,
		"last_check":     w.lastCheck,
		"last_error":     w.lastError,
		"check_count":    w.checkCount,
		"check_interval": w.config.CheckInterval,
	}
}

// watchLoop 监控循环
func (w *CertWatcher) watchLoop() {
	defer w.wg.Done()

	// 立即执行第一次检查
	w.performCheck()

	ticker := time.NewTicker(w.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.performCheck()
		}
	}
}

// performCheck 执行检查
func (w *CertWatcher) performCheck() {
	w.mu.Lock()
	w.lastCheck = time.Now()
	w.checkCount++
	w.mu.Unlock()

	// 提取证书信息
	clientInfo, err := w.auth.ExtractClientInfo(w.certPEM)
	if err != nil {
		w.handleError(WatchEventInvalid, nil, err)
		return
	}

	// 检查证书是否过期
	now := time.Now()
	if now.After(clientInfo.ExpiryDate) {
		w.triggerCallback(WatchEventExpired, clientInfo, nil)
		return
	}

	// 检查是否即将到期
	if w.config.EnableExpiryWarning {
		timeUntilExpiry := clientInfo.ExpiryDate.Sub(now)
		if timeUntilExpiry <= w.config.ExpiryWarningPeriod {
			w.triggerCallback(WatchEventExpiring, clientInfo, nil)
			return
		}
	}

	// 验证证书有效性（包括吊销检查）
	if err := w.auth.ValidateCert(w.certPEM, w.machineID); err != nil {
		if IsSecurityError(err) {
			// 安全错误不算证书问题，可能是环境变化
			w.handleError(WatchEventInvalid, clientInfo, err)
		} else {
			// 其他错误可能是吊销或证书无效
			event := WatchEventInvalid
			if w.config.EnableRevocationCheck {
				// 这里可以进一步判断是否为吊销
				event = WatchEventRevoked
			}
			w.triggerCallback(event, clientInfo, err)
		}
		return
	}

	// 清除上次错误
	w.mu.Lock()
	w.lastError = nil
	w.mu.Unlock()
}

// triggerCallback 触发回调
func (w *CertWatcher) triggerCallback(event WatchEvent, clientInfo *ClientInfo, err error) {
	if w.callback != nil {
		go w.callback(event, clientInfo, err)
	}
}

// handleError 处理错误（带重试机制）
func (w *CertWatcher) handleError(event WatchEvent, clientInfo *ClientInfo, err error) {
	w.mu.Lock()
	w.lastError = err
	w.mu.Unlock()

	// 实现简单的重试机制
	for i := 0; i < w.config.MaxRetries; i++ {
		time.Sleep(w.config.RetryInterval)

		// 重新验证
		if validateErr := w.auth.ValidateCert(w.certPEM, w.machineID); validateErr == nil {
			// 重试成功，清除错误
			w.mu.Lock()
			w.lastError = nil
			w.mu.Unlock()
			return
		}
	}

	// 重试失败，触发回调
	w.triggerCallback(event, clientInfo, err)
}

// Watch 是Authorizer的便捷方法，用于启动证书监控
func (a *Authorizer) Watch(certPEM []byte, machineID string, callback WatchCallback, intervals ...time.Duration) (*CertWatcher, error) {
	watcher := NewCertWatcher(a, certPEM, machineID, callback)

	// 设置自定义检查间隔（如果提供）
	if len(intervals) > 0 && intervals[0] > 0 {
		watcher.WithCheckInterval(intervals[0])
	}

	// 如果提供了第二个参数作为预警时间
	if len(intervals) > 1 && intervals[1] > 0 {
		watcher.WithExpiryWarning(intervals[1])
	}

	if err := watcher.Start(); err != nil {
		return nil, err
	}

	return watcher, nil
}

// WatcherManager 监控器管理器
type WatcherManager struct {
	watchers map[string]*CertWatcher
	mu       sync.RWMutex
}

// NewWatcherManager 创建监控器管理器
func NewWatcherManager() *WatcherManager {
	return &WatcherManager{
		watchers: make(map[string]*CertWatcher),
	}
}

// AddWatcher 添加监控器
func (wm *WatcherManager) AddWatcher(id string, watcher *CertWatcher) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// 如果已存在同ID的监控器，先停止它
	if existing, exists := wm.watchers[id]; exists {
		existing.Stop()
	}

	wm.watchers[id] = watcher
}

// RemoveWatcher 移除监控器
func (wm *WatcherManager) RemoveWatcher(id string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if watcher, exists := wm.watchers[id]; exists {
		watcher.Stop()
		delete(wm.watchers, id)
	}
}

// Watcher 获取监控器
func (wm *WatcherManager) Watcher(id string) (*CertWatcher, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	watcher, exists := wm.watchers[id]
	return watcher, exists
}

// StopAll 停止所有监控器
func (wm *WatcherManager) StopAll() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for _, watcher := range wm.watchers {
		watcher.Stop()
	}
	wm.watchers = make(map[string]*CertWatcher)
}

// AllStats 获取所有监控器的统计信息
func (wm *WatcherManager) AllStats() map[string]map[string]interface{} {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	stats := make(map[string]map[string]interface{})
	for id, watcher := range wm.watchers {
		stats[id] = watcher.Stats()
	}

	return stats
}
