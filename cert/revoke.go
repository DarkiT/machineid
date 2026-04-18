package cert

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RevokeInfo 吊销信息
type RevokeInfo struct {
	SerialNumber    string    // 证书序列号
	RevokeDate      time.Time // 吊销时间
	RevokeReason    string    // 吊销原因
	MinValidVersion string    // 最低有效版本
}

// RevokeList 吊销列表
type RevokeList struct {
	UpdateTime   time.Time              // 列表更新时间
	RevokedCerts map[string]*RevokeInfo // 已吊销证书
	MinVersion   string                 // 最低支持版本
}

// RevokeManager 吊销管理器
type RevokeManager struct {
	mu         sync.RWMutex
	revokeList *RevokeList
	currentVer string
	updateFunc func() ([]byte, error) // 添加更新函数

	// 自动更新相关字段
	autoUpdateConfig *AutoUpdateConfig
	stopChan         chan struct{}
	wg               sync.WaitGroup
	running          bool
}

// AutoUpdateConfig 自动更新配置
type AutoUpdateConfig struct {
	Interval      time.Duration // 更新间隔（默认1小时）
	RetryInterval time.Duration // 重试间隔（默认5分钟）
	MaxRetries    int           // 最大重试次数（默认3次）
	OnUpdate      func(oldTime, newTime time.Time, err error)
}

// DefaultAutoUpdateConfig 返回默认的自动更新配置
func DefaultAutoUpdateConfig() *AutoUpdateConfig {
	return &AutoUpdateConfig{
		Interval:      time.Hour,
		RetryInterval: 5 * time.Minute,
		MaxRetries:    3,
	}
}

// RevokeOption 吊销管理器的配置选项
type RevokeOption func(*RevokeManager) error

// WithRevokeList 直接设置吊销列表
func WithRevokeList(list []byte) RevokeOption {
	return func(rm *RevokeManager) error {
		var revokeList RevokeList
		if err := json.Unmarshal(list, &revokeList); err != nil {
			return fmt.Errorf("invalid revoke list: %v", err)
		}
		rm.mu.Lock()
		rm.revokeList = &revokeList
		rm.mu.Unlock()
		return nil
	}
}

// WithRevokeListUpdater 设置吊销列表更新函数
func WithRevokeListUpdater(updater func() ([]byte, error)) RevokeOption {
	return func(rm *RevokeManager) error {
		rm.updateFunc = updater
		return nil
	}
}

// NewRevokeManager 创建吊销管理器
func NewRevokeManager(version string, opts ...RevokeOption) (*RevokeManager, error) {
	rm := &RevokeManager{
		currentVer: version,
		revokeList: &RevokeList{
			UpdateTime:   time.Now(),
			RevokedCerts: make(map[string]*RevokeInfo),
			MinVersion:   "0.0.0",
		},
	}

	// 应用选项
	for _, opt := range opts {
		if err := opt(rm); err != nil {
			return nil, err
		}
	}

	return rm, nil
}

// UpdateRevokeList 更新吊销列表
func (rm *RevokeManager) UpdateRevokeList() error {
	if rm.updateFunc == nil {
		return errors.New("no update function configured")
	}

	data, err := rm.updateFunc()
	if err != nil {
		return fmt.Errorf("failed to update revoke list: %v", err)
	}

	return WithRevokeList(data)(rm)
}

// IsRevoked 检查证书是否被吊销
func (rm *RevokeManager) IsRevoked(serialNumber string) (bool, string) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// 检查证书是否在吊销列表中
	if info, exists := rm.revokeList.RevokedCerts[serialNumber]; exists {
		return true, info.RevokeReason
	}

	// 检查当前版本是否满足最低版本要求
	if rm.revokeList.MinVersion != "" && rm.currentVer != "" {
		if ok, err := compare(rm.currentVer, "<", rm.revokeList.MinVersion); err == nil && ok {
			return true, "program version too old"
		}
	}

	return false, ""
}

// StartAutoUpdate 启动自动更新
// 如果 config 为 nil，则使用默认配置
func (rm *RevokeManager) StartAutoUpdate(config *AutoUpdateConfig) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.running {
		return errors.New("auto update already running")
	}

	if rm.updateFunc == nil {
		return errors.New("no update function configured")
	}

	if config == nil {
		config = DefaultAutoUpdateConfig()
	}

	rm.autoUpdateConfig = config
	rm.stopChan = make(chan struct{})
	rm.running = true

	rm.wg.Add(1)
	go rm.autoUpdateLoop()

	return nil
}

// StopAutoUpdate 停止自动更新
func (rm *RevokeManager) StopAutoUpdate() {
	rm.mu.Lock()
	if !rm.running {
		rm.mu.Unlock()
		return
	}
	rm.running = false
	close(rm.stopChan)
	rm.mu.Unlock()

	rm.wg.Wait()
}

// IsAutoUpdateRunning 检查自动更新是否正在运行
func (rm *RevokeManager) IsAutoUpdateRunning() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.running
}

// autoUpdateLoop 自动更新循环
func (rm *RevokeManager) autoUpdateLoop() {
	defer rm.wg.Done()

	ticker := time.NewTicker(rm.autoUpdateConfig.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.performUpdateWithRetry()
		}
	}
}

// performUpdateWithRetry 执行带重试的更新
func (rm *RevokeManager) performUpdateWithRetry() {
	rm.mu.RLock()
	config := rm.autoUpdateConfig
	oldTime := rm.revokeList.UpdateTime
	rm.mu.RUnlock()

	var lastErr error
	for i := 0; i <= config.MaxRetries; i++ {
		if i > 0 {
			// 重试前等待
			select {
			case <-rm.stopChan:
				return
			case <-time.After(config.RetryInterval):
			}
		}

		err := rm.UpdateRevokeList()
		if err == nil {
			// 更新成功
			rm.mu.RLock()
			newTime := rm.revokeList.UpdateTime
			rm.mu.RUnlock()

			if config.OnUpdate != nil {
				config.OnUpdate(oldTime, newTime, nil)
			}
			return
		}
		lastErr = err
	}

	// 所有重试都失败
	if config.OnUpdate != nil {
		config.OnUpdate(oldTime, oldTime, lastErr)
	}
}

// AddRevocation 添加吊销记录
func (rm *RevokeManager) AddRevocation(serialNumber, reason string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.revokeList.RevokedCerts[serialNumber] = &RevokeInfo{
		SerialNumber: serialNumber,
		RevokeDate:   time.Now(),
		RevokeReason: reason,
	}
	rm.revokeList.UpdateTime = time.Now()
}

// RemoveRevocation 移除吊销记录
func (rm *RevokeManager) RemoveRevocation(serialNumber string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.revokeList.RevokedCerts, serialNumber)
	rm.revokeList.UpdateTime = time.Now()
}

// GetRevokeList 获取吊销列表的副本
func (rm *RevokeManager) GetRevokeList() *RevokeList {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// 返回副本以避免并发问题
	copyList := &RevokeList{
		UpdateTime:   rm.revokeList.UpdateTime,
		MinVersion:   rm.revokeList.MinVersion,
		RevokedCerts: make(map[string]*RevokeInfo, len(rm.revokeList.RevokedCerts)),
	}
	for k, v := range rm.revokeList.RevokedCerts {
		copyList.RevokedCerts[k] = &RevokeInfo{
			SerialNumber:    v.SerialNumber,
			RevokeDate:      v.RevokeDate,
			RevokeReason:    v.RevokeReason,
			MinValidVersion: v.MinValidVersion,
		}
	}
	return copyList
}
