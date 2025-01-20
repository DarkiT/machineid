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
	if rm.currentVer < rm.revokeList.MinVersion {
		return true, "program version too old"
	}

	return false, ""
}
