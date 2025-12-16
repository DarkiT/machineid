package cert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	machineid "github.com/darkit/machineid"
)

// HardwareSnapshot 硬件快照结构
//
// 用于离线验证场景：
// - 在联网环境下创建快照并签名
// - 在离线环境下验证硬件是否发生变化
// - 支持时间有效性检查
type HardwareSnapshot struct {
	// Fingerprint 硬件指纹哈希
	Fingerprint string `json:"fingerprint"`

	// Components 组成指纹的硬件组件列表
	Components []string `json:"components"`

	// Weights 各组件的权重（与 Components 一一对应）
	Weights []int `json:"weights"`

	// CreatedAt 快照创建时间
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt 快照过期时间
	ExpiresAt time.Time `json:"expires_at"`

	// Signature HMAC-SHA256 签名（使用 machine ID 作为密钥）
	Signature string `json:"signature"`

	// Version 快照格式版本
	Version int `json:"version"`
}

const (
	// SnapshotVersion 当前快照格式版本
	SnapshotVersion = 1

	// DefaultSnapshotValidity 默认快照有效期（90天）
	DefaultSnapshotValidity = 90 * 24 * time.Hour
)

// CreateSnapshot 创建硬件快照
//
// 参数：
//   - appID: 应用标识符（用于生成签名密钥）
//   - validity: 快照有效期（传 0 使用默认 90 天）
//
// 返回快照对象和错误
func CreateSnapshot(appID string, validity time.Duration) (*HardwareSnapshot, error) {
	// 获取硬件指纹状态
	fpStatus, err := machineid.GetHardwareFingerprintStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware fingerprint: %w", err)
	}

	// 获取机器 ID（用于签名）
	machineID, err := machineid.ID()
	if err != nil {
		return nil, fmt.Errorf("failed to get machine ID: %w", err)
	}

	// 设置有效期
	if validity == 0 {
		validity = DefaultSnapshotValidity
	}

	now := time.Now()
	snapshot := &HardwareSnapshot{
		Fingerprint: fpStatus.Value,
		Components:  make([]string, 0),
		Weights:     make([]int, 0),
		CreatedAt:   now,
		ExpiresAt:   now.Add(validity),
		Version:     SnapshotVersion,
	}

	// 收集硬件组件（这里简化处理，实际应从 hardware info 获取）
	// 注意：这需要根据实际平台实现细节来填充
	snapshot.Components = append(snapshot.Components, fpStatus.Value)
	snapshot.Weights = append(snapshot.Weights, 100)

	// 计算签名
	signatureKey := fmt.Sprintf("%s/%s", appID, machineID)
	snapshot.Signature = snapshot.calculateSignature(signatureKey)

	return snapshot, nil
}

// VerifySnapshot 验证硬件快照
//
// 参数：
//   - appID: 应用标识符
//   - allowedDeviation: 允许的硬件变化偏差（0.0-1.0，例如 0.2 表示允许 20% 的硬件变化）
//
// 返回错误（nil 表示验证通过）
func VerifySnapshot(snapshot *HardwareSnapshot, appID string, allowedDeviation float64) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is nil")
	}

	// 检查快照版本
	if snapshot.Version != SnapshotVersion {
		return fmt.Errorf("unsupported snapshot version: %d (expected %d)", snapshot.Version, SnapshotVersion)
	}

	// 检查是否过期
	if time.Now().After(snapshot.ExpiresAt) {
		return fmt.Errorf("snapshot expired at %s", snapshot.ExpiresAt.Format(time.RFC3339))
	}

	// 验证签名
	machineID, err := machineid.ID()
	if err != nil {
		return fmt.Errorf("failed to get machine ID: %w", err)
	}

	signatureKey := fmt.Sprintf("%s/%s", appID, machineID)
	expectedSignature := snapshot.calculateSignature(signatureKey)
	if snapshot.Signature != expectedSignature {
		return fmt.Errorf("signature verification failed")
	}

	// 获取当前硬件指纹
	currentFP, err := machineid.GetHardwareFingerprintStatus()
	if err != nil {
		return fmt.Errorf("failed to get current hardware fingerprint: %w", err)
	}

	// 比较硬件指纹
	if snapshot.Fingerprint != currentFP.Value {
		// 如果不完全匹配，检查偏差是否在允许范围内
		deviation := calculateDeviation(snapshot.Components, snapshot.Weights, currentFP.Value)
		if deviation > allowedDeviation {
			return fmt.Errorf("hardware changed: deviation %.2f%% exceeds allowed %.2f%%",
				deviation*100, allowedDeviation*100)
		}
	}

	return nil
}

// calculateSignature 计算快照签名
func (s *HardwareSnapshot) calculateSignature(key string) string {
	// 构建待签名数据
	data := fmt.Sprintf("%s|%v|%s|%s|%d",
		s.Fingerprint,
		s.Components,
		s.CreatedAt.Format(time.RFC3339),
		s.ExpiresAt.Format(time.RFC3339),
		s.Version,
	)

	// HMAC-SHA256 签名
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// calculateDeviation 计算硬件变化偏差
//
// 简化实现：比较指纹字符串的相似度
// 实际应该基于组件权重进行精确计算
func calculateDeviation(components []string, weights []int, currentFingerprint string) float64 {
	// 简化：如果指纹完全不同，返回 100% 偏差
	// 实际应该解析组件并基于权重计算
	if len(components) == 0 {
		return 1.0
	}

	// 这里应该实现更精细的偏差计算逻辑
	// 例如：解析指纹，对比各个组件，根据权重计算偏差
	// 当前简化为：不匹配即返回最大偏差
	for _, comp := range components {
		if comp == currentFingerprint {
			return 0.0
		}
	}

	return 1.0
}

// SaveToFile 保存快照到文件
func (s *HardwareSnapshot) SaveToFile(filepath string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	err = os.WriteFile(filepath, data, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write snapshot file: %w", err)
	}

	return nil
}

// LoadSnapshotFromFile 从文件加载快照
func LoadSnapshotFromFile(filepath string) (*HardwareSnapshot, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot file: %w", err)
	}

	var snapshot HardwareSnapshot
	err = json.Unmarshal(data, &snapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}

	return &snapshot, nil
}

// IsExpired 检查快照是否已过期
func (s *HardwareSnapshot) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// TimeUntilExpiry 返回距离过期的剩余时间
func (s *HardwareSnapshot) TimeUntilExpiry() time.Duration {
	return time.Until(s.ExpiresAt)
}

// ExtendValidity 延长快照有效期
//
// 注意：延长有效期后需要重新计算签名
func (s *HardwareSnapshot) ExtendValidity(appID string, extension time.Duration) error {
	s.ExpiresAt = s.ExpiresAt.Add(extension)

	// 重新计算签名
	machineID, err := machineid.ID()
	if err != nil {
		return fmt.Errorf("failed to get machine ID: %w", err)
	}

	signatureKey := fmt.Sprintf("%s/%s", appID, machineID)
	s.Signature = s.calculateSignature(signatureKey)

	return nil
}
