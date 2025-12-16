package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	machineid "github.com/darkit/machineid"
)

// License 是离线授权文件的载体（payload + 签名）。
//
// 设计目标：
// - 可离线校验：客户端只需要内置公钥
// - 与证书授权并存：证书用于“更重”的授权体系，License 适合“轻量文件/配置”分发
// - 机器绑定：可绑定 MachineID（建议使用 machineid.ProtectedIDResult 的 Hash）
//
// 注意：
// - Signature 覆盖 CanonicalPayload（稳定 JSON 序列化），避免字段顺序导致签名不一致
type License struct {
	Payload   LicensePayload `json:"payload"`
	Signature string         `json:"signature"` // base64(std) of ed25519 signature
}

type LicensePayload struct {
	SchemaVersion int               `json:"schema_version"`
	LicenseID     string            `json:"license_id"`
	IssuedAt      time.Time         `json:"issued_at"`
	NotBefore     time.Time         `json:"not_before"`
	NotAfter      time.Time         `json:"not_after"`
	MachineID     string            `json:"machine_id"` // MachineID 建议填 machineid.ProtectedIDResult(appID).Hash（而非原始 machine-id），允许逗号分隔多个值
	Features      map[string]any    `json:"features,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"`
}

const defaultLicenseSchemaVersion = 1

func (p *LicensePayload) validate(now time.Time, machineID string) error {
	if p.SchemaVersion == 0 {
		p.SchemaVersion = defaultLicenseSchemaVersion
	}
	if p.LicenseID == "" {
		return fmt.Errorf("license: license_id required")
	}
	if p.NotAfter.IsZero() {
		return fmt.Errorf("license: not_after required")
	}
	if !p.NotBefore.IsZero() && now.Before(p.NotBefore) {
		return fmt.Errorf("license: not yet valid")
	}
	if now.After(p.NotAfter) {
		return fmt.Errorf("license: expired")
	}
	if machineID != "" && p.MachineID != "" {
		authorized := splitCSV(p.MachineID)
		if !containsTrimmed(authorized, machineID) {
			return fmt.Errorf("license: machine id not authorized")
		}
	}
	return nil
}

// GenerateLicenseKeyPairPEM 生成 Ed25519 license key pair（PKCS#8 PEM）。
func GenerateLicenseKeyPairPEM() (publicKeyPEM, privateKeyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDer})
	return publicKeyPEM, privateKeyPEM, nil
}

func ParseEd25519PublicKeyPEM(publicKeyPEM []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(publicKeyPEM)
	if blk == nil {
		return nil, errors.New("license: invalid public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("license: parse public key: %w", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("license: public key is not ed25519")
	}
	return pub, nil
}

func ParseEd25519PrivateKeyPEM(privateKeyPEM []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(privateKeyPEM)
	if blk == nil {
		return nil, errors.New("license: invalid private key PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("license: parse private key: %w", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("license: private key is not ed25519")
	}
	return priv, nil
}

// CanonicalPayload 返回用于签名/验签的稳定 JSON 表示。
func CanonicalPayload(payload LicensePayload) ([]byte, error) {
	// 这里使用 encoding/json 的稳定输出（struct 字段顺序固定；map 键在 Go1.20+ 会排序输出）。
	// 若未来需要更强确定性，可切换到自定义 canonical JSON（但当前足够）。
	return json.Marshal(payload)
}

// IssueLicense 使用 Ed25519 私钥签发 license（返回 JSON）。
func IssueLicense(payload LicensePayload, privateKey ed25519.PrivateKey) ([]byte, error) {
	if payload.SchemaVersion == 0 {
		payload.SchemaVersion = defaultLicenseSchemaVersion
	}
	if payload.IssuedAt.IsZero() {
		payload.IssuedAt = time.Now().UTC()
	}
	if payload.NotBefore.IsZero() {
		payload.NotBefore = payload.IssuedAt
	}

	msg, err := CanonicalPayload(payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(privateKey, msg)

	lic := License{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	return json.Marshal(lic)
}

// ValidateLicenseJSON 校验 license JSON，包含：
// - 签名验证
// - 时间有效期验证
// - 机器码匹配（若传入 machineID）
func ValidateLicenseJSON(licenseJSON []byte, publicKey ed25519.PublicKey, machineID string, now time.Time) (*LicensePayload, error) {
	var lic License
	if err := json.Unmarshal(licenseJSON, &lic); err != nil {
		return nil, fmt.Errorf("license: invalid json: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(lic.Signature)
	if err != nil {
		return nil, fmt.Errorf("license: invalid signature encoding: %w", err)
	}

	msg, err := CanonicalPayload(lic.Payload)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, msg, sig) {
		return nil, errors.New("license: signature verify failed")
	}

	if err := lic.Payload.validate(now, machineID); err != nil {
		return nil, err
	}
	return &lic.Payload, nil
}

// ValidateLicenseJSONWithAppID 是更推荐的校验入口：
// - machineID 使用 machineid.ProtectedIDResult(appID).Hash（避免暴露原始 machine-id）
// - 仍可保持 “license payload 内存储的是绑定后的 hash” 的设计
func ValidateLicenseJSONWithAppID(licenseJSON []byte, publicKey ed25519.PublicKey, appID string, now time.Time) (*LicensePayload, error) {
	if appID == "" {
		return nil, errors.New("license: appID required")
	}
	binding, err := machineid.ProtectedIDResult(appID)
	if err != nil {
		return nil, err
	}
	return ValidateLicenseJSON(licenseJSON, publicKey, binding.Hash, now)
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func containsTrimmed(items []string, target string) bool {
	for _, it := range items {
		if trimSpaces(it) == target {
			return true
		}
	}
	return false
}

func trimSpaces(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
