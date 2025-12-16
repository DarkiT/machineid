package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestGetKeySize_ECDSA 测试 ECDSA 密钥大小识别
func TestGetKeySize_ECDSA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		curve    elliptic.Curve
		expected int
	}{
		{"P-256", elliptic.P256(), 256},
		{"P-384", elliptic.P384(), 384},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// 生成 ECDSA 密钥
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("生成 ECDSA 密钥失败: %v", err)
			}

			// 创建自签名证书
			cert := createTestCertificate(t, &privateKey.PublicKey)

			// 检查密钥大小
			inspector := NewCertificateInspector()
			keySize := inspector.getKeySize(cert)

			if keySize != tt.expected {
				t.Errorf("密钥大小不匹配: 期望 %d, 实际 %d", tt.expected, keySize)
			}
		})
	}
}

// TestGetKeySize_Ed25519 测试 Ed25519 密钥大小识别
func TestGetKeySize_Ed25519(t *testing.T) {
	t.Parallel()

	// 生成 Ed25519 密钥
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}

	// 创建自签名证书
	cert := createTestCertificate(t, publicKey)

	// 检查密钥大小
	inspector := NewCertificateInspector()
	keySize := inspector.getKeySize(cert)

	expected := 256
	if keySize != expected {
		t.Errorf("密钥大小不匹配: 期望 %d, 实际 %d", expected, keySize)
	}
}

// TestGetKeySize_NilPublicKey 测试 nil 公钥的处理
func TestGetKeySize_NilPublicKey(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{
		PublicKey: nil,
	}

	inspector := NewCertificateInspector()
	keySize := inspector.getKeySize(cert)

	if keySize != 0 {
		t.Errorf("nil 公钥应返回 0, 实际返回 %d", keySize)
	}
}

// createTestCertificate 创建测试用的自签名证书
func createTestCertificate(t *testing.T, publicKey any) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// 根据不同的公钥类型选择合适的私钥
	var privateKey any
	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		privateKey, err = ecdsa.GenerateKey(pub.Curve, rand.Reader)
		if err != nil {
			t.Fatalf("生成 ECDSA 私钥失败: %v", err)
		}
	case ed25519.PublicKey:
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("生成 Ed25519 密钥失败: %v", err)
		}
	default:
		t.Fatalf("不支持的公钥类型")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}

	return cert
}

// TestInspectCertificate_KeySize 测试完整的证书检查流程
func TestInspectCertificate_KeySize(t *testing.T) {
	// 生成 ECDSA P-256 密钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}

	cert := createTestCertificate(t, &privateKey.PublicKey)

	inspector := NewCertificateInspector()
	info := inspector.InspectCertificate(cert)

	if info.KeySize != 256 {
		t.Errorf("证书信息中的密钥大小不匹配: 期望 256, 实际 %d", info.KeySize)
	}
}

// TestIsValidMachineID 验证机器 ID 校验逻辑
func TestIsValidMachineID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"空字符串", "", false},
		{"长度不足", "abc123", false},
		{"合法单个ID", "ABC-1234_def", true},
		{"合法多个ID", "device-1234, NODE_9876", true},
		{"包含非法字符", "abc$1234", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsValidMachineID(tt.id)
			if got != tt.want {
				t.Fatalf("期望 %v, 实际 %v (输入: %q)", tt.want, got, tt.id)
			}
		})
	}
}
