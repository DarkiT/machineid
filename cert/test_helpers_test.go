package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"
)

var (
	testCAOnce sync.Once
	testCACert []byte
	testCAKey  []byte
	testCAErr  error
)

func ensureTestCA() error {
	testCAOnce.Do(func() {
		info := CAInfo{
			CommonName:   "Test Root CA",
			Organization: "MachineID Tests",
			Country:      "CN",
			Province:     "GD",
			Locality:     "SZ",
			ValidDays:    3650,
			KeySize:      1024,
		}

		priv, err := rsa.GenerateKey(rand.Reader, info.KeySize)
		if err != nil {
			testCAErr = err
			return
		}

		tmpl := createCertificateTemplate(info, priv)
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			testCAErr = err
			return
		}

		testCACert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		testCAKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	})
	return testCAErr
}

func getTestCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	if err := ensureTestCA(); err != nil {
		t.Fatalf("生成测试 CA 失败: %v", err)
	}
	return testCACert, testCAKey
}

func newTestAuthorizerBuilder(t *testing.T) *AuthorizerBuilder {
	t.Helper()
	certPEM, keyPEM := getTestCA(t)
	return NewAuthorizer().WithCA(certPEM, keyPEM)
}
