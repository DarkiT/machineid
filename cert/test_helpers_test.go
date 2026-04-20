package cert

import (
	"crypto/ed25519"
	"crypto/rand"
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
		}

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			testCAErr = err
			return
		}

		tmpl := createCertificateTemplate(info)
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			testCAErr = err
			return
		}

		testCACert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			testCAErr = err
			return
		}
		testCAKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	})
	return testCAErr
}

func getTestCA(tb testing.TB) ([]byte, []byte) {
	tb.Helper()
	if err := ensureTestCA(); err != nil {
		tb.Fatalf("生成测试 CA 失败: %v", err)
	}
	return testCACert, testCAKey
}

func newTestAuthorizerBuilder(tb testing.TB) *AuthorizerBuilder {
	tb.Helper()
	certPEM, keyPEM := getTestCA(tb)
	return NewAuthorizer().WithCA(certPEM, keyPEM)
}
