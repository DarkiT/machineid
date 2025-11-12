package machineid

import "testing"

func stubFingerprint(t *testing.T, fn func() (*FingerprintStatus, error)) {
	t.Helper()
	orig := fingerprintStatusProvider
	fingerprintStatusProvider = fn
	t.Cleanup(func() { fingerprintStatusProvider = orig })
}

func stubMACResolver(t *testing.T, fn func() (*MACInfo, error)) {
	t.Helper()
	orig := macResolver
	macResolver = fn
	t.Cleanup(func() { macResolver = orig })
}

func stubIDProvider(t *testing.T, fn func() (string, error)) {
	t.Helper()
	orig := idProvider
	idProvider = fn
	t.Cleanup(func() { idProvider = orig })
}
