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

func resetBindingProviders(t *testing.T) {
	t.Helper()
	bindingProvidersMu.Lock()
	orig := append([]bindingProvider(nil), bindingProviders...)
	bindingProviders = nil
	bindingProvidersMu.Unlock()
	t.Cleanup(func() {
		bindingProvidersMu.Lock()
		bindingProviders = orig
		bindingProvidersMu.Unlock()
	})
}

func resetContainerHintProviders(t *testing.T) {
	t.Helper()
	containerHintProvidersMu.Lock()
	origAnonymous := append([]ContainerHintProvider(nil), containerHintProviders...)
	origNamed := append([]namedContainerHintProvider(nil), namedContainerHintProviders...)
	containerHintProviders = nil
	namedContainerHintProviders = nil
	containerHintProvidersMu.Unlock()
	t.Cleanup(func() {
		containerHintProvidersMu.Lock()
		containerHintProviders = origAnonymous
		namedContainerHintProviders = origNamed
		containerHintProvidersMu.Unlock()
	})
}
