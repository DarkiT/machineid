//go:build freebsd || openbsd || netbsd || dragonfly || solaris
// +build freebsd openbsd netbsd dragonfly solaris

package machineid

import "testing"

func stubBsdCommandOutput(t *testing.T, fn func(string, ...string) ([]byte, error)) {
	t.Helper()
	orig := bsdCommandOutput
	bsdCommandOutput = fn
	t.Cleanup(func() {
		bsdCommandOutput = orig
	})
}
