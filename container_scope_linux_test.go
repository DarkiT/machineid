//go:build linux
// +build linux

package machineid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanAccessHostHardware_NoPanic(t *testing.T) {
	_ = canAccessHostHardware()
}

func TestGetContainerPersistentFeatures_BasicKeys(t *testing.T) {
	features := getContainerPersistentFeatures()
	// 在不同运行环境下不保证一定有 ns_*，但至少不应返回 nil 并且不含空字符串。
	if features == nil {
		t.Fatalf("features is nil")
	}
	for i, f := range features {
		if f == "" {
			t.Fatalf("features[%d] is empty", i)
		}
	}
}

func TestGetContainerPersistentFeaturesWithConfig_PersistentVolume(t *testing.T) {
	dir := t.TempDir()
	// 用一个真实存在的目录模拟持久卷。
	pv := filepath.Join(dir, "pv")
	if err := os.MkdirAll(pv, 0o755); err != nil {
		t.Fatalf("mkdir pv: %v", err)
	}

	cfg := &ContainerBindingConfig{
		Mode:                ContainerBindingContainer,
		PreferHostHardware:  false,
		FallbackToContainer: true,
		PersistentVolume:    pv,
	}

	features := getContainerPersistentFeaturesWithConfig(cfg)
	if len(features) == 0 {
		t.Fatalf("expected non-empty features")
	}

	foundPV := false
	for _, f := range features {
		if len(f) >= 3 && (f[:3] == "pv_") {
			foundPV = true
			break
		}
	}
	if !foundPV {
		t.Fatalf("expected pv_* feature, got: %v", features)
	}
}

func TestSelectBindingStrategy_RespectsMode(t *testing.T) {
	if got := selectBindingStrategy(&ContainerBindingConfig{Mode: ContainerBindingHost}); got != "host_hardware" {
		t.Fatalf("host mode: got %q", got)
	}
	if got := selectBindingStrategy(&ContainerBindingConfig{Mode: ContainerBindingContainer}); got != "container_scoped" {
		t.Fatalf("container mode: got %q", got)
	}
}
