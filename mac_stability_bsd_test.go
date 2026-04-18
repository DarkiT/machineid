//go:build freebsd || openbsd || netbsd || dragonfly || solaris
// +build freebsd openbsd netbsd dragonfly solaris

package machineid

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestInferInterfaceStabilityPlatform_BSD_VirtualPrefix(t *testing.T) {
	stubBsdCommandOutput(t, func(string, ...string) ([]byte, error) {
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "lo0"}
	if inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected loopback to be unstable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_SysctlStable(t *testing.T) {
	stubBsdCommandOutput(t, func(name string, args ...string) ([]byte, error) {
		if name == "sysctl" && len(args) == 2 && args[0] == "-n" && strings.Contains(args[1], ".iftype") {
			return []byte("6\n"), nil
		}
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "em0"}
	if !inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected sysctl ethernet iftype to be stable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_SysctlLoopback(t *testing.T) {
	stubBsdCommandOutput(t, func(name string, args ...string) ([]byte, error) {
		if name == "sysctl" && len(args) == 2 && args[0] == "-n" && strings.Contains(args[1], ".iftype") {
			return []byte("24\n"), nil
		}
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "em1"}
	if inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected loopback iftype to be unstable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_IfconfigStable(t *testing.T) {
	stubBsdCommandOutput(t, func(name string, args ...string) ([]byte, error) {
		if name == "sysctl" {
			return nil, fmt.Errorf("not found")
		}
		if name == "ifconfig" && len(args) == 1 && args[0] == "re0" {
			return []byte("\tmedia: Ethernet autoselect\n\tstatus: active\n"), nil
		}
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "re0"}
	if !inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected ifconfig ethernet media to be stable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_IfconfigEncapStable(t *testing.T) {
	stubBsdCommandOutput(t, func(name string, args ...string) ([]byte, error) {
		if name == "sysctl" {
			return nil, fmt.Errorf("not found")
		}
		if name == "ifconfig" && len(args) == 1 && args[0] == "fxp0" {
			return []byte("fxp0: flags=\n\tencap: Ethernet\n\tstatus: active\n"), nil
		}
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "fxp0"}
	if !inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected ifconfig encap ethernet to be stable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_IfconfigVirtual(t *testing.T) {
	stubBsdCommandOutput(t, func(name string, args ...string) ([]byte, error) {
		if name == "sysctl" {
			return nil, fmt.Errorf("not found")
		}
		if name == "ifconfig" && len(args) == 1 && args[0] == "tap0" {
			return []byte("\tflags=\n\tmedia: Ethernet autoselect\n\tvirtual\n"), nil
		}
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "tap0"}
	if inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected virtual interface to be unstable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_IfconfigStatusActive(t *testing.T) {
	stubBsdCommandOutput(t, func(name string, args ...string) ([]byte, error) {
		if name == "sysctl" {
			return nil, fmt.Errorf("not found")
		}
		if name == "ifconfig" && len(args) == 1 && args[0] == "em3" {
			return []byte("\tstatus: active\n"), nil
		}
		return nil, fmt.Errorf("unexpected call")
	})

	iface := net.Interface{Name: "em3"}
	if !inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected active status to be stable")
	}
}

func TestInferInterfaceStabilityPlatform_BSD_IfconfigFallbackTrue(t *testing.T) {
	stubBsdCommandOutput(t, func(string, ...string) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	})

	iface := net.Interface{Name: "em2"}
	if !inferInterfaceStabilityPlatform(iface) {
		t.Fatalf("expected fallback to be stable when no info")
	}
}
