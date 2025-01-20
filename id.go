// Package machineid provides support for reading the unique machine id of most OSs (without admin privileges).
//
// https://github.com/darkit/machineid
//
// https://godoc.org/github.com/darkit/machineid/cmd/machineid
//
// This package is Cross-Platform (tested on Win7+, Debian 8+, Ubuntu 14.04+, OS X 10.6+, FreeBSD 11+)
// and does not use any internal hardware IDs (no MAC, BIOS, or CPU).
//
// Returned machine IDs are generally stable for the OS installation
// and usually stay the same after updates or hardware changes.
//
// This package allows sharing of machine IDs in a secure way by
// calculating HMAC-SHA256 over a user provided app ID, which is keyed by the machine id.
//
// Caveat: Image-based environments have usually the same machine-id (perfect clone).
// Linux users can generate a new id with `dbus-uuidgen` and put the id into
// `/var/lib/dbus/machine-id` and `/etc/machine-id`.
// Windows users can use the `sysprep` toolchain to create images, which produce valid images ready for distribution.
package machineid // import "github.com/darkit/machineid"

import (
	"fmt"
	"net"
)

// ID returns the platform specific machine id of the current host OS.
// Regard the returned id as "confidential" and consider using ProtectedID() instead.
func ID() (string, error) {
	id, err := machineID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}
	return id, nil
}

// ProtectedID returns a hashed version of the machine ID in a cryptographically secure way,
// using a fixed, application-specific key.
// Internally, this function calculates HMAC-SHA256 of the application ID, keyed by the machine ID.
func ProtectedID(appID string) (string, error) {
	id, err := ID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}
	return protect(fmt.Sprintf("%s/%s", appID, getMACAddr()), id), nil
}

// 获取网卡 MAC 地址，返回所有物理网卡中MAC地址最小的那个
func getMACAddr() (macAddr string) {
	// 获取所有网络接口
	ifas, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// 用于存储找到的最小MAC地址
	var minMACAddr string

	// 遍历所有网卡
	for _, iface := range ifas {
		// 过滤条件：
		// 1. 不是回环接口 (FlagLoopback)
		// 2. 有MAC地址
		// 3. 接口处于开启状态 (FlagUp)
		// 4. 不是虚拟接口 (FlagPointToPoint)
		if iface.Flags&net.FlagLoopback == 0 && // 不是回环接口
			iface.HardwareAddr != nil && // 有MAC地址
			iface.Flags&net.FlagUp != 0 && // 接口是启用的
			iface.Flags&net.FlagPointToPoint == 0 && // 不是点对点接口（虚拟接口）
			len(iface.HardwareAddr.String()) > 0 { // MAC地址长度大于0

			currentMAC := iface.HardwareAddr.String()

			// 如果是第一个找到的MAC地址，或者当前MAC地址小于已存储的最小值
			if minMACAddr == "" || currentMAC < minMACAddr {
				minMACAddr = currentMAC
			}
		}
	}
	return minMACAddr
}
