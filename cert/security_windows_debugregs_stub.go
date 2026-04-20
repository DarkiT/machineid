//go:build windows && !amd64 && !386

package cert

// hasHardwareBreakpoints 在暂未实现调试寄存器探测的 Windows 架构上返回 false。
// 当前精确实现仅覆盖 amd64 与 386，其他架构至少保证可编译与行为可回退。
func hasHardwareBreakpoints() bool { return false }
