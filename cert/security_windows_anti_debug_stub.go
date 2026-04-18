//go:build !windows

package cert

func hasHardwareBreakpoints() bool { return false }
var isBeingDebuggedByPEB = func() bool { return false }
