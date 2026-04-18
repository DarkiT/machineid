//go:build !windows

package cert

func isDebugPortPresent() bool { return false }

func isDebugObjectPresent() bool { return false }

func isDebugFlagsSuspicious() bool { return false }
