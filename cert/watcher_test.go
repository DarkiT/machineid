package cert

import (
	"sync"
	"testing"
	"time"

	machineid "github.com/darkit/machineid"
)

func TestCertWatcher_EmitsRevokedWhenRevoked(t *testing.T) {
	t.Parallel()

	auth, err := newTestAuthorizerBuilder(t).
		WithRuntimeVersion("test").
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	appID := "watcher-test"
	binding := &machineid.BindingResult{Hash: "TEST_MACHINE_ID", Mode: machineid.BindingModeMachineID, Provider: "test"}
	req, err := NewClientRequest().
		WithMachineID(binding.Hash).
		WithBindingResult(binding).
		WithExpiry(time.Now().Add(24*time.Hour)).
		WithCompany("Test Co", "Test Dept").
		WithMinClientVersion("0.0.0").
		WithValidityDays(1).
		Build()
	if err != nil {
		t.Fatalf("构建请求失败: %v", err)
	}
	_ = appID

	issued, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	serial, err := extractSerialNumber(issued.CertPEM)
	if err != nil {
		t.Fatalf("提取证书序列号失败: %v", err)
	}
	auth.revokeManager.mu.Lock()
	auth.revokeManager.revokeList.RevokedCerts[serial] = &RevokeInfo{SerialNumber: serial, RevokeDate: time.Now(), RevokeReason: "test"}
	auth.revokeManager.mu.Unlock()

	var (
		mu    sync.Mutex
		event WatchEvent
		got   bool
	)
	cb := func(e WatchEvent, _ *ClientInfo, _ error) {
		mu.Lock()
		defer mu.Unlock()
		event = e
		got = true
	}

	w := NewCertWatcher(auth, issued.CertPEM, binding.Hash, cb)
	w.WithConfig(&WatchConfig{CheckInterval: time.Hour, ExpiryWarningPeriod: 7 * 24 * time.Hour, EnableExpiryWarning: false, EnableRevocationCheck: true, MaxRetries: 0, RetryInterval: time.Millisecond})
	if err := w.Start(); err != nil {
		t.Fatalf("启动监控失败: %v", err)
	}
	defer w.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ready := got
		e := event
		mu.Unlock()
		if ready {
			if e != WatchEventRevoked {
				t.Fatalf("期望事件 %s, 实际 %s", WatchEventRevoked, e)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("期望收到事件回调但超时 (got=%v, event=%s)", got, event)
}

func TestCertWatcher_SecurityErrorDoesNotBecomeRevoked(t *testing.T) {
	SetSecurityErrorSanitizeEnabled(false)
	t.Cleanup(func() { SetSecurityErrorSanitizeEnabled(true) })

	auth, err := newTestAuthorizerBuilder(t).
		WithRuntimeVersion("test").
		EnableAntiDebug(true).
		WithSecurityLevel(SecurityLevelBasic).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	// 说明：无法在测试中可靠伪造各平台的 checkDebugger 行为，
	// 该用例改为覆盖内部可注入的检查器（见 cert/security_hooks.go）。
	prev := checkDebuggerFn
	checkDebuggerFn = func() bool { return true }
	t.Cleanup(func() { checkDebuggerFn = prev })

	req, err := NewClientRequest().
		WithMachineID("TEST_MACHINE_ID").
		WithExpiry(time.Now().Add(24*time.Hour)).
		WithCompany("Test Co", "Test Dept").
		WithMinClientVersion("0.0.0").
		WithValidityDays(1).
		Build()
	if err != nil {
		t.Fatalf("构建请求失败: %v", err)
	}
	issued, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	var (
		mu    sync.Mutex
		event WatchEvent
		got   bool
	)
	cb := func(e WatchEvent, _ *ClientInfo, _ error) {
		mu.Lock()
		defer mu.Unlock()
		event = e
		got = true
	}

	w := NewCertWatcher(auth, issued.CertPEM, "TEST_MACHINE_ID", cb)
	w.WithConfig(&WatchConfig{CheckInterval: time.Hour, EnableExpiryWarning: false, EnableRevocationCheck: true, MaxRetries: 0, RetryInterval: time.Millisecond})
	w.performCheck()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ready := got
		e := event
		mu.Unlock()
		if ready {
			if e == WatchEventRevoked {
				t.Fatalf("安全错误不应被误判为 revoked")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("期望收到事件回调但超时 (got=%v, event=%s)", got, event)
}

func TestCertWatcher_StatsExposeErrorTypeAndCode(t *testing.T) {
	// 依赖全局 hook，避免并行互相覆盖导致结果不稳定。
	SetSecurityErrorSanitizeEnabled(false)
	t.Cleanup(func() { SetSecurityErrorSanitizeEnabled(true) })
	// 保护全局 hook，避免其它并行测试污染导致 watcher 未触发错误
	prevVM := virtualMachineDetectorFn
	virtualMachineDetectorFn = func() bool { return false }
	t.Cleanup(func() { virtualMachineDetectorFn = prevVM })
	prevAdv := checkAdvancedDebuggerFn
	checkAdvancedDebuggerFn = func() bool { return false }
	t.Cleanup(func() { checkAdvancedDebuggerFn = prevAdv })

	auth, err := newTestAuthorizerBuilder(t).
		WithRuntimeVersion("test").
		EnableAntiDebug(true).
		WithSecurityLevel(SecurityLevelBasic).
		Build()
	if err != nil {
		t.Fatalf("创建授权管理器失败: %v", err)
	}

	prev := checkDebuggerFn
	checkDebuggerFn = func() bool { return true }
	t.Cleanup(func() { checkDebuggerFn = prev })

	req, err := NewClientRequest().
		WithMachineID("TEST_MACHINE_ID").
		WithExpiry(time.Now().Add(24*time.Hour)).
		WithCompany("Test Co", "Test Dept").
		WithMinClientVersion("0.0.0").
		WithValidityDays(1).
		Build()
	if err != nil {
		t.Fatalf("构建请求失败: %v", err)
	}
	issued, err := auth.IssueClientCert(req)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}

	w := NewCertWatcher(auth, issued.CertPEM, "TEST_MACHINE_ID", func(WatchEvent, *ClientInfo, error) {})
	w.WithConfig(&WatchConfig{CheckInterval: time.Hour, EnableExpiryWarning: false, EnableRevocationCheck: true, MaxRetries: 0, RetryInterval: time.Millisecond})
	w.performCheck()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats := w.Stats()
		if stats["last_error"] != nil {
			if stats["last_error_type"] == "" || stats["last_error_code"] == "" {
				t.Fatalf("期望 stats 暴露 last_error_type/last_error_code，但得到: %#v", stats)
			}
			if stats["last_error_details"] == nil {
				t.Fatalf("期望 stats 暴露 last_error_details，但得到: %#v", stats)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := w.Stats()
	t.Fatalf("期望产生 last_error 但超时: %#v", stats)
}
