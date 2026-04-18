package cert

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRevokeManager_NewRevokeManager(t *testing.T) {
	t.Parallel()

	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	if rm.currentVer != "1.0.0" {
		t.Errorf("版本号不匹配: 期望 1.0.0, 实际 %s", rm.currentVer)
	}

	if rm.revokeList == nil {
		t.Error("吊销列表不应为 nil")
	}

	if rm.revokeList.RevokedCerts == nil {
		t.Error("吊销证书映射不应为 nil")
	}
}

func TestRevokeManager_AddAndCheckRevocation(t *testing.T) {
	t.Parallel()

	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	serial := "ABC123"
	reason := "测试吊销"

	// 添加吊销
	rm.AddRevocation(serial, reason)

	// 检查是否被吊销
	revoked, revokeReason := rm.IsRevoked(serial)
	if !revoked {
		t.Error("证书应该被标记为已吊销")
	}
	if revokeReason != reason {
		t.Errorf("吊销原因不匹配: 期望 %s, 实际 %s", reason, revokeReason)
	}

	// 检查未吊销的证书
	revoked, _ = rm.IsRevoked("NOT_REVOKED")
	if revoked {
		t.Error("未吊销的证书不应被标记为已吊销")
	}
}

func TestRevokeManager_RemoveRevocation(t *testing.T) {
	t.Parallel()

	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	serial := "ABC123"
	rm.AddRevocation(serial, "测试")

	// 确认已吊销
	revoked, _ := rm.IsRevoked(serial)
	if !revoked {
		t.Fatal("证书应该被标记为已吊销")
	}

	// 移除吊销
	rm.RemoveRevocation(serial)

	// 确认已移除
	revoked, _ = rm.IsRevoked(serial)
	if revoked {
		t.Error("吊销记录应该已被移除")
	}
}

func TestRevokeManager_GetRevokeList(t *testing.T) {
	t.Parallel()

	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	rm.AddRevocation("SERIAL1", "原因1")
	rm.AddRevocation("SERIAL2", "原因2")

	list := rm.GetRevokeList()

	if len(list.RevokedCerts) != 2 {
		t.Errorf("吊销列表长度不匹配: 期望 2, 实际 %d", len(list.RevokedCerts))
	}

	// 验证返回的是副本
	list.RevokedCerts["SERIAL3"] = &RevokeInfo{SerialNumber: "SERIAL3"}
	originalList := rm.GetRevokeList()
	if len(originalList.RevokedCerts) != 2 {
		t.Error("GetRevokeList 应该返回副本，不应影响原始数据")
	}
}

func TestRevokeManager_WithRevokeList(t *testing.T) {
	t.Parallel()

	revokeList := RevokeList{
		UpdateTime: time.Now(),
		MinVersion: "1.0.0",
		RevokedCerts: map[string]*RevokeInfo{
			"SERIAL1": {SerialNumber: "SERIAL1", RevokeReason: "测试"},
		},
	}

	data, err := json.Marshal(revokeList)
	if err != nil {
		t.Fatalf("序列化吊销列表失败: %v", err)
	}

	rm, err := NewRevokeManager("1.0.0", WithRevokeList(data))
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	revoked, _ := rm.IsRevoked("SERIAL1")
	if !revoked {
		t.Error("从初始列表加载的证书应该被标记为已吊销")
	}
}

func TestRevokeManager_MinVersionCheck(t *testing.T) {
	t.Parallel()

	revokeList := RevokeList{
		UpdateTime:   time.Now(),
		MinVersion:   "2.0.0",
		RevokedCerts: map[string]*RevokeInfo{},
	}

	data, err := json.Marshal(revokeList)
	if err != nil {
		t.Fatalf("序列化吊销列表失败: %v", err)
	}

	rm, err := NewRevokeManager("1.0.0", WithRevokeList(data))
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	// 版本过低应该被视为吊销
	revoked, reason := rm.IsRevoked("ANY_SERIAL")
	if !revoked {
		t.Error("版本过低的客户端应该被拒绝")
	}
	if reason != "program version too old" {
		t.Errorf("吊销原因不匹配: 期望 'program version too old', 实际 '%s'", reason)
	}
}

func TestRevokeManager_AutoUpdate(t *testing.T) {
	t.Parallel()

	var updateCount int32
	updater := func() ([]byte, error) {
		atomic.AddInt32(&updateCount, 1)
		list := RevokeList{
			UpdateTime:   time.Now(),
			MinVersion:   "1.0.0",
			RevokedCerts: map[string]*RevokeInfo{},
		}
		return json.Marshal(list)
	}

	rm, err := NewRevokeManager("1.0.0", WithRevokeListUpdater(updater))
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	config := &AutoUpdateConfig{
		Interval:      50 * time.Millisecond,
		RetryInterval: 10 * time.Millisecond,
		MaxRetries:    1,
	}

	err = rm.StartAutoUpdate(config)
	if err != nil {
		t.Fatalf("启动自动更新失败: %v", err)
	}

	if !rm.IsAutoUpdateRunning() {
		t.Error("自动更新应该正在运行")
	}

	// 等待几次更新
	time.Sleep(200 * time.Millisecond)

	rm.StopAutoUpdate()

	if rm.IsAutoUpdateRunning() {
		t.Error("自动更新应该已停止")
	}

	count := atomic.LoadInt32(&updateCount)
	if count < 2 {
		t.Errorf("更新次数不足: 期望 >= 2, 实际 %d", count)
	}
}

func TestRevokeManager_AutoUpdateWithCallback(t *testing.T) {
	t.Parallel()

	var (
		mu          sync.Mutex
		callbackErr error
		callCount   int
	)

	updater := func() ([]byte, error) {
		list := RevokeList{
			UpdateTime:   time.Now(),
			MinVersion:   "1.0.0",
			RevokedCerts: map[string]*RevokeInfo{},
		}
		return json.Marshal(list)
	}

	rm, err := NewRevokeManager("1.0.0", WithRevokeListUpdater(updater))
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	config := &AutoUpdateConfig{
		Interval:      50 * time.Millisecond,
		RetryInterval: 10 * time.Millisecond,
		MaxRetries:    1,
		OnUpdate: func(oldTime, newTime time.Time, err error) {
			mu.Lock()
			defer mu.Unlock()
			callbackErr = err
			callCount++
		},
	}

	err = rm.StartAutoUpdate(config)
	if err != nil {
		t.Fatalf("启动自动更新失败: %v", err)
	}

	time.Sleep(150 * time.Millisecond)
	rm.StopAutoUpdate()

	mu.Lock()
	defer mu.Unlock()

	if callbackErr != nil {
		t.Errorf("回调收到意外错误: %v", callbackErr)
	}

	if callCount < 1 {
		t.Errorf("回调调用次数不足: 期望 >= 1, 实际 %d", callCount)
	}
}

func TestRevokeManager_AutoUpdateRetry(t *testing.T) {
	t.Parallel()

	var attemptCount int32
	updater := func() ([]byte, error) {
		count := atomic.AddInt32(&attemptCount, 1)
		if count <= 2 {
			return nil, errors.New("模拟失败")
		}
		list := RevokeList{
			UpdateTime:   time.Now(),
			MinVersion:   "1.0.0",
			RevokedCerts: map[string]*RevokeInfo{},
		}
		return json.Marshal(list)
	}

	rm, err := NewRevokeManager("1.0.0", WithRevokeListUpdater(updater))
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	var (
		mu         sync.Mutex
		lastErr    error
		successCnt int
	)

	config := &AutoUpdateConfig{
		Interval:      100 * time.Millisecond,
		RetryInterval: 10 * time.Millisecond,
		MaxRetries:    3,
		OnUpdate: func(oldTime, newTime time.Time, err error) {
			mu.Lock()
			defer mu.Unlock()
			lastErr = err
			if err == nil {
				successCnt++
			}
		},
	}

	err = rm.StartAutoUpdate(config)
	if err != nil {
		t.Fatalf("启动自动更新失败: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	rm.StopAutoUpdate()

	mu.Lock()
	defer mu.Unlock()

	// 应该在重试后成功
	if successCnt < 1 {
		t.Errorf("重试后应该成功至少一次, lastErr=%v, successCnt=%d", lastErr, successCnt)
	}
}

func TestRevokeManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 10
	const operations = 100

	// 并发添加
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				serial := "SERIAL_" + string(rune('A'+id)) + "_" + string(rune('0'+j%10))
				rm.AddRevocation(serial, "并发测试")
			}
		}(i)
	}

	// 并发检查
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				serial := "SERIAL_" + string(rune('A'+id)) + "_" + string(rune('0'+j%10))
				rm.IsRevoked(serial)
			}
		}(i)
	}

	// 并发获取列表
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				rm.GetRevokeList()
			}
		}()
	}

	wg.Wait()
}

func TestRevokeManager_DoubleStartStop(t *testing.T) {
	t.Parallel()

	updater := func() ([]byte, error) {
		list := RevokeList{UpdateTime: time.Now(), RevokedCerts: map[string]*RevokeInfo{}}
		return json.Marshal(list)
	}

	rm, err := NewRevokeManager("1.0.0", WithRevokeListUpdater(updater))
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	config := DefaultAutoUpdateConfig()
	config.Interval = 100 * time.Millisecond

	// 第一次启动
	err = rm.StartAutoUpdate(config)
	if err != nil {
		t.Fatalf("第一次启动失败: %v", err)
	}

	// 重复启动应该返回错误
	err = rm.StartAutoUpdate(config)
	if err == nil {
		t.Error("重复启动应该返回错误")
	}

	rm.StopAutoUpdate()

	// 重复停止不应 panic
	rm.StopAutoUpdate()
}

func TestRevokeManager_UpdateWithoutUpdater(t *testing.T) {
	t.Parallel()

	rm, err := NewRevokeManager("1.0.0")
	if err != nil {
		t.Fatalf("创建吊销管理器失败: %v", err)
	}

	err = rm.UpdateRevokeList()
	if err == nil {
		t.Error("没有配置更新函数时应该返回错误")
	}

	err = rm.StartAutoUpdate(nil)
	if err == nil {
		t.Error("没有配置更新函数时启动自动更新应该返回错误")
	}
}
