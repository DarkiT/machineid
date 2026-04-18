package cert

// 为了在单元测试中可控地验证安全语义（例如 watcher 不应把安全错误误判为 revoked），
// 将平台检测函数通过可注入的函数变量间接调用。
//
// 生产环境保持默认指向各平台的 checkDebugger / checkAdvancedDebugger 实现。

var (
	checkDebuggerFn              = func() bool { return checkDebugger() }
	checkAdvancedDebuggerFn      = checkAdvancedDebugger
	virtualMachineDetectorFn     func() bool
	hardwareBreakpointDetectorFn = hasHardwareBreakpoints
	debugPortDetectorFn          = isDebugPortPresent
	debugObjectDetectorFn        = isDebugObjectPresent
	debugFlagsDetectorFn         = isDebugFlagsSuspicious
)

func init() {
	virtualMachineDetectorFn = func() bool {
		sm := &SecurityManager{level: SecurityLevelAdvanced}
		return sm.DetectVirtualMachine()
	}
}
