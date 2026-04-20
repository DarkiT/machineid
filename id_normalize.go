package machineid

import "strings"

// normalizeMachineIDValue 统一机器码、容器 ID 与派生结果的比较格式。
func normalizeMachineIDValue(value string) string {
	return strings.ToUpper(trim(value))
}
