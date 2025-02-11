package cert

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// version 语义化版本
type version struct {
	raw      string // 原始版本号字符串
	segments []int  // 版本号数字段
}

// 版本号缓存
var (
	versionCache = make(map[string]*version)
	cacheMutex   sync.RWMutex
)

// compare 提供快速比较两个版本号的静态方法
func compare(v1 string, op string, v2 string) (bool, error) {
	// 验证操作符
	switch op {
	case "<", "<=", ">", ">=", "==":
	default:
		return false, fmt.Errorf("unsupported operator: %s", op)
	}

	// 解析版本号
	ver1, err := parse(v1)
	if err != nil {
		return false, fmt.Errorf("failed to resolve version number 1: %v", err)
	}

	ver2, err := parse(v2)
	if err != nil {
		return false, fmt.Errorf("failed to resolve version number 2: %v", err)
	}

	// 根据操作符选择对应的比较方法
	switch op {
	case "<":
		return ver1.LessThan(ver2), nil
	case "<=":
		return ver1.LessThanOrEqual(ver2), nil
	case ">":
		return ver1.GreaterThan(ver2), nil
	case ">=":
		return ver1.GreaterThanOrEqual(ver2), nil
	case "==":
		return ver1.Equal(ver2), nil
	}

	return false, nil
}

// compare compare比较两个版本号的大小
//
//	返回值：
//	-1: 小于, 0: 等于, 1: 大于
func (v *version) compare(other *version) int {
	// 获取两个版本号的最大长度
	maxLen := max(len(v.segments), len(other.segments))

	// 遍历两个版本号的每个部分
	for i := 0; i < maxLen; i++ {
		// 获取当前版本号的部分
		v1 := 0
		if i < len(v.segments) {
			v1 = v.segments[i]
		}

		// 获取另一个版本号的部分
		v2 := 0
		if i < len(other.segments) {
			v2 = other.segments[i]
		}

		// 如果当前版本号的部分小于另一个版本号的部分，返回-1
		if v1 < v2 {
			return -1
		}
		// 如果当前版本号的部分大于另一个版本号的部分，返回1
		if v1 > v2 {
			return 1
		}
	}
	// 如果两个版本号相等，返回0
	return 0
}

// LessThan 判断当前版本号是否小于另一个版本号
func (v *version) LessThan(other *version) bool {
	return v.compare(other) < 0
}

// LessThanOrEqual 判断当前版本号是否小于等于另一个版本号
func (v *version) LessThanOrEqual(other *version) bool {
	return v.compare(other) <= 0
}

// GreaterThan 判断当前版本号是否大于另一个版本号
func (v *version) GreaterThan(other *version) bool {
	return v.compare(other) > 0
}

// GreaterThanOrEqual 判断当前版本号是否大于等于另一个版本号
func (v *version) GreaterThanOrEqual(other *version) bool {
	return v.compare(other) >= 0
}

// Equal 判断当前版本号是否等于另一个版本号
func (v *version) Equal(other *version) bool {
	return v.compare(other) == 0
}

// Between 判断版本号是否在指定范围内
func (v *version) Between(min, max *version) bool {
	return v.GreaterThanOrEqual(min) && v.LessThanOrEqual(max)
}

// String 返回版本号字符串
func (v *version) String() string {
	return v.raw
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// parse 解析版本号字符串
func parse(v string) (*version, error) {
	if v == "" {
		return nil, fmt.Errorf("version number cannot be empty")
	}

	// 检查缓存
	cacheMutex.RLock()
	if cached, ok := versionCache[v]; ok {
		cacheMutex.RUnlock()
		return cached, nil
	}
	cacheMutex.RUnlock()

	// 解析版本号
	parts := strings.Split(v, ".")
	segments := make([]int, len(parts))

	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid version number format: %s", v)
		}
		if num < 0 {
			return nil, fmt.Errorf("version number cannot contain negative numbers: %s", v)
		}

		segments[i] = num
	}

	ver := &version{
		raw:      v,
		segments: segments,
	}

	// 更新缓存
	cacheMutex.Lock()
	versionCache[v] = ver
	cacheMutex.Unlock()

	return ver, nil
}
