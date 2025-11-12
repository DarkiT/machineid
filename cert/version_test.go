package cert

import "testing"

// TestCompareOperators 覆盖 compare 的常见操作符
func TestCompareOperators(t *testing.T) {
	t.Parallel()

	cases := []struct {
		v1  string
		op  string
		v2  string
		val bool
	}{
		{"1.0.0", "==", "1.0", true},
		{"1.0.1", ">", "1.0.0", true},
		{"2.0", ">=", "2.0.0", true},
		{"1.2.3", "<", "1.3.0", true},
		{"1.2.3", "<=", "1.2.3", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.op+tc.v1+tc.v2, func(t *testing.T) {
			got, err := compare(tc.v1, tc.op, tc.v2)
			if err != nil {
				t.Fatalf("比较报错: %v", err)
			}
			if got != tc.val {
				t.Fatalf("比较结果不符合预期: %v vs %v", got, tc.val)
			}
		})
	}

	if _, err := compare("1.0.0", "!", "1.0.1"); err == nil {
		t.Fatalf("非法操作符应报错")
	}
}

// TestVersionParseCachesResult 确认解析结果会缓存复用
func TestVersionParseCachesResult(t *testing.T) {
	t.Parallel()

	v1, err := parse("3.4.5")
	if err != nil {
		t.Fatalf("首次解析失败: %v", err)
	}
	v2, err := parse("3.4.5")
	if err != nil {
		t.Fatalf("缓存解析失败: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("同一版本应复用缓存实例")
	}
}

// TestVersionBetween 验证 Between 逻辑
func TestVersionBetween(t *testing.T) {
	t.Parallel()

	v, _ := parse("1.5.0")
	min, _ := parse("1.0.0")
	max, _ := parse("2.0.0")
	if !v.Between(min, max) {
		t.Fatalf("版本应介于区间内")
	}

	min2, _ := parse("1.6.0")
	if v.Between(min2, max) {
		t.Fatalf("超出下限时不应返回 true")
	}
}
