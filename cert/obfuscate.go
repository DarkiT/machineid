package cert

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

// ObfuscatedString 混淆字符串。
//
// 用途说明：
// - 通过 XOR 对字节做轻量“扰码”，再配合 Base64 进行可打印编码；
// - 主要目的是避免敏感字符串以明文形式直接出现在源码/二进制的只读数据段中，降低被简单字符串扫描直接命中的概率；
// - 这不是密码学意义上的加密（key 也会随二进制一同分发），不要用于对抗有能力的逆向分析，只用于“去明文”。
type ObfuscatedString struct {
	data []byte
	key  byte
}

// NewObfuscatedString 创建混淆字符串。
//
// 使用 XOR + Base64 对敏感字符串进行混淆，避免明文暴露在二进制中。
func NewObfuscatedString(plaintext string) *ObfuscatedString {
	key := randomByte()
	data := make([]byte, len(plaintext))
	for i := range plaintext {
		data[i] = plaintext[i] ^ key
	}
	return &ObfuscatedString{
		data: data,
		key:  key,
	}
}

func randomByte() byte {
	// 使用 crypto/rand 生成 0~255 的随机 key，避免引入 math/rand 的全局种子等额外状态。
	n, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		// 作为“去明文”的轻量手段，随机失败时回退到固定 key，
		// 保证不因环境熵不足等原因导致功能不可用。
		return 0xA5
	}
	return byte(n.Int64())
}

// Reveal 解密混淆字符串。
func (o *ObfuscatedString) Reveal() string {
	result := make([]byte, len(o.data))
	for i := range o.data {
		result[i] = o.data[i] ^ o.key
	}
	return string(result)
}

// Encode 编码为 Base64。
func (o *ObfuscatedString) Encode() string {
	return base64.StdEncoding.EncodeToString(o.data)
}

// DecodeObfuscated 从 Base64 解码。
func DecodeObfuscated(encoded string, key byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key
	}
	return string(result), nil
}

// 预定义混淆字符串（避免明文硬编码）。
var (
	obfDebugger = &ObfuscatedString{
		data: []byte{0x64 ^ 0xAA, 0x65 ^ 0xAA, 0x62 ^ 0xAA, 0x75 ^ 0xAA, 0x67 ^ 0xAA, 0x67 ^ 0xAA, 0x65 ^ 0xAA, 0x72 ^ 0xAA},
		key:  0xAA,
	}
	obfTrace = &ObfuscatedString{
		data: []byte{0x74 ^ 0xBB, 0x72 ^ 0xBB, 0x61 ^ 0xBB, 0x63 ^ 0xBB, 0x65 ^ 0xBB},
		key:  0xBB,
	}
)

// GetDebuggerString 获取 "debugger" 字符串。
func GetDebuggerString() string {
	return obfDebugger.Reveal()
}

// GetTraceString 获取 "trace" 字符串。
func GetTraceString() string {
	return obfTrace.Reveal()
}
