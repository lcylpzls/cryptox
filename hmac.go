package cryptox

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/lcylpzls/errx"
)

// SignHMAC 使用 HMAC-SHA256 对消息签名，返回 32 字节签名。
// key 必须非空。
func SignHMAC(key, msg []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errx.NewCode(CodeInvalidKey, "HMAC 密钥不能为空")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(msg)
	return mac.Sum(nil), nil
}

// VerifyHMAC 使用常量时间比较校验 HMAC-SHA256 签名。
// key 为空或签名不匹配时返回 false。
func VerifyHMAC(key, msg, sig []byte) bool {
	if len(key) == 0 {
		return false
	}
	// key 非空时 SignHMAC 不会失败。
	want, _ := SignHMAC(key, msg)
	return ConstantTimeEquals(want, sig)
}

// ConstantTimeEquals 常量时间比较两个字节切片。
// 长度不同也立即返回 false，不泄露前缀信息。
func ConstantTimeEquals(a, b []byte) bool {
	return hmac.Equal(a, b)
}
