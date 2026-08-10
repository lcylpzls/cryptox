package core

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"

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

// SignHMACWithHash 使用指定哈希算法（SHA1/SHA256/SHA512）对消息签名。
// key 必须非空；算法不受支持时返回错误。
func SignHMACWithHash(hashName string, key, msg []byte) ([]byte, error) {
	hf, err := hmacHashFunc(hashName)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errx.NewCode(CodeInvalidKey, "HMAC 密钥不能为空")
	}
	mac := hmac.New(hf, key)
	_, _ = mac.Write(msg)
	return mac.Sum(nil), nil
}

// VerifyHMACWithHash 使用指定哈希算法常量时间校验 HMAC 签名。
// key 为空、算法不受支持或签名不匹配时返回 false。
func VerifyHMACWithHash(hashName string, key, msg, sig []byte) bool {
	if len(key) == 0 {
		return false
	}
	want, err := SignHMACWithHash(hashName, key, msg)
	if err != nil {
		return false
	}
	return ConstantTimeEquals(want, sig)
}

// hmacHashFunc 返回哈希算法对应的构造器，只允许 SHA1/SHA256/SHA512。
func hmacHashFunc(hashName string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.TrimSpace(hashName)) {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, errx.NewCodef(CodeInvalidArgument,
			"不支持的 HMAC 哈希算法：%s（仅支持 SHA1/SHA256/SHA512）", hashName)
	}
}

// ConstantTimeEquals 常量时间比较两个字节切片。
// 长度不同也立即返回 false，不泄露前缀信息。
func ConstantTimeEquals(a, b []byte) bool {
	return hmac.Equal(a, b)
}
