package cryptox

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"

	"github.com/lcylpzls/errx"
)

// Ed25519 密钥与签名的标准字节长度。
const (
	// Ed25519PublicKeySize 公钥字节数。
	Ed25519PublicKeySize = ed25519.PublicKeySize
	// Ed25519PrivateKeySize 私钥字节数（种子 + 公钥）。
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	// Ed25519SeedSize 私钥种子字节数。
	Ed25519SeedSize = ed25519.SeedSize
	// Ed25519SignatureSize 签名字节数。
	Ed25519SignatureSize = ed25519.SignatureSize
)

// GenerateEd25519Key 生成 Ed25519 密钥对：
// 私钥 64 字节（种子 + 公钥），公钥 32 字节。
func GenerateEd25519Key() (priv, pub []byte, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(randomReader)
	if err != nil {
		return nil, nil, errx.WrapCode(err, CodeRandomFailed, "生成 Ed25519 密钥失败")
	}
	return []byte(privKey), []byte(pubKey), nil
}

// SignEd25519 使用 Ed25519 私钥对消息签名，返回 64 字节签名。
// 私钥必须为 64 字节。
func SignEd25519(priv, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"Ed25519 私钥长度必须为 %d 字节，当前 %d", ed25519.PrivateKeySize, len(priv))
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), msg), nil
}

// VerifyEd25519 使用 Ed25519 公钥验签；公钥长度非法或签名不匹配返回 false。
func VerifyEd25519(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// Ed25519PublicKey 从 64 字节私钥导出 32 字节公钥。
func Ed25519PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"Ed25519 私钥长度必须为 %d 字节，当前 %d", ed25519.PrivateKeySize, len(priv))
	}
	return append([]byte(nil), priv[ed25519.SeedSize:]...), nil
}

// ParseEd25519PublicKeyHex 解析 64 字符小写/大写十六进制公钥。
func ParseEd25519PublicKeyHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "公钥十六进制非法")
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"公钥长度必须为 %d 字节，当前 %d", ed25519.PublicKeySize, len(b))
	}
	return b, nil
}

// ParseEd25519PrivateKeyHex 解析 128 字符十六进制私钥。
func ParseEd25519PrivateKeyHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "私钥十六进制非法")
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"私钥长度必须为 %d 字节，当前 %d", ed25519.PrivateKeySize, len(b))
	}
	return b, nil
}
