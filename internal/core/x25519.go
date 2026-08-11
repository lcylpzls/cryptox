package core

import (
	"encoding/hex"
	"io"
	"strings"

	"github.com/lcylpzls/errx"
	"golang.org/x/crypto/curve25519"
)

// X25519 密钥与共享密钥的标准字节长度。
const (
	// X25519PublicKeySize 公钥字节数。
	X25519PublicKeySize = 32
	// X25519PrivateKeySize 私钥字节数。
	X25519PrivateKeySize = 32
	// X25519SharedSecretSize 共享密钥字节数。
	X25519SharedSecretSize = 32
)

// GenerateX25519Key 生成 X25519 密钥对：私钥与公钥各 32 字节。
func GenerateX25519Key() (priv, pub []byte, err error) {
	priv = make([]byte, X25519PrivateKeySize)
	if _, err := io.ReadFull(randomReader, priv); err != nil {
		return nil, nil, errx.WrapCode(err, CodeRandomFailed, "生成 X25519 私钥失败")
	}
	// 基点固定为合法点，推导公钥不会失败。
	pub, _ = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, nil
}

// X25519PublicKey 从 32 字节私钥导出 32 字节公钥。
func X25519PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != X25519PrivateKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"X25519 私钥长度必须为 %d 字节，当前 %d", X25519PrivateKeySize, len(priv))
	}
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	return pub, nil
}

// X25519SharedSecret 计算 X25519 共享密钥（ECDH）。
// 双方分别使用自己的私钥与对方公钥，得到一致的 32 字节共享密钥。
func X25519SharedSecret(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != X25519PrivateKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"X25519 私钥长度必须为 %d 字节，当前 %d", X25519PrivateKeySize, len(priv))
	}
	if len(peerPub) != X25519PublicKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"X25519 公钥长度必须为 %d 字节，当前 %d", X25519PublicKeySize, len(peerPub))
	}
	secret, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "X25519 共享密钥计算失败（对方公钥可能为低阶点）")
	}
	return secret, nil
}

// ParseX25519PublicKeyHex 解析 64 字符小写/大写十六进制公钥。
func ParseX25519PublicKeyHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "公钥十六进制非法")
	}
	if len(b) != X25519PublicKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"公钥长度必须为 %d 字节，当前 %d", X25519PublicKeySize, len(b))
	}
	return b, nil
}

// ParseX25519PrivateKeyHex 解析 64 字符十六进制私钥。
func ParseX25519PrivateKeyHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "私钥十六进制非法")
	}
	if len(b) != X25519PrivateKeySize {
		return nil, errx.NewCodef(CodeInvalidKey,
			"私钥长度必须为 %d 字节，当前 %d", X25519PrivateKeySize, len(b))
	}
	return b, nil
}
