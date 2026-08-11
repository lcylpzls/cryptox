package core

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lcylpzls/testx"
)

// TestGenerateX25519Key 覆盖 X25519 密钥生成与公钥推导。
func TestGenerateX25519Key(t *testing.T) {
	priv, pub, err := GenerateX25519Key()
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, len(priv), X25519PrivateKeySize)
	testx.RequireEqual(t, len(pub), X25519PublicKeySize)

	derived, err := X25519PublicKey(priv)
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, bytes.Equal(pub, derived))
}

// TestX25519KeyExchange 覆盖双方 ECDH 得到一致共享密钥。
func TestX25519KeyExchange(t *testing.T) {
	alicePriv, alicePub, err := GenerateX25519Key()
	testx.RequireNoError(t, err)
	bobPriv, bobPub, err := GenerateX25519Key()
	testx.RequireNoError(t, err)

	s1, err := X25519SharedSecret(alicePriv, bobPub)
	testx.RequireNoError(t, err)
	s2, err := X25519SharedSecret(bobPriv, alicePub)
	testx.RequireNoError(t, err)

	testx.RequireEqual(t, len(s1), X25519SharedSecretSize)
	testx.RequireTrue(t, bytes.Equal(s1, s2))
}

// TestX25519RFC7748Vector 覆盖 RFC 7748 官方测试向量。
func TestX25519RFC7748Vector(t *testing.T) {
	alicePriv := mustDecodeHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustDecodeHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustDecodeHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustDecodeHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	want := mustDecodeHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	gotPub, err := X25519PublicKey(alicePriv)
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, bytes.Equal(gotPub, alicePub))

	secret, err := X25519SharedSecret(alicePriv, bobPub)
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, bytes.Equal(secret, want))

	secret2, err := X25519SharedSecret(bobPriv, alicePub)
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, bytes.Equal(secret2, want))
}

// TestX25519Errors 覆盖密钥长度、随机源与低阶点错误分支。
func TestX25519Errors(t *testing.T) {
	old := randomReader
	randomReader = failingReader{}
	_, _, err := GenerateX25519Key()
	randomReader = old
	testx.RequireError(t, err)

	if _, err := X25519PublicKey(make([]byte, 31)); err == nil {
		t.Fatal("私钥长度错误应报错")
	}
	if _, err := X25519SharedSecret(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("私钥长度错误应报错")
	}
	if _, err := X25519SharedSecret(make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("公钥长度错误应报错")
	}
	// 全零公钥为低阶点，计算共享密钥应报错。
	if _, err := X25519SharedSecret(make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("低阶点公钥应报错")
	}
}

// TestParseX25519Hex 覆盖十六进制公钥/私钥解析。
func TestParseX25519Hex(t *testing.T) {
	priv, pub, err := GenerateX25519Key()
	testx.RequireNoError(t, err)

	gotPub, err := ParseX25519PublicKeyHex(hex.EncodeToString(pub))
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, bytes.Equal(gotPub, pub))

	gotPriv, err := ParseX25519PrivateKeyHex(hex.EncodeToString(priv))
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, bytes.Equal(gotPriv, priv))

	if _, err := ParseX25519PublicKeyHex("zz"); err == nil {
		t.Fatal("非法十六进制应报错")
	}
	if _, err := ParseX25519PublicKeyHex(hex.EncodeToString(make([]byte, 31))); err == nil {
		t.Fatal("公钥长度错误应报错")
	}
	if _, err := ParseX25519PrivateKeyHex("zz"); err == nil {
		t.Fatal("非法十六进制应报错")
	}
	if _, err := ParseX25519PrivateKeyHex(hex.EncodeToString(make([]byte, 31))); err == nil {
		t.Fatal("长度错误应报错")
	}
}

// mustHex 将十六进制字符串解析为字节切片（测试辅助）。
func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	testx.RequireNoError(t, err)
	return b
}
