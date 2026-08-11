package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/testx"
)

func TestEd25519Roundtrip(t *testing.T) {
	priv, pub, err := GenerateEd25519Key()
	testx.RequireNoError(t, err)
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("密钥长度不匹配：priv=%d pub=%d", len(priv), len(pub))
	}
	derived, err := Ed25519PublicKey(priv)
	testx.RequireNoError(t, err)
	if !bytes.Equal(derived, pub) {
		t.Fatal("导出的公钥与生成的不一致")
	}
	msg := []byte("签名消息")
	sig, err := SignEd25519(priv, msg)
	testx.RequireNoError(t, err)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("签名长度应为 %d，得到 %d", ed25519.SignatureSize, len(sig))
	}
	if !VerifyEd25519(pub, msg, sig) {
		t.Fatal("合法签名应通过校验")
	}
	if VerifyEd25519(pub, []byte("其他消息"), sig) {
		t.Fatal("篡改消息不应通过校验")
	}
	otherPriv, otherPub, _ := GenerateEd25519Key()
	_ = otherPriv
	if VerifyEd25519(otherPub, msg, sig) {
		t.Fatal("错误公钥不应通过校验")
	}
	tampered := append([]byte(nil), sig...)
	tampered[10] ^= 0xff
	if VerifyEd25519(pub, msg, tampered) {
		t.Fatal("篡改签名不应通过校验")
	}
}

func TestEd25519InvalidInputs(t *testing.T) {
	t.Run("签名私钥长度非法", func(t *testing.T) {
		for _, priv := range [][]byte{nil, make([]byte, 31), make([]byte, 63), make([]byte, 65)} {
			_, err := SignEd25519(priv, []byte("x"))
			assertErrCode(t, err, CodeInvalidKey)
		}
	})
	t.Run("导出公钥长度非法", func(t *testing.T) {
		for _, priv := range [][]byte{nil, make([]byte, 32)} {
			_, err := Ed25519PublicKey(priv)
			assertErrCode(t, err, CodeInvalidKey)
		}
	})
	t.Run("验签公钥长度非法", func(t *testing.T) {
		priv, _, _ := GenerateEd25519Key()
		sig, _ := SignEd25519(priv, []byte("x"))
		if VerifyEd25519([]byte("短"), []byte("x"), sig) {
			t.Fatal("长度非法的公钥不应通过校验")
		}
	})
}

func TestEd25519GenerateFailure(t *testing.T) {
	old := randomReader
	randomReader = failingReader{}
	defer func() { randomReader = old }()
	_, _, err := GenerateEd25519Key()
	assertErrCode(t, err, CodeRandomFailed)
}

func TestEd25519PrivateKeyFromSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, ed25519.SeedSize)
	priv, err := Ed25519PrivateKeyFromSeed(seed)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, len(priv), ed25519.PrivateKeySize)

	stdPriv := ed25519.NewKeyFromSeed(seed)
	testx.RequireTrue(t, bytes.Equal(priv, []byte(stdPriv)))

	// 派生私钥可正常签名验签。
	msg := []byte("seed 签名")
	sig, err := SignEd25519(priv, msg)
	testx.RequireNoError(t, err)
	pub, err := Ed25519PublicKey(priv)
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, VerifyEd25519(pub, msg, sig))

	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := Ed25519PrivateKeyFromSeed(bad); err == nil {
			t.Fatal("种子长度非法应报错")
		}
	}
}

func TestParseEd25519Hex(t *testing.T) {
	priv, pub, err := GenerateEd25519Key()
	testx.RequireNoError(t, err)
	pubHex := hex.EncodeToString(pub)
	parsedPub, err := ParseEd25519PublicKeyHex(pubHex)
	testx.RequireNoError(t, err)
	if !bytes.Equal(parsedPub, pub) {
		t.Fatal("解析公钥与原始不一致")
	}
	privHex := hex.EncodeToString(priv)
	parsedPriv, err := ParseEd25519PrivateKeyHex(privHex)
	testx.RequireNoError(t, err)
	if !bytes.Equal(parsedPriv, priv) {
		t.Fatal("解析私钥与原始不一致")
	}
}

func TestParseEd25519HexErrors(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
		want errx.Code
	}{
		{"公钥非十六进制", func() error {
			_, err := ParseEd25519PublicKeyHex("zzzz")
			return err
		}, CodeInvalidKey},
		{"公钥长度错误", func() error {
			_, err := ParseEd25519PublicKeyHex(hex.EncodeToString(make([]byte, 16)))
			return err
		}, CodeInvalidKey},
		{"私钥非十六进制", func() error {
			_, err := ParseEd25519PrivateKeyHex("zzzz")
			return err
		}, CodeInvalidKey},
		{"私钥长度错误", func() error {
			_, err := ParseEd25519PrivateKeyHex(hex.EncodeToString(make([]byte, 16)))
			return err
		}, CodeInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertErrCode(t, tt.fn(), tt.want)
		})
	}
}

func TestEd25519Sizes(t *testing.T) {
	if Ed25519PublicKeySize != 32 || Ed25519PrivateKeySize != 64 ||
		Ed25519SeedSize != 32 || Ed25519SignatureSize != 64 {
		t.Fatalf("Ed25519 尺寸常量非法：pub=%d priv=%d seed=%d sig=%d",
			Ed25519PublicKeySize, Ed25519PrivateKeySize,
			Ed25519SeedSize, Ed25519SignatureSize)
	}
}
