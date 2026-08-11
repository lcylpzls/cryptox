package cryptox_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/lcylpzls/cryptox"
	"github.com/lcylpzls/errx"
)

// TestPublicAPI 黑盒冒烟测试：覆盖根包全部转发函数与常量。
func TestPublicAPI(t *testing.T) {
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	plain := []byte("秘密数据")

	env, err := cryptox.Seal(kek, plain)
	if err != nil || len(env) == 0 {
		t.Fatalf("Seal 失败：%v", err)
	}
	got, err := cryptox.Open(kek, env)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open 失败：%v", err)
	}
	aad := []byte("aad")
	env2, _ := cryptox.SealWithAAD(kek, plain, aad)
	got2, _ := cryptox.OpenWithAAD(kek, env2, aad)
	if !bytes.Equal(got2, plain) {
		t.Fatal("SealWithAAD/OpenWithAAD 往返失败")
	}

	var buf bytes.Buffer
	if err := cryptox.EncryptStream(kek, &buf, bytes.NewReader(plain)); err != nil {
		t.Fatalf("EncryptStream 失败：%v", err)
	}
	var out bytes.Buffer
	if err := cryptox.DecryptStream(kek, &out, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("DecryptStream 失败：%v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatal("流加密往返失败")
	}
	buf.Reset()
	_ = cryptox.EncryptStreamWithAAD(kek, &buf, bytes.NewReader(plain), aad)
	out.Reset()
	_ = cryptox.DecryptStreamWithAAD(kek, &out, bytes.NewReader(buf.Bytes()), aad)

	_ = cryptox.AuditFields(cryptox.OperationSeal, "aes-256-gcm", 1, errx.New(errx.KindBusiness, errx.Code("smoke"), "冒烟"))

	priv, pub, err := cryptox.GenerateEd25519Key()
	if err != nil || len(priv) == 0 || len(pub) == 0 {
		t.Fatalf("GenerateEd25519Key 失败：%v", err)
	}
	sig, _ := cryptox.SignEd25519(priv, plain)
	if !cryptox.VerifyEd25519(pub, plain, sig) {
		t.Fatal("VerifyEd25519 失败")
	}
	pub2, _ := cryptox.Ed25519PublicKey(priv)
	if !bytes.Equal(pub, pub2) {
		t.Fatal("Ed25519PublicKey 不一致")
	}
	privHex := bytes.NewBuffer(nil)
	_ = privHex
	_, _ = cryptox.ParseEd25519PrivateKeyHex("00")
	_, _ = cryptox.ParseEd25519PublicKeyHex("00")

	_, _ = cryptox.Argon2ID([]byte("pwd"), []byte("salt"), 64*1024, 3, 2, 32)
	dk, _ := cryptox.HKDF([]byte("secret"), []byte("salt"), []byte("info"), 32)
	if len(dk) != 32 {
		t.Fatal("HKDF 长度错误")
	}
	_, _ = cryptox.PBKDF2([]byte("pwd"), []byte("salt"), 1000, 32)
	rb, _ := cryptox.RandomBytes(16)
	if len(rb) != 16 {
		t.Fatal("RandomBytes 长度错误")
	}
	cryptox.Wipe(rb)

	env3, _ := cryptox.Seal(kek, plain)
	rotated, err := cryptox.RotateKEK(kek, make([]byte, 32), env3)
	if err != nil || len(rotated) == 0 {
		t.Fatalf("RotateKEK 失败：%v", err)
	}

	h := cryptox.NewSHA256()
	_ = h
	sum := cryptox.SHA256(plain)
	if len(sum) != 32 {
		t.Fatal("SHA256 长度错误")
	}
	hex, _ := cryptox.SHA256Hex(bytes.NewReader(plain))
	if hex == "" {
		t.Fatal("SHA256Hex 为空")
	}

	mac, _ := cryptox.SignHMAC(kek, plain)
	if !cryptox.VerifyHMAC(kek, plain, mac) {
		t.Fatal("VerifyHMAC 失败")
	}
	mac2, _ := cryptox.SignHMACWithHash("sha256", kek, plain)
	if !cryptox.VerifyHMACWithHash("sha256", kek, plain, mac2) {
		t.Fatal("VerifyHMACWithHash 失败")
	}
	if !cryptox.ConstantTimeEquals(plain, plain) {
		t.Fatal("ConstantTimeEquals 失败")
	}

	_ = cryptox.Ed25519PublicKeySize
	_ = cryptox.Ed25519PrivateKeySize
	_ = cryptox.Ed25519SeedSize
	_ = cryptox.Ed25519SignatureSize
	_ = cryptox.OperationOpen
	_ = cryptox.OperationEncryptStream
	_ = cryptox.OperationDecryptStream
	_ = cryptox.OperationSignHMAC
	_ = cryptox.OperationVerifyHMAC
	_ = cryptox.OperationSignEd25519
	_ = cryptox.OperationVerifyEd25519
	_ = cryptox.OperationDeriveKey
	_ = cryptox.OperationRotateKEK
	_ = cryptox.CodeInvalidKey
	_ = cryptox.Argon2Version
}
