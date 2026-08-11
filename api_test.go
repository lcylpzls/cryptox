package cryptox_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"

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
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	seedPriv, err := cryptox.Ed25519PrivateKeyFromSeed(seed)
	if err != nil || len(seedPriv) != cryptox.Ed25519PrivateKeySize {
		t.Fatalf("Ed25519PrivateKeyFromSeed 失败：%v", err)
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
	hexStr, _ := cryptox.SHA256Hex(bytes.NewReader(plain))
	if hexStr == "" {
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

	xpriv, xpub, err := cryptox.GenerateX25519Key()
	if err != nil || len(xpriv) != cryptox.X25519PrivateKeySize || len(xpub) != cryptox.X25519PublicKeySize {
		t.Fatalf("GenerateX25519Key 失败：%v", err)
	}
	xpub2, err := cryptox.X25519PublicKey(xpriv)
	if err != nil || !bytes.Equal(xpub, xpub2) {
		t.Fatalf("X25519PublicKey 不一致：%v", err)
	}
	xpriv2, xpub3, err := cryptox.GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key 失败：%v", err)
	}
	xs1, err := cryptox.X25519SharedSecret(xpriv, xpub3)
	if err != nil {
		t.Fatalf("X25519SharedSecret 失败：%v", err)
	}
	xs2, err := cryptox.X25519SharedSecret(xpriv2, xpub)
	if err != nil {
		t.Fatalf("X25519SharedSecret 失败：%v", err)
	}
	if len(xs1) != cryptox.X25519SharedSecretSize || !bytes.Equal(xs1, xs2) {
		t.Fatal("X25519 共享密钥不一致")
	}
	_, _ = cryptox.ParseX25519PublicKeyHex(hex.EncodeToString(xpub))
	_, _ = cryptox.ParseX25519PrivateKeyHex(hex.EncodeToString(xpriv))

	certPEM, keyPEM, err := cryptox.SelfSignedCert("localhost",
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, 1)
	if err != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("SelfSignedCert 失败：%v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("证书加载失败：%v", err)
	}
	_, _, err = cryptox.SelfSignedCertWithOptions("localhost", nil, nil, 1,
		cryptox.WithCertAlgorithm(cryptox.CertAlgorithmECDSA),
		cryptox.WithCertClock(time.Now),
	)
	if err != nil {
		t.Fatalf("SelfSignedCertWithOptions 失败：%v", err)
	}

	_ = cryptox.Ed25519PublicKeySize
	_ = cryptox.Ed25519PrivateKeySize
	_ = cryptox.Ed25519SeedSize
	_ = cryptox.Ed25519SignatureSize
	_ = cryptox.X25519PublicKeySize
	_ = cryptox.X25519PrivateKeySize
	_ = cryptox.X25519SharedSecretSize
	_ = cryptox.OperationOpen
	_ = cryptox.OperationEncryptStream
	_ = cryptox.OperationDecryptStream
	_ = cryptox.OperationSignHMAC
	_ = cryptox.OperationVerifyHMAC
	_ = cryptox.OperationSignEd25519
	_ = cryptox.OperationVerifyEd25519
	_ = cryptox.OperationDeriveEd25519
	_ = cryptox.OperationGenerateX25519
	_ = cryptox.OperationX25519SharedSecret
	_ = cryptox.OperationGenerateCert
	_ = cryptox.CodeCertFailed
	_ = cryptox.CertAlgorithmEd25519
	_ = cryptox.CertAlgorithmECDSA
	var _ cryptox.CertAlgorithm
	var _ cryptox.CertOption
	_ = cryptox.OperationDeriveKey
	_ = cryptox.OperationRotateKEK
	_ = cryptox.CodeInvalidKey
	_ = cryptox.Argon2Version
}
