package basic_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lcylpzls/cryptox"
)

func TestExampleSealOpen(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	envelope, err := cryptox.Seal(kek, []byte("机密数据"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	plain, err := cryptox.Open(kek, envelope)
	if err != nil {
		t.Fatalf("Open 失败：%v", err)
	}
	if !bytes.Equal(plain, []byte("机密数据")) {
		t.Fatalf("明文不匹配：%q", plain)
	}

	var stream bytes.Buffer
	if err := cryptox.EncryptStream(kek, &stream, bytes.NewReader([]byte("大文件内容"))); err != nil {
		t.Fatalf("EncryptStream 失败：%v", err)
	}
	var decrypted bytes.Buffer
	if err := cryptox.DecryptStream(kek, &decrypted, bytes.NewReader(stream.Bytes())); err != nil {
		t.Fatalf("DecryptStream 失败：%v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), []byte("大文件内容")) {
		t.Fatalf("流式明文不匹配：%q", decrypted.String())
	}

	sig, err := cryptox.SignHMAC(kek, []byte("消息"))
	if err != nil {
		t.Fatalf("SignHMAC 失败：%v", err)
	}
	if !cryptox.VerifyHMAC(kek, []byte("消息"), sig) {
		t.Fatal("HMAC 校验失败")
	}
	digest, err := cryptox.SHA256Hex(strings.NewReader("abc"))
	if err != nil {
		t.Fatalf("SHA256Hex 失败：%v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("摘要长度应为 64，得到 %d", len(digest))
	}

	priv, pub, err := cryptox.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key 失败：%v", err)
	}
	sig, err = cryptox.SignEd25519(priv, []byte("消息"))
	if err != nil {
		t.Fatalf("SignEd25519 失败：%v", err)
	}
	if !cryptox.VerifyEd25519(pub, []byte("消息"), sig) {
		t.Fatal("Ed25519 校验失败")
	}

	derived, err := cryptox.HKDF(kek, nil, []byte("派生"), 32)
	if err != nil {
		t.Fatalf("HKDF 失败：%v", err)
	}
	if len(derived) != 32 {
		t.Fatalf("HKDF 派生长度应为 32，得到 %d", len(derived))
	}
	rotated, err := cryptox.RotateKEK(kek, bytes.Repeat([]byte("Z"), 32), envelope)
	if err != nil {
		t.Fatalf("RotateKEK 失败：%v", err)
	}
	plain2, err := cryptox.Open(bytes.Repeat([]byte("Z"), 32), rotated)
	if err != nil {
		t.Fatalf("轮换后 Open 失败：%v", err)
	}
	if !bytes.Equal(plain2, []byte("机密数据")) {
		t.Fatalf("轮换后明文不匹配：%q", plain2)
	}
}
