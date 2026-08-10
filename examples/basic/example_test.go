package basic_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lcylpzls/cryptox"
	"github.com/lcylpzls/testx"
)

func TestExampleSealOpen(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	envelope, err := cryptox.Seal(kek, []byte("机密数据"))
	testx.RequireNoError(t, err)
	plain, err := cryptox.Open(kek, envelope)
	testx.RequireNoError(t, err)
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
	testx.RequireNoError(t, err)
	if !cryptox.VerifyHMAC(kek, []byte("消息"), sig) {
		t.Fatal("HMAC 校验失败")
	}
	digest, err := cryptox.SHA256Hex(strings.NewReader("abc"))
	testx.RequireNoError(t, err)
	if len(digest) != 64 {
		t.Fatalf("摘要长度应为 64，得到 %d", len(digest))
	}

	priv, pub, err := cryptox.GenerateEd25519Key()
	testx.RequireNoError(t, err)
	sig, err = cryptox.SignEd25519(priv, []byte("消息"))
	testx.RequireNoError(t, err)
	if !cryptox.VerifyEd25519(pub, []byte("消息"), sig) {
		t.Fatal("Ed25519 校验失败")
	}

	derived, err := cryptox.HKDF(kek, nil, []byte("派生"), 32)
	testx.RequireNoError(t, err)
	if len(derived) != 32 {
		t.Fatalf("HKDF 派生长度应为 32，得到 %d", len(derived))
	}
	rotated, err := cryptox.RotateKEK(kek, bytes.Repeat([]byte("Z"), 32), envelope)
	testx.RequireNoError(t, err)
	plain2, err := cryptox.Open(bytes.Repeat([]byte("Z"), 32), rotated)
	testx.RequireNoError(t, err)
	if !bytes.Equal(plain2, []byte("机密数据")) {
		t.Fatalf("轮换后明文不匹配：%q", plain2)
	}
	fields := cryptox.AuditFields(cryptox.OperationOpen, "AES-256-GCM", len(envelope), nil)
	if fields.Len() != 3 {
		t.Fatalf("审计字段数量应为 3，得到 %d", fields.Len())
	}

	var aadStream bytes.Buffer
	if err := cryptox.EncryptStreamWithAAD(kek, &aadStream, bytes.NewReader([]byte("带上下文数据")), []byte("backup")); err != nil {
		t.Fatalf("EncryptStreamWithAAD 失败：%v", err)
	}
	var aadPlain bytes.Buffer
	if err := cryptox.DecryptStreamWithAAD(kek, &aadPlain, bytes.NewReader(aadStream.Bytes()), []byte("backup")); err != nil {
		t.Fatalf("DecryptStreamWithAAD 失败：%v", err)
	}
	if aadPlain.String() != "带上下文数据" {
		t.Fatalf("AAD 流明文不匹配：%q", aadPlain.String())
	}
}
