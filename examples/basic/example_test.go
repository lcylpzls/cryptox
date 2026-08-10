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
}
