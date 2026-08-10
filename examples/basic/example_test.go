package basic_test

import (
	"bytes"
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
}
