package core

import (
	"bytes"
	"testing"
)

// BenchmarkSealOpen 基准：小数据信封加解密。
func BenchmarkSealOpen(b *testing.B) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	plain := []byte("机密数据")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		envelope, err := Seal(kek, plain)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Open(kek, envelope); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptStream1MB 基准：1 MiB 分块流式加密。
func BenchmarkEncryptStream1MB(b *testing.B) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	data := bytes.Repeat([]byte("S"), 1<<20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := EncryptStream(kek, discardWriter{}, bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignVerifyHMAC 基准：HMAC 签名与验签。
func BenchmarkSignVerifyHMAC(b *testing.B) {
	key := []byte("hmac 密钥")
	msg := []byte("消息")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sig, err := SignHMAC(key, msg)
		if err != nil {
			b.Fatal(err)
		}
		if !VerifyHMAC(key, msg, sig) {
			b.Fatal("验签失败")
		}
	}
}

// BenchmarkPBKDF2 基准：PBKDF2-HMAC-SHA256（1000 次迭代）。
func BenchmarkPBKDF2(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := PBKDF2([]byte("password"), []byte("salt"), 1000, 32); err != nil {
			b.Fatal(err)
		}
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
