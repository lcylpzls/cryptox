package cryptox

import (
	"bytes"
	"io"
	"testing"
)

// FuzzOpen 验证任意信封字节输入下 Open 不 panic、不越界。
func FuzzOpen(f *testing.F) {
	envelope, err := Seal(testKEK, []byte("fuzz 数据"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(envelope)
	f.Add(envelope[:10])
	f.Add([]byte("CRX1"))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xfe, 0xfd})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Open(testKEK, data)
	})
}

// FuzzDecryptStream 验证任意密文流字节输入下解密不 panic、不越界。
func FuzzDecryptStream(f *testing.F) {
	var buf bytes.Buffer
	if err := EncryptStream(testKEK, &buf, bytes.NewReader(bytes.Repeat([]byte("S"), streamChunkSize+7))); err != nil {
		f.Fatal(err)
	}
	stream := buf.Bytes()
	f.Add(stream)
	f.Add(stream[:streamHeaderSize])
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = DecryptStream(testKEK, io.Discard, bytes.NewReader(data))
	})
}

// FuzzVerifyHMAC 验证任意密钥/消息/签名输入下校验不 panic。
func FuzzVerifyHMAC(f *testing.F) {
	f.Add([]byte("key"), []byte("msg"), []byte("sig"))
	f.Add([]byte(nil), []byte(nil), []byte(nil))
	f.Fuzz(func(t *testing.T, key, msg, sig []byte) {
		_ = VerifyHMAC(key, msg, sig)
	})
}

// FuzzVerifyEd25519 验证任意公钥/消息/签名输入下验签不 panic。
func FuzzVerifyEd25519(f *testing.F) {
	priv, pub, err := GenerateEd25519Key()
	if err != nil {
		f.Fatal(err)
	}
	sig, _ := SignEd25519(priv, []byte("msg"))
	f.Add(pub, []byte("msg"), sig)
	f.Add([]byte(nil), []byte(nil), []byte(nil))
	f.Fuzz(func(t *testing.T, pub, msg, sig []byte) {
		_ = VerifyEd25519(pub, msg, sig)
	})
}
