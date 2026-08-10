package cryptox

import (
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
