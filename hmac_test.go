package cryptox

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSignVerifyHMAC(t *testing.T) {
	key := []byte("hmac 密钥")
	msg := []byte("待签名消息")
	sig, err := SignHMAC(key, msg)
	if err != nil {
		t.Fatalf("SignHMAC 失败：%v", err)
	}
	if len(sig) != 32 {
		t.Fatalf("签名长度应为 32，得到 %d", len(sig))
	}
	if !VerifyHMAC(key, msg, sig) {
		t.Fatal("合法签名应通过校验")
	}
	if VerifyHMAC(key, []byte("篡改消息"), sig) {
		t.Fatal("篡改消息不应通过校验")
	}
	if VerifyHMAC([]byte("其他密钥"), msg, sig) {
		t.Fatal("错误密钥不应通过校验")
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if VerifyHMAC(key, msg, tampered) {
		t.Fatal("篡改签名不应通过校验")
	}
	if VerifyHMAC(key, msg, sig[:16]) {
		t.Fatal("截断签名不应通过校验")
	}
	if VerifyHMAC(nil, msg, sig) {
		t.Fatal("空密钥不应通过校验")
	}
}

func TestSignHMACEmptyKey(t *testing.T) {
	_, err := SignHMAC(nil, []byte("x"))
	assertErrCode(t, err, CodeInvalidKey)
}

func TestSignHMACEmptyMessage(t *testing.T) {
	sig, err := SignHMAC([]byte("k"), nil)
	if err != nil {
		t.Fatalf("空消息签名失败：%v", err)
	}
	if !VerifyHMAC([]byte("k"), nil, sig) {
		t.Fatal("空消息签名应通过校验")
	}
}

func TestConstantTimeEquals(t *testing.T) {
	if !ConstantTimeEquals(nil, nil) {
		t.Fatal("空切片应相等")
	}
	if !ConstantTimeEquals([]byte("abc"), []byte("abc")) {
		t.Fatal("相同内容应相等")
	}
	if ConstantTimeEquals([]byte("abc"), []byte("abd")) {
		t.Fatal("不同内容不应相等")
	}
	if ConstantTimeEquals([]byte("abc"), []byte("abcd")) {
		t.Fatal("不同长度不应相等")
	}
}

func TestSHA256(t *testing.T) {
	// 标准测试向量："abc" 的 SHA256。
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := hex.EncodeToString(SHA256([]byte("abc"))); got != want {
		t.Fatalf("SHA256 不匹配：%s", got)
	}
	if len(SHA256(nil)) != 32 {
		t.Fatalf("空数据摘要长度应为 32")
	}
}

func TestSHA256Hex(t *testing.T) {
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got, err := SHA256Hex(strings.NewReader("abc"))
	if err != nil {
		t.Fatalf("SHA256Hex 失败：%v", err)
	}
	if got != want {
		t.Fatalf("SHA256Hex 不匹配：%s", got)
	}
	got, err = SHA256Hex(strings.NewReader(""))
	if err != nil {
		t.Fatalf("SHA256Hex 空输入失败：%v", err)
	}
	if !bytes.Equal(SHA256(nil), mustHex(got)) {
		t.Fatalf("流式摘要与单次摘要不一致：%s", got)
	}
}

func TestSHA256HexReadFailure(t *testing.T) {
	_, err := SHA256Hex(failingReader{})
	assertErrCode(t, err, CodeHashFailed)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
