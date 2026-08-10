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

func TestSignHMACWithHashAllAlgorithms(t *testing.T) {
	key := []byte("hmac 密钥")
	msg := []byte("待签名消息")
	sizes := map[string]int{"SHA1": 20, "SHA256": 32, "SHA512": 64}
	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			sig, err := SignHMACWithHash(name, key, msg)
			if err != nil {
				t.Fatalf("SignHMACWithHash(%s) 失败：%v", name, err)
			}
			if len(sig) != size {
				t.Fatalf("签名长度应为 %d，得到 %d", size, len(sig))
			}
			if !VerifyHMACWithHash(name, key, msg, sig) {
				t.Fatal("合法签名应通过校验")
			}
			if VerifyHMACWithHash(name, key, msg, sig[:size-1]) {
				t.Fatal("截断签名不应通过校验")
			}
			if VerifyHMACWithHash(name, key, []byte("篡改"), sig) {
				t.Fatal("篡改消息不应通过校验")
			}
		})
	}
	// 大小写与首尾空白应被容忍。
	sig, err := SignHMACWithHash(" sha1 ", key, msg)
	if err != nil {
		t.Fatalf("大小写/空白归一失败：%v", err)
	}
	if !VerifyHMACWithHash("SHA1", key, msg, sig) {
		t.Fatal("归一化算法名签名应通过校验")
	}
}

func TestSignHMACWithHashErrors(t *testing.T) {
	_, err := SignHMACWithHash("MD5", []byte("k"), []byte("m"))
	assertErrCode(t, err, CodeInvalidArgument)
	_, err = SignHMACWithHash("SHA256", nil, []byte("m"))
	assertErrCode(t, err, CodeInvalidKey)
	if VerifyHMACWithHash("MD5", []byte("k"), []byte("m"), []byte("x")) {
		t.Fatal("不支持算法应返回 false")
	}
	if VerifyHMACWithHash("SHA256", nil, []byte("m"), []byte("x")) {
		t.Fatal("空密钥应返回 false")
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

func TestNewSHA256(t *testing.T) {
	h := NewSHA256()
	if _, err := h.Write([]byte("abc")); err != nil {
		t.Fatalf("流式写入失败：%v", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("流式 SHA256 不匹配：%s", got)
	}
	// 新实例互不影响。
	h2 := NewSHA256()
	if _, err := h2.Write([]byte("x")); err != nil {
		t.Fatalf("第二个实例写入失败：%v", err)
	}
	if !bytes.Equal(h.Sum(nil), SHA256([]byte("abc"))) {
		t.Fatal("流式摘要应与单次摘要一致")
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
