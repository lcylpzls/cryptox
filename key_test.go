package cryptox

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHKDF(t *testing.T) {
	secret := []byte("高熵种子")
	a, err := HKDF(secret, []byte("salt"), []byte("info"), 32)
	if err != nil {
		t.Fatalf("HKDF 失败：%v", err)
	}
	b, err := HKDF(secret, []byte("salt"), []byte("info"), 32)
	if err != nil {
		t.Fatalf("HKDF 失败：%v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("相同输入派生结果应一致")
	}
	other, err := HKDF(secret, []byte("其他 salt"), []byte("info"), 32)
	if err != nil {
		t.Fatalf("HKDF 失败：%v", err)
	}
	if bytes.Equal(a, other) {
		t.Fatal("不同 salt 派生结果不应一致")
	}
	if len(a) != 32 {
		t.Fatalf("派生长度应为 32，得到 %d", len(a))
	}
	_, err = HKDF(secret, nil, nil, 1)
	if err != nil {
		t.Fatalf("nil salt/info 应支持：%v", err)
	}
}

func TestHKDFInvalidLength(t *testing.T) {
	for _, length := range []int{0, -1, hkdfMaxLength + 1} {
		_, err := HKDF([]byte("s"), nil, nil, length)
		assertErrCode(t, err, CodeInvalidArgument)
	}
}

func TestHKDFRFC5869Vector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := make([]byte, 13)
	for i := range salt {
		salt[i] = byte(i)
	}
	info := make([]byte, 10)
	for i := range info {
		info[i] = byte(0xf0 + i)
	}
	got, err := HKDF(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("HKDF 失败：%v", err)
	}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if hex.EncodeToString(got) != want {
		t.Fatalf("HKDF RFC 5869 向量不匹配：\n得到 %s\n期望 %s", hex.EncodeToString(got), want)
	}
}

func TestPBKDF2(t *testing.T) {
	a, err := PBKDF2([]byte("password"), []byte("salt"), 1000, 32)
	if err != nil {
		t.Fatalf("PBKDF2 失败：%v", err)
	}
	b, err := PBKDF2([]byte("password"), []byte("salt"), 1000, 32)
	if err != nil {
		t.Fatalf("PBKDF2 失败：%v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("相同输入派生结果应一致")
	}
	other, err := PBKDF2([]byte("password"), []byte("salt2"), 1000, 32)
	if err != nil {
		t.Fatalf("PBKDF2 失败：%v", err)
	}
	if bytes.Equal(a, other) {
		t.Fatal("不同 salt 派生结果不应一致")
	}
	if len(a) != 32 {
		t.Fatalf("派生长度应为 32，得到 %d", len(a))
	}
}

func TestPBKDF2InvalidArgs(t *testing.T) {
	_, err := PBKDF2([]byte("p"), []byte("s"), 0, 32)
	assertErrCode(t, err, CodeInvalidArgument)
	_, err = PBKDF2([]byte("p"), []byte("s"), 100, 0)
	assertErrCode(t, err, CodeInvalidArgument)
}

func TestPBKDF2RFCVector(t *testing.T) {
	got, err := PBKDF2([]byte("password"), []byte("salt"), 1, 32)
	if err != nil {
		t.Fatalf("PBKDF2 失败：%v", err)
	}
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if hex.EncodeToString(got) != want {
		t.Fatalf("PBKDF2 向量不匹配：\n得到 %s\n期望 %s", hex.EncodeToString(got), want)
	}
}

func TestRandomBytes(t *testing.T) {
	got, err := RandomBytes(16)
	if err != nil {
		t.Fatalf("RandomBytes 失败：%v", err)
	}
	if len(got) != 16 {
		t.Fatalf("长度应为 16，得到 %d", len(got))
	}
	empty, err := RandomBytes(0)
	if err != nil {
		t.Fatalf("RandomBytes(0) 失败：%v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("RandomBytes(0) 应为空，得到 %d", len(empty))
	}
	_, err = RandomBytes(-1)
	assertErrCode(t, err, CodeInvalidArgument)

	old := randomReader
	randomReader = failingReader{}
	defer func() { randomReader = old }()
	_, err = RandomBytes(8)
	assertErrCode(t, err, CodeRandomFailed)
}

func TestWipe(t *testing.T) {
	b := []byte("敏感密钥材料")
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("Wipe 后第 %d 字节未清零：%d", i, v)
		}
	}
	Wipe(nil)
}

func TestRotateKEK(t *testing.T) {
	oldKEK := bytes.Repeat([]byte("O"), 32)
	newKEK := bytes.Repeat([]byte("N"), 32)
	plain := []byte("轮换测试数据")
	envelope, err := Seal(oldKEK, plain)
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	rotated, err := RotateKEK(oldKEK, newKEK, envelope)
	if err != nil {
		t.Fatalf("RotateKEK 失败：%v", err)
	}
	if bytes.Equal(rotated, envelope) {
		t.Fatal("轮换后信封不应与原来相同")
	}
	got, err := Open(newKEK, rotated)
	if err != nil {
		t.Fatalf("新密钥 Open 失败：%v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("轮换后明文不一致")
	}
	_, err = Open(oldKEK, rotated)
	assertErrCode(t, err, CodeDecryptFailed)
}

func TestRotateKEKErrors(t *testing.T) {
	oldKEK := bytes.Repeat([]byte("O"), 32)
	envelope, err := Seal(oldKEK, []byte("x"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	t.Run("旧密钥非法", func(t *testing.T) {
		_, err := RotateKEK(nil, oldKEK, envelope)
		assertErrCode(t, err, CodeInvalidKey)
	})
	t.Run("新密钥非法", func(t *testing.T) {
		_, err := RotateKEK(oldKEK, []byte("短"), envelope)
		assertErrCode(t, err, CodeInvalidKey)
	})
	t.Run("信封非法", func(t *testing.T) {
		_, err := RotateKEK(oldKEK, oldKEK, []byte("坏"))
		assertErrCode(t, err, CodeInvalidEnvelope)
	})
	t.Run("旧密钥错误", func(t *testing.T) {
		_, err := RotateKEK(bytes.Repeat([]byte("X"), 32), oldKEK, envelope)
		assertErrCode(t, err, CodeDecryptFailed)
	})
	t.Run("随机失败", func(t *testing.T) {
		old := randomReader
		randomReader = failingReader{}
		defer func() { randomReader = old }()
		_, err := RotateKEK(oldKEK, oldKEK, envelope)
		assertErrCode(t, err, CodeRandomFailed)
	})
	t.Run("版本不支持", func(t *testing.T) {
		bad := append([]byte(nil), envelope...)
		bad[4] = 99
		_, err := RotateKEK(oldKEK, oldKEK, bad)
		assertErrCode(t, err, CodeUnsupportedVersion)
	})
}

func TestRotateKEKTamperedCiphertext(t *testing.T) {
	oldKEK := bytes.Repeat([]byte("O"), 32)
	envelope, err := Seal(oldKEK, []byte("x"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	// 轮换不验证数据密文，篡改数据密文后轮换应成功但新密钥解密失败。
	bad := append([]byte(nil), envelope...)
	bad[len(bad)-1] ^= 0xff
	rotated, err := RotateKEK(oldKEK, bytes.Repeat([]byte("N"), 32), bad)
	if err != nil {
		t.Fatalf("轮换应不校验数据密文：%v", err)
	}
	_, err = Open(bytes.Repeat([]byte("N"), 32), rotated)
	assertErrCode(t, err, CodeDecryptFailed)
}
