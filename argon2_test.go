package cryptox

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lcylpzls/errx"
)

func TestArgon2IDRoundtrip(t *testing.T) {
	password := []byte("家庭式套件测试密码")
	salt := bytes.Repeat([]byte{0x5a}, 16)
	key, err := Argon2ID(password, salt, 8, 1, 1, 32)
	if err != nil {
		t.Fatalf("Argon2ID 派生失败：%v", err)
	}
	if len(key) != 32 {
		t.Fatalf("派生密钥长度应为 32，当前 %d", len(key))
	}
	other, err := Argon2ID(password, salt, 8, 1, 1, 32)
	if err != nil {
		t.Fatalf("Argon2ID 重复派生失败：%v", err)
	}
	if !bytes.Equal(key, other) {
		t.Fatal("相同参数派生结果不一致")
	}
	// 与 RFC 9106 已知向量一致：相同参数结果确定且可复现。
	if Argon2Version != 19 {
		t.Fatalf("Argon2 版本号应为 19，当前 %d", Argon2Version)
	}
}

func TestArgon2IDRFC9106Vector(t *testing.T) {
	// RFC 9106 / x/crypto 官方向量：password="password"、salt="somesalt"、
	// t=2、m=64 KiB、p=1、keyLen=24。
	key, err := Argon2ID(
		[]byte("password"), []byte("somesalt"), 64, 2, 1, 24)
	if err != nil {
		t.Fatalf("Argon2ID 派生失败：%v", err)
	}
	want := "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("官方向量不匹配：got=%s want=%s", got, want)
	}
}

func TestArgon2IDInvalidArgs(t *testing.T) {
	password := []byte("密码")
	salt := bytes.Repeat([]byte{1}, 16)
	cases := []struct {
		name        string
		memory      uint32
		iterations  uint32
		parallelism uint8
		keyLen      uint32
	}{
		{"内存过小", 7, 1, 1, 32},
		{"时间成本为零", 8, 0, 1, 32},
		{"并行度为零", 8, 1, 0, 32},
		{"派生长度为零", 8, 1, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Argon2ID(password, salt, tc.memory, tc.iterations, tc.parallelism, tc.keyLen)
			if err == nil || !errx.Is(err, CodeInvalidArgument) {
				t.Fatalf("应返回参数非法错误，当前 %v", err)
			}
		})
	}
}
