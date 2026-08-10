package cryptox

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lcylpzls/errx"
)

var testKEK = []byte("0123456789abcdef0123456789abcdef")

func TestSealOpenRoundtrip(t *testing.T) {
	for _, plain := range [][]byte{
		nil,
		[]byte(""),
		[]byte("机密数据"),
		bytes.Repeat([]byte("A"), 1024*1024+17),
	} {
		envelope, err := Seal(testKEK, plain)
		if err != nil {
			t.Fatalf("Seal 失败：%v", err)
		}
		got, err := Open(testKEK, envelope)
		if err != nil {
			t.Fatalf("Open 失败：%v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("明文不一致：%d != %d", len(got), len(plain))
		}
	}
}

func TestSealUniqueNonce(t *testing.T) {
	a, err := Seal(testKEK, []byte("相同明文"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	b, err := Seal(testKEK, []byte("相同明文"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("两次 Seal 结果不应相同（nonce/DEK 应随机）")
	}
	pa, err := Open(testKEK, a)
	if err != nil {
		t.Fatalf("Open a 失败：%v", err)
	}
	pb, err := Open(testKEK, b)
	if err != nil {
		t.Fatalf("Open b 失败：%v", err)
	}
	if !bytes.Equal(pa, pb) {
		t.Fatal("两次 Open 明文应一致")
	}
}

func TestSealInvalidKey(t *testing.T) {
	for _, kek := range [][]byte{nil, {}, []byte("short"), bytes.Repeat([]byte("K"), 33)} {
		_, err := Seal(kek, []byte("x"))
		assertErrCode(t, err, CodeInvalidKey)
	}
}

func TestOpenInvalidKey(t *testing.T) {
	envelope, err := Seal(testKEK, []byte("x"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	for _, kek := range [][]byte{nil, []byte("short")} {
		_, err := Open(kek, envelope)
		assertErrCode(t, err, CodeInvalidKey)
	}
}

func TestOpenDifferentKey(t *testing.T) {
	envelope, err := Seal(testKEK, []byte("x"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	other := bytes.Repeat([]byte("Z"), 32)
	_, err = Open(other, envelope)
	assertErrCode(t, err, CodeDecryptFailed)
}

func TestOpenTampered(t *testing.T) {
	envelope, err := Seal(testKEK, []byte("机密数据"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	tamper := func(transform func([]byte) []byte) []byte {
		cp := append([]byte(nil), envelope...)
		return transform(cp)
	}
	tests := []struct {
		name string
		data []byte
		want errx.Code
	}{
		{"空信封", nil, CodeInvalidEnvelope},
		{"截断", envelope[:len(envelope)-1], CodeInvalidEnvelope},
		{"标识损坏", tamper(func(b []byte) []byte { b[0] = 'X'; return b }), CodeInvalidEnvelope},
		{"版本不支持", tamper(func(b []byte) []byte { b[4] = 99; return b }), CodeUnsupportedVersion},
		{"算法不支持", tamper(func(b []byte) []byte { b[5] = 99; return b }), CodeUnsupportedVersion},
		{"长度声明不一致", tamper(func(b []byte) []byte {
			b[6] = 0xff
			return b
		}), CodeInvalidEnvelope},
		{"包裹密钥篡改", tamper(func(b []byte) []byte {
			b[wrappedKeyOffset+10] ^= 0xff
			return b
		}), CodeDecryptFailed},
		{"密文篡改", tamper(func(b []byte) []byte {
			b[len(b)-1] ^= 0xff
			return b
		}), CodeDecryptFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open(testKEK, tt.data)
			assertErrCode(t, err, tt.want)
		})
	}
}

func TestSealRandomFailure(t *testing.T) {
	old := randomReader
	randomReader = failingReader{}
	defer func() { randomReader = old }()
	_, err := Seal(testKEK, []byte("x"))
	assertErrCode(t, err, CodeRandomFailed)
}

func TestEncodeEnvelopeLayout(t *testing.T) {
	envelope, err := Seal(testKEK, []byte("x"))
	if err != nil {
		t.Fatalf("Seal 失败：%v", err)
	}
	if string(envelope[:4]) != envelopeMagic {
		t.Fatalf("magic 不匹配：%q", envelope[:4])
	}
	if envelope[4] != envelopeVersion || envelope[5] != algorithmAES256GCM {
		t.Fatalf("版本/算法头不匹配：%d/%d", envelope[4], envelope[5])
	}
	payloadLen := int(envelope[6])<<24 | int(envelope[7])<<16 | int(envelope[8])<<8 | int(envelope[9])
	if payloadLen != len(envelope)-headerSize {
		t.Fatalf("payloadLen 不匹配：%d != %d", payloadLen, len(envelope)-headerSize)
	}
}

func assertErrCode(t *testing.T, err error, want errx.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望错误 %q，得到 nil", want)
	}
	if !errx.Is(err, want) {
		t.Fatalf("期望错误码 %q，得到 %v", want, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("随机数源故障")
}
