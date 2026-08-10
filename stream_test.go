package cryptox

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/lcylpzls/errx"
)

func TestStreamRoundtrip(t *testing.T) {
	sizes := []int{0, 1, 1024, streamChunkSize, streamChunkSize + 1, 3*streamChunkSize + 17, 1<<20 + 7}
	for _, size := range sizes {
		plain := bytes.Repeat([]byte("S"), size)
		stream := streamOf(t, plain)
		var got bytes.Buffer
		if err := DecryptStream(testKEK, &got, bytes.NewReader(stream)); err != nil {
			t.Fatalf("size=%d DecryptStream 失败：%v", size, err)
		}
		if !bytes.Equal(got.Bytes(), plain) {
			t.Fatalf("size=%d 明文不一致", size)
		}
	}
}

func TestStreamUniqueNonce(t *testing.T) {
	a := streamOf(t, []byte("相同数据"))
	b := streamOf(t, []byte("相同数据"))
	if bytes.Equal(a, b) {
		t.Fatal("两次加密流不应相同")
	}
}

func TestStreamWithAAD(t *testing.T) {
	aad := []byte("stream:backup-2026")
	plain := bytes.Repeat([]byte("A"), streamChunkSize+17)
	var stream bytes.Buffer
	if err := EncryptStreamWithAAD(testKEK, &stream, bytes.NewReader(plain), aad); err != nil {
		t.Fatalf("EncryptStreamWithAAD 失败：%v", err)
	}
	var got bytes.Buffer
	if err := DecryptStreamWithAAD(testKEK, &got, bytes.NewReader(stream.Bytes()), aad); err != nil {
		t.Fatalf("DecryptStreamWithAAD 失败：%v", err)
	}
	if !bytes.Equal(got.Bytes(), plain) {
		t.Fatal("AAD 流明文不一致")
	}
	err := DecryptStreamWithAAD(testKEK, io.Discard, bytes.NewReader(stream.Bytes()), []byte("其他上下文"))
	assertErrCode(t, err, CodeDecryptFailed)
	err = DecryptStream(testKEK, io.Discard, bytes.NewReader(stream.Bytes()))
	assertErrCode(t, err, CodeDecryptFailed)
}

func TestStreamAADNilEquivalent(t *testing.T) {
	var withAAD bytes.Buffer
	if err := EncryptStreamWithAAD(testKEK, &withAAD, bytes.NewReader([]byte("x")), nil); err != nil {
		t.Fatalf("EncryptStreamWithAAD 失败：%v", err)
	}
	var got bytes.Buffer
	if err := DecryptStream(testKEK, &got, bytes.NewReader(withAAD.Bytes())); err != nil {
		t.Fatalf("aad 为 nil 时应可用 DecryptStream 解开：%v", err)
	}
	if got.String() != "x" {
		t.Fatalf("明文不匹配：%q", got.String())
	}
}

func TestRotateKEKWithAAD(t *testing.T) {
	aad := []byte("object:orders/10086")
	oldKEK := bytes.Repeat([]byte("O"), 32)
	newKEK := bytes.Repeat([]byte("N"), 32)
	envelope, err := SealWithAAD(oldKEK, []byte("机密数据"), aad)
	if err != nil {
		t.Fatalf("SealWithAAD 失败：%v", err)
	}
	rotated, err := RotateKEK(oldKEK, newKEK, envelope)
	if err != nil {
		t.Fatalf("RotateKEK 失败：%v", err)
	}
	plain, err := OpenWithAAD(newKEK, rotated, aad)
	if err != nil {
		t.Fatalf("轮换后 OpenWithAAD 失败：%v", err)
	}
	if string(plain) != "机密数据" {
		t.Fatalf("明文不匹配：%q", plain)
	}
}

func TestStreamInvalidKey(t *testing.T) {
	for _, kek := range [][]byte{nil, []byte("short")} {
		var buf bytes.Buffer
		err := EncryptStream(kek, &buf, bytes.NewReader([]byte("x")))
		assertErrCode(t, err, CodeInvalidKey)
	}
	stream := streamOf(t, []byte("x"))
	for _, kek := range [][]byte{nil, []byte("short")} {
		err := DecryptStream(kek, io.Discard, bytes.NewReader(stream))
		assertErrCode(t, err, CodeInvalidKey)
	}
}

func TestStreamDifferentKey(t *testing.T) {
	stream := streamOf(t, []byte("x"))
	other := bytes.Repeat([]byte("Z"), 32)
	err := DecryptStream(other, io.Discard, bytes.NewReader(stream))
	assertErrCode(t, err, CodeDecryptFailed)
}

func TestStreamTampered(t *testing.T) {
	stream := streamOf(t, bytes.Repeat([]byte("D"), streamChunkSize+100))
	tamper := func(transform func([]byte) []byte) []byte {
		cp := append([]byte(nil), stream...)
		return transform(cp)
	}
	tests := []struct {
		name string
		data []byte
		want errx.Code
	}{
		{"空流", nil, CodeInvalidStream},
		{"头部截断", stream[:20], CodeInvalidStream},
		{"标识损坏", tamper(func(b []byte) []byte { b[0] = 'X'; return b }), CodeInvalidStream},
		{"版本不支持", tamper(func(b []byte) []byte { b[4] = 99; return b }), CodeUnsupportedVersion},
		{"算法不支持", tamper(func(b []byte) []byte { b[5] = 99; return b }), CodeUnsupportedVersion},
		{"块大小非法", tamper(func(b []byte) []byte { b[6] = 0xff; return b }), CodeInvalidStream},
		{"块长度过大", tamper(func(b []byte) []byte {
			b[streamHeaderSize] = 0xff
			return b
		}), CodeInvalidStream},
		{"块长度过小", tamper(func(b []byte) []byte {
			for i := 0; i < 4; i++ {
				b[streamHeaderSize+i] = 0
			}
			return b
		}), CodeInvalidStream},
		{"密文篡改", tamper(func(b []byte) []byte {
			b[len(b)-1] ^= 0xff
			return b
		}), CodeDecryptFailed},
		{"尾部截断", stream[:len(stream)-5], CodeInvalidStream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecryptStream(testKEK, io.Discard, bytes.NewReader(tt.data))
			assertErrCode(t, err, tt.want)
		})
	}
}

func TestStreamRandomFailure(t *testing.T) {
	old := randomReader
	randomReader = failingReader{}
	defer func() { randomReader = old }()
	err := EncryptStream(testKEK, io.Discard, bytes.NewReader([]byte("x")))
	assertErrCode(t, err, CodeRandomFailed)
}

func TestStreamReadFailure(t *testing.T) {
	err := EncryptStream(testKEK, io.Discard, failingReader{})
	assertErrCode(t, err, CodeStreamReadFailed)
}

func TestStreamWriteFailure(t *testing.T) {
	t.Run("头部写入失败", func(t *testing.T) {
		err := EncryptStream(testKEK, failingWriter{}, bytes.NewReader([]byte("x")))
		assertErrCode(t, err, CodeStreamWriteFailed)
	})
	t.Run("块写入失败", func(t *testing.T) {
		err := EncryptStream(testKEK, &failAfterWriter{remaining: 1}, bytes.NewReader(bytes.Repeat([]byte("B"), streamChunkSize+1)))
		assertErrCode(t, err, CodeStreamWriteFailed)
	})
	t.Run("尾块写入失败", func(t *testing.T) {
		err := EncryptStream(testKEK, &failAfterWriter{remaining: 4}, bytes.NewReader(bytes.Repeat([]byte("C"), streamChunkSize+100)))
		assertErrCode(t, err, CodeStreamWriteFailed)
	})
	t.Run("解密写出失败", func(t *testing.T) {
		stream := streamOf(t, []byte("x"))
		err := DecryptStream(testKEK, failingWriter{}, bytes.NewReader(stream))
		assertErrCode(t, err, CodeStreamWriteFailed)
	})
	t.Run("块长度读取失败", func(t *testing.T) {
		stream := streamOf(t, []byte("x"))
		err := DecryptStream(testKEK, io.Discard, errAtEOFReader{r: bytes.NewReader(stream)})
		assertErrCode(t, err, CodeInvalidStream)
	})
}

func TestChunkNonceUnique(t *testing.T) {
	nonce := bytes.Repeat([]byte("N"), nonceSize)
	if bytes.Equal(chunkNonce(nonce, 0), chunkNonce(nonce, 1)) {
		t.Fatal("不同计数器的块 nonce 不应相同")
	}
}

func TestChunkWriterFlushEmpty(t *testing.T) {
	cw := &chunkWriter{dst: io.Discard}
	if err := cw.flush(); err != nil {
		t.Fatalf("空缓冲区 flush 不应失败：%v", err)
	}
}

func streamOf(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := EncryptStream(testKEK, &buf, bytes.NewReader(plain)); err != nil {
		t.Fatalf("EncryptStream 失败：%v", err)
	}
	return buf.Bytes()
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("写入失败")
}

type failAfterWriter struct {
	remaining int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("写入失败")
	}
	w.remaining--
	return len(p), nil
}

// errAtEOFReader 在底层 EOF 时返回普通错误，覆盖非 EOF 的读取失败分支。
type errAtEOFReader struct {
	r io.Reader
}

func (r errAtEOFReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if errors.Is(err, io.EOF) && n == 0 {
		return 0, errors.New("读取出错")
	}
	return n, err
}
