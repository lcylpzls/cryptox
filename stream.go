package cryptox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"github.com/lcylpzls/errx"
)

// 加密流 v1 格式常量。
const (
	streamVersion     = 1
	streamAlgorithm   = 1 // AES-256-GCM 分块
	streamChunkSize   = 64 * 1024
	streamHeaderSize  = 82
	streamMaxChunk    = 16 * 1024 * 1024
	streamLenFieldLen = 4
	streamTagSize     = 16
)

// EncryptStream 将 src 明文分块加密后写入 dst，头部携带
// 版本化流格式（KEK/DEK 信封 + 块计数器 nonce）。
// 内存占用有界（单块大小），适合大文件。
func EncryptStream(kek []byte, dst io.Writer, src io.Reader) error {
	return EncryptStreamWithAAD(kek, dst, src, nil)
}

// EncryptStreamWithAAD 与 EncryptStream 相同，但将 aad 绑定到每个数据块，
// 防止密文流被置换到其他用途/路径/上下文。
func EncryptStreamWithAAD(kek []byte, dst io.Writer, src io.Reader, aad []byte) error {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return errx.WrapCode(err, CodeInvalidKey, "主密钥非法（需 16/24/32 字节）")
	}
	keyNonce := make([]byte, nonceSize)
	streamNonce := make([]byte, nonceSize)
	dek := make([]byte, dekSize)
	for _, nonce := range [][]byte{keyNonce, streamNonce, dek} {
		if _, err := io.ReadFull(randomReader, nonce); err != nil {
			return errx.WrapCode(err, CodeRandomFailed, "生成安全随机数失败")
		}
	}
	wrapped := sealGCM(block, keyNonce, dek, nil)
	if err := writeStreamHeader(dst, wrapped, keyNonce, streamNonce); err != nil {
		return errx.WrapCode(err, CodeStreamWriteFailed, "写入加密流头部失败")
	}
	// DEK 固定 32 字节，aes.NewCipher 不会失败。
	dekBlock, _ := aes.NewCipher(dek)
	defer Wipe(dek)
	cw := &chunkWriter{
		block:       dekBlock,
		streamNonce: streamNonce,
		dst:         dst,
		buf:         make([]byte, 0, streamChunkSize),
		aad:         aad,
	}
	buf := make([]byte, 64*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := cw.Write(buf[:n]); werr != nil {
				return errx.WrapCode(werr, CodeStreamWriteFailed, "写入加密流失败")
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return errx.WrapCode(rerr, CodeStreamReadFailed, "读取明文失败")
		}
	}
	if err := cw.flush(); err != nil {
		return errx.WrapCode(err, CodeStreamWriteFailed, "写入加密流失败")
	}
	return nil
}

// DecryptStream 读取 EncryptStream 生成的密文流并解密写入 dst。
// 块认证失败统一返回 CodeDecryptFailed。
func DecryptStream(kek []byte, dst io.Writer, src io.Reader) error {
	return DecryptStreamWithAAD(kek, dst, src, nil)
}

// DecryptStreamWithAAD 解开 EncryptStreamWithAAD 生成的密文流；
// aad 必须与加密时一致。
func DecryptStreamWithAAD(kek []byte, dst io.Writer, src io.Reader, aad []byte) error {
	header := make([]byte, streamHeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		if errors.Is(err, io.EOF) {
			return errx.NewCode(CodeInvalidStream, "加密流头部缺失")
		}
		return errx.WrapCode(err, CodeInvalidStream, "读取加密流头部失败")
	}
	if err := validateStreamHeader(header); err != nil {
		return err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return errx.WrapCode(err, CodeInvalidKey, "主密钥非法（需 16/24/32 字节）")
	}
	dek, err := openGCM(block, header[keyNonceOffset:dataNonceOffset],
		header[wrappedKeyOffset:streamHeaderSize], nil)
	if err != nil {
		return errx.NewCode(CodeDecryptFailed, "解密失败")
	}
	// DEK 固定 32 字节，aes.NewCipher 不会失败。
	dekBlock, _ := aes.NewCipher(dek)
	defer Wipe(dek)
	streamNonce := append([]byte(nil), header[dataNonceOffset:wrappedKeyOffset]...)
	var counter uint32
	lenField := make([]byte, streamLenFieldLen)
	for {
		if _, err := io.ReadFull(src, lenField); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return errx.WrapCode(err, CodeInvalidStream, "读取块长度失败")
		}
		blockLen := int(binary.BigEndian.Uint32(lenField))
		if blockLen < streamTagSize || blockLen > streamMaxChunk+streamTagSize {
			return errx.NewCodef(CodeInvalidStream, "块长度非法：%d", blockLen)
		}
		ct := make([]byte, blockLen)
		if _, err := io.ReadFull(src, ct); err != nil {
			return errx.WrapCode(err, CodeInvalidStream, "读取块密文失败")
		}
		plain, err := openGCM(dekBlock, chunkNonce(streamNonce, counter), ct, aad)
		if err != nil {
			return errx.NewCode(CodeDecryptFailed, "解密失败")
		}
		if _, err := dst.Write(plain); err != nil {
			return errx.WrapCode(err, CodeStreamWriteFailed, "写入明文失败")
		}
		counter++
	}
}

// writeStreamHeader 写 v1 流头部。
func writeStreamHeader(w io.Writer, wrappedKey, keyNonce, streamNonce []byte) error {
	header := make([]byte, streamHeaderSize)
	copy(header[0:4], envelopeMagic)
	header[4] = streamVersion
	header[5] = streamAlgorithm
	binary.BigEndian.PutUint32(header[6:10], streamChunkSize)
	copy(header[keyNonceOffset:], keyNonce)
	copy(header[dataNonceOffset:], streamNonce)
	copy(header[wrappedKeyOffset:], wrappedKey)
	_, err := w.Write(header)
	return err
}

// validateStreamHeader 校验流头部 magic/版本/算法/块大小。
func validateStreamHeader(header []byte) error {
	if !bytes.Equal(header[:4], []byte(envelopeMagic)) {
		return errx.NewCode(CodeInvalidStream, "加密流标识不匹配")
	}
	if header[4] != streamVersion {
		return errx.NewCodef(CodeUnsupportedVersion, "不支持的流版本 %d", header[4])
	}
	if header[5] != streamAlgorithm {
		return errx.NewCodef(CodeUnsupportedVersion, "不支持的流算法 %d", header[5])
	}
	chunkSize := int(binary.BigEndian.Uint32(header[6:10]))
	if chunkSize < 1 || chunkSize > streamMaxChunk {
		return errx.NewCodef(CodeInvalidStream, "块大小非法：%d", chunkSize)
	}
	return nil
}

// chunkNonce 由流随机数与块计数器构造唯一 nonce（前 8 字节 + 4 字节计数）。
func chunkNonce(streamNonce []byte, counter uint32) []byte {
	nonce := make([]byte, nonceSize)
	copy(nonce[:8], streamNonce[:8])
	binary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

// chunkWriter 是分块加密写入器：积累到一块即加密写出。
type chunkWriter struct {
	block       cipher.Block
	streamNonce []byte
	dst         io.Writer
	buf         []byte
	counter     uint32
	aad         []byte
}

// Write 积累明文并按块加密写出。
func (w *chunkWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for len(w.buf) >= streamChunkSize {
		if err := w.writeChunk(w.buf[:streamChunkSize]); err != nil {
			return 0, err
		}
		w.buf = w.buf[streamChunkSize:]
	}
	return len(p), nil
}

// flush 加密并写出剩余不足一块的明文。
func (w *chunkWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	return w.writeChunk(w.buf)
}

// writeChunk 加密单块并写出 [4B 长度 + 密文]。
func (w *chunkWriter) writeChunk(plain []byte) error {
	ct := sealGCM(w.block, chunkNonce(w.streamNonce, w.counter), plain, w.aad)
	w.counter++
	lenField := make([]byte, streamLenFieldLen)
	binary.BigEndian.PutUint32(lenField, uint32(len(ct)))
	if _, err := w.dst.Write(lenField); err != nil {
		return err
	}
	_, err := w.dst.Write(ct)
	return err
}
