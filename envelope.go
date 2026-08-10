package cryptox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/lcylpzls/errx"
)

// 信封 v1 格式常量。
const (
	envelopeMagic      = "CRX1"
	envelopeVersion    = 1
	algorithmAES256GCM = 1

	dekSize    = 32
	nonceSize  = 12
	headerSize = 10 // magic(4) + version(1) + algorithm(1) + payloadLen(4)

	keyNonceOffset   = headerSize
	dataNonceOffset  = keyNonceOffset + nonceSize
	wrappedKeyOffset = dataNonceOffset + nonceSize
	wrappedKeySize   = dekSize + 16 // DEK + GCM tag
	envelopeHeader   = wrappedKeyOffset + wrappedKeySize
)

// randomReader 是安全随机数源，可注入便于测试失败分支。
var randomReader io.Reader = rand.Reader

// Seal 使用主密钥 kek 对明文进行信封加密：
// 生成随机 DEK（32 字节）并用 kek 包装，再用 DEK 加密数据，
// 返回自包含的版本化信封。相同明文两次结果不同。
// kek 必须是 16/24/32 字节的 AES 密钥，推荐 32 字节。
func Seal(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "主密钥非法（需 16/24/32 字节）")
	}
	keyNonce := make([]byte, nonceSize)
	dataNonce := make([]byte, nonceSize)
	dek := make([]byte, dekSize)
	for _, dst := range [][]byte{keyNonce, dataNonce, dek} {
		if _, err := io.ReadFull(randomReader, dst); err != nil {
			return nil, errx.WrapCode(err, CodeRandomFailed, "生成安全随机数失败")
		}
	}
	wrapped := sealGCM(block, keyNonce, dek, nil)
	// DEK 固定 32 字节，aes.NewCipher 不会失败。
	dekBlock, _ := aes.NewCipher(dek)
	ciphertext := sealGCM(dekBlock, dataNonce, plaintext, nil)
	return encodeEnvelope(wrapped, keyNonce, dataNonce, ciphertext), nil
}

// Open 解开 Seal 生成的信封并返回明文。
// 解密失败统一返回 CodeDecryptFailed，不区分密钥错误与篡改。
func Open(kek, envelope []byte) ([]byte, error) {
	if len(envelope) < envelopeHeader {
		return nil, errx.NewCode(CodeInvalidEnvelope, "信封长度不足")
	}
	if !bytes.Equal(envelope[:4], []byte(envelopeMagic)) {
		return nil, errx.NewCode(CodeInvalidEnvelope, "信封标识不匹配")
	}
	if envelope[4] != envelopeVersion {
		return nil, errx.NewCodef(CodeUnsupportedVersion, "不支持的信封版本 %d", envelope[4])
	}
	if envelope[5] != algorithmAES256GCM {
		return nil, errx.NewCodef(CodeUnsupportedVersion, "不支持的加密算法 %d", envelope[5])
	}
	payloadLen := int(binary.BigEndian.Uint32(envelope[6:10]))
	if payloadLen != len(envelope)-headerSize {
		return nil, errx.NewCode(CodeInvalidEnvelope, "信封长度与声明不一致")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "主密钥非法（需 16/24/32 字节）")
	}
	dek, err := openGCM(block, envelope[keyNonceOffset:dataNonceOffset],
		envelope[wrappedKeyOffset:envelopeHeader], nil)
	if err != nil {
		return nil, errx.NewCode(CodeDecryptFailed, "解密失败")
	}
	// DEK 固定 32 字节，aes.NewCipher 不会失败。
	dekBlock, _ := aes.NewCipher(dek)
	plain, err := openGCM(dekBlock, envelope[dataNonceOffset:wrappedKeyOffset],
		envelope[envelopeHeader:], nil)
	if err != nil {
		return nil, errx.NewCode(CodeDecryptFailed, "解密失败")
	}
	return plain, nil
}

// encodeEnvelope 按 v1 格式编码信封。
func encodeEnvelope(wrappedKey, keyNonce, dataNonce, ciphertext []byte) []byte {
	payloadLen := len(wrappedKey) + len(keyNonce) + len(dataNonce) + len(ciphertext)
	out := make([]byte, envelopeHeader+len(ciphertext))
	copy(out[0:4], envelopeMagic)
	out[4] = envelopeVersion
	out[5] = algorithmAES256GCM
	binary.BigEndian.PutUint32(out[6:10], uint32(payloadLen))
	copy(out[keyNonceOffset:], keyNonce)
	copy(out[dataNonceOffset:], dataNonce)
	copy(out[wrappedKeyOffset:], wrappedKey)
	copy(out[envelopeHeader:], ciphertext)
	return out
}

// sealGCM 使用 GCM 加密并返回密文+标签。
// AES 块大小固定 16 字节，cipher.NewGCM 不会失败。
func sealGCM(block cipher.Block, nonce, plaintext, aad []byte) []byte {
	aead, _ := cipher.NewGCM(block)
	return aead.Seal(nil, nonce, plaintext, aad)
}

// openGCM 使用 GCM 解密并校验认证标签。
func openGCM(block cipher.Block, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, _ := cipher.NewGCM(block)
	return aead.Open(nil, nonce, ciphertext, aad)
}
