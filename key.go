package cryptox

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"github.com/lcylpzls/errx"
)

// hkdfMaxLength 是 HKDF-SHA256 单次派生的最大字节数（255 × 32）。
const hkdfMaxLength = 255 * sha256.Size

// HKDF 使用 HKDF-SHA256 从 secret 派生 length 字节密钥。
// length 必须在 1..hkdfMaxLength 范围内。
func HKDF(secret, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > hkdfMaxLength {
		return nil, errx.NewCodef(CodeInvalidArgument,
			"HKDF 派生长度必须在 1..%d，当前 %d", hkdfMaxLength, length)
	}
	// RFC 5869：提取阶段（salt 为空时使用 hashLen 个零字节）。
	var prkSalt []byte
	if len(salt) == 0 {
		prkSalt = make([]byte, sha256.Size)
	} else {
		prkSalt = salt
	}
	prk := hmacSum(prkSalt, secret)
	return hkdfExpand(prk, info, length), nil
}

// PBKDF2 使用 PBKDF2-HMAC-SHA256 从 password 派生密钥。
func PBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	if iterations <= 0 {
		return nil, errx.NewCodef(CodeInvalidArgument, "PBKDF2 迭代次数必须为正，当前 %d", iterations)
	}
	if keyLen <= 0 {
		return nil, errx.NewCodef(CodeInvalidArgument, "PBKDF2 派生长度必须为正，当前 %d", keyLen)
	}
	return pbkdf2SHA256(password, salt, iterations, keyLen), nil
}

// hmacSum 计算 HMAC-SHA256。
func hmacSum(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// hkdfExpand 是 RFC 5869 的扩展阶段：T(i) = HMAC(PRK, T(i-1) || info || i)。
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(prev)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		block := mac.Sum(nil)
		out = append(out, block...)
		prev = block
	}
	return out[:length]
}

// pbkdf2SHA256 是 RFC 8018 的 PBKDF2-HMAC-SHA256 实现。
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{
			byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block),
		})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// RandomBytes 生成 n 字节安全随机数。
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errx.NewCodef(CodeInvalidArgument, "随机数长度不能为负，当前 %d", n)
	}
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(randomReader, out); err != nil {
		return nil, errx.WrapCode(err, CodeRandomFailed, "生成安全随机数失败")
	}
	return out, nil
}

// Wipe 将切片全部清零，用于及时擦除密钥等敏感内存。
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RotateKEK 使用新主密钥重新包装信封中的数据密钥，密文保持不变。
// 适合主密钥轮换场景：无需解出明文即可换钥。
func RotateKEK(oldKEK, newKEK, envelope []byte) ([]byte, error) {
	keyNonce, dataNonce, wrapped, ciphertext, err := parseEnvelopeHeader(envelope)
	if err != nil {
		return nil, err
	}
	oldBlock, err := aes.NewCipher(oldKEK)
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "旧主密钥非法（需 16/24/32 字节）")
	}
	dek, err := openGCM(oldBlock, keyNonce, wrapped, nil)
	if err != nil {
		return nil, errx.NewCode(CodeDecryptFailed, "解密失败")
	}
	defer Wipe(dek)
	newBlock, err := aes.NewCipher(newKEK)
	if err != nil {
		return nil, errx.WrapCode(err, CodeInvalidKey, "新主密钥非法（需 16/24/32 字节）")
	}
	newKeyNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(randomReader, newKeyNonce); err != nil {
		return nil, errx.WrapCode(err, CodeRandomFailed, "生成安全随机数失败")
	}
	newWrapped := sealGCM(newBlock, newKeyNonce, dek, nil)
	return encodeEnvelope(newWrapped, newKeyNonce, dataNonce, ciphertext), nil
}
