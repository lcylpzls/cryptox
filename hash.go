package cryptox

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/lcylpzls/errx"
)

// SHA256 计算字节切片的 SHA256 摘要（32 字节）。
func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// SHA256Hex 流式计算 r 的 SHA256 摘要并返回小写十六进制字符串。
// 适合大文件边读边哈希。
func SHA256Hex(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", errx.WrapCode(err, CodeHashFailed, "计算摘要失败")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
