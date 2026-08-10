package cryptox

import (
	"github.com/lcylpzls/errx"
	"golang.org/x/crypto/argon2"
)

// Argon2Version 是当前实现的 Argon2 版本号（v=19，对应 Argon2id 标准编码）。
const Argon2Version = argon2.Version

// Argon2ID 使用 Argon2id（RFC 9106）从 password 派生 keyLen 字节密钥。
// memory 为 KiB 内存成本，iterations 为时间成本，parallelism 为并行度。
// 参数非法时返回错误，避免底层实现因非法参数直接 panic。
func Argon2ID(password, salt []byte, memory, iterations uint32, parallelism uint8, keyLen uint32) ([]byte, error) {
	switch {
	case memory < 8:
		return nil, errx.NewCodef(CodeInvalidArgument,
			"Argon2 内存成本至少 8 KiB，当前 %d", memory)
	case iterations == 0:
		return nil, errx.NewCode(CodeInvalidArgument, "Argon2 时间成本必须为正")
	case parallelism == 0:
		return nil, errx.NewCode(CodeInvalidArgument, "Argon2 并行度必须为正")
	case keyLen == 0:
		return nil, errx.NewCode(CodeInvalidArgument, "Argon2 派生密钥长度必须为正")
	default:
		return argon2.IDKey(password, salt, memory, iterations, parallelism, keyLen), nil
	}
}
