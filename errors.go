package cryptox

import "github.com/lcylpzls/errx"

// cryptox 错误码全集：所有失败场景统一使用 errx 结构化错误。
const (
	// CodeInvalidKey 主密钥/数据密钥非法。
	CodeInvalidKey errx.Code = "CRYPTOX_INVALID_KEY"
	// CodeRandomFailed 生成安全随机数失败。
	CodeRandomFailed errx.Code = "CRYPTOX_RANDOM_FAILED"
	// CodeInvalidEnvelope 信封格式非法。
	CodeInvalidEnvelope errx.Code = "CRYPTOX_INVALID_ENVELOPE"
	// CodeUnsupportedVersion 信封版本或算法不受支持。
	CodeUnsupportedVersion errx.Code = "CRYPTOX_UNSUPPORTED_VERSION"
	// CodeDecryptFailed 解密失败（不区分密钥错误与篡改）。
	CodeDecryptFailed errx.Code = "CRYPTOX_DECRYPT_FAILED"
	// CodeInvalidStream 加密流头部或块格式非法。
	CodeInvalidStream errx.Code = "CRYPTOX_INVALID_STREAM"
	// CodeStreamReadFailed 读取明文或密文流失败。
	CodeStreamReadFailed errx.Code = "CRYPTOX_STREAM_READ_FAILED"
	// CodeStreamWriteFailed 写入密文或明文流失败。
	CodeStreamWriteFailed errx.Code = "CRYPTOX_STREAM_WRITE_FAILED"
	// CodeHashFailed 计算摘要失败。
	CodeHashFailed errx.Code = "CRYPTOX_HASH_FAILED"
)

func init() {
	errx.RegisterCode(CodeInvalidKey, "主密钥/数据密钥非法")
	errx.RegisterCodeKind(CodeInvalidKey, errx.KindInvalid)
	errx.RegisterCode(CodeRandomFailed, "生成安全随机数失败")
	errx.RegisterCodeKind(CodeRandomFailed, errx.KindUnavailable)
	errx.RegisterCode(CodeInvalidEnvelope, "信封格式非法")
	errx.RegisterCodeKind(CodeInvalidEnvelope, errx.KindInvalid)
	errx.RegisterCode(CodeUnsupportedVersion, "信封版本或算法不受支持")
	errx.RegisterCodeKind(CodeUnsupportedVersion, errx.KindInvalid)
	errx.RegisterCode(CodeDecryptFailed, "解密失败")
	errx.RegisterCodeKind(CodeDecryptFailed, errx.KindDataLoss)
	errx.RegisterCode(CodeInvalidStream, "加密流头部或块格式非法")
	errx.RegisterCodeKind(CodeInvalidStream, errx.KindInvalid)
	errx.RegisterCode(CodeStreamReadFailed, "读取明文或密文流失败")
	errx.RegisterCodeKind(CodeStreamReadFailed, errx.KindUnavailable)
	errx.RegisterCode(CodeStreamWriteFailed, "写入密文或明文流失败")
	errx.RegisterCodeKind(CodeStreamWriteFailed, errx.KindUnavailable)
	errx.RegisterCode(CodeHashFailed, "计算摘要失败")
	errx.RegisterCodeKind(CodeHashFailed, errx.KindUnavailable)
}
