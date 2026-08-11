package core

import (
	"github.com/lcylpzls/logx"
)

// 加密操作标识，用于审计字段 crypto.operation。
const (
	OperationSeal               = "seal"
	OperationOpen               = "open"
	OperationEncryptStream      = "encrypt_stream"
	OperationDecryptStream      = "decrypt_stream"
	OperationSignHMAC           = "sign_hmac"
	OperationVerifyHMAC         = "verify_hmac"
	OperationSignEd25519        = "sign_ed25519"
	OperationVerifyEd25519      = "verify_ed25519"
	OperationGenerateX25519     = "generate_x25519"
	OperationX25519SharedSecret = "x25519_shared_secret"
	OperationDeriveEd25519      = "derive_ed25519_private_key"
	OperationDeriveKey          = "derive_key"
	OperationRotateKEK          = "rotate_kek"
)

// AuditFields 生成加密操作的 logx 审计字段：
// 只包含操作、算法与数据规模，绝不包含密钥材料。
// err 非 nil 时附带 errx 结构化错误字段。
func AuditFields(operation, algorithm string, size int, err error) logx.FieldGroup {
	groups := []logx.FieldGroup{
		logx.Fields(
			logx.String("crypto.operation", operation),
			logx.String("crypto.algorithm", algorithm),
			logx.Int("crypto.size", size),
		),
	}
	if err != nil {
		groups = append(groups, logx.FieldsFromError(err))
	}
	var fs []logx.Field
	for _, g := range groups {
		for i := 0; i < g.Len(); i++ {
			fs = append(fs, g.At(i))
		}
	}
	return logx.Fields(fs...)
}
