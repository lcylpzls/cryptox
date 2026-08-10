package cryptox

import (
	"testing"

	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/logx"
)

func TestAuditFieldsWithoutError(t *testing.T) {
	g := AuditFields(OperationSeal, "AES-256-GCM", 42, nil)
	keys := fieldKeys(g)
	for _, want := range []string{"crypto.operation", "crypto.algorithm", "crypto.size"} {
		if !keys[want] {
			t.Fatalf("审计字段缺少 %q：%v", want, keys)
		}
	}
	if keys["err.code"] {
		t.Fatal("无错误时不应包含 err.code")
	}
	if len(keys) != 3 {
		t.Fatalf("无错误时应恰好 3 个字段，得到 %d：%v", len(keys), keys)
	}
}

func TestAuditFieldsWithError(t *testing.T) {
	err := errx.NewCode(CodeDecryptFailed, "解密失败")
	g := AuditFields(OperationOpen, "AES-256-GCM", 42, err)
	keys := fieldKeys(g)
	if !keys["err.code"] {
		t.Fatalf("错误审计字段缺少 err.code：%v", keys)
	}
}

func fieldKeys(g logx.FieldGroup) map[string]bool {
	keys := map[string]bool{}
	for i := 0; i < g.Len(); i++ {
		keys[g.At(i).Key] = true
	}
	return keys
}
