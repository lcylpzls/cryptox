package core

import (
	"testing"

	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/logx"
	"github.com/lcylpzls/testx"
)

func TestAuditFieldsWithoutError(t *testing.T) {
	g := AuditFields(OperationSeal, "AES-256-GCM", 42, nil)
	keys := fieldKeys(g)
	for _, want := range []string{"crypto.operation", "crypto.algorithm", "crypto.size"} {
		testx.RequireTrue(t, keys[want])
	}
	testx.RequireFalse(t, keys["err.code"])
	testx.RequireLen(t, keys, 3)
}

func TestAuditFieldsWithError(t *testing.T) {
	err := errx.NewCode(CodeDecryptFailed, "解密失败")
	g := AuditFields(OperationOpen, "AES-256-GCM", 42, err)
	keys := fieldKeys(g)
	testx.RequireTrue(t, keys["err.code"])
}

func fieldKeys(g logx.FieldGroup) map[string]bool {
	keys := map[string]bool{}
	for i := 0; i < g.Len(); i++ {
		keys[g.At(i).Key] = true
	}
	return keys
}
