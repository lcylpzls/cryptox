package cryptox

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestSHA256HexStreamingMatchesWriter(t *testing.T) {
	// 覆盖 NewSHA256 与 SHA256Hex 的一致性：同一输入两条路径摘要相同。
	const input = "流式哈希一致性校验"
	h := NewSHA256()
	if _, err := h.Write([]byte(input)); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	gotHex := hex.EncodeToString(h.Sum(nil))
	wantHex, err := SHA256Hex(strings.NewReader(input))
	if err != nil {
		t.Fatalf("SHA256Hex 失败：%v", err)
	}
	if gotHex != wantHex {
		t.Fatalf("两条路径摘要不一致：%s != %s", gotHex, wantHex)
	}
}
