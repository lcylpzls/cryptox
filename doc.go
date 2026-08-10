// Package cryptox 是家族加密基座：信封加密、流式加密、签名、摘要与
// 密钥管理辅助。全部基于 Go 标准库 crypto/*，不自研算法。
//
// 典型用法：
//
//	envelope, err := cryptox.Seal(kek, []byte("机密数据"))
//	plain, err := cryptox.Open(kek, envelope)
package cryptox
