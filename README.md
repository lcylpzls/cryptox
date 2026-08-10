# cryptox

家族加密基座：信封加密、流式加密、签名、摘要与密钥管理辅助。
全部基于 Go 标准库 crypto/*，不自研算法，与 errx / logx 家族打通。

> 当前状态：**v0.6.x（1.0 候选）**；v1.0.0 是否发布由维护者决定。

[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.26.5-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/lcylpzls/cryptox/actions/workflows/ci.yml/badge.svg)](https://github.com/lcylpzls/cryptox/actions/workflows/ci.yml)

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/lcylpzls/cryptox"
)

func main() {
	kek := []byte("0123456789abcdef0123456789abcdef") // 32 字节主密钥
	envelope, err := cryptox.Seal(kek, []byte("机密数据"))
	if err != nil {
		panic(err)
	}
	plain, err := cryptox.Open(kek, envelope)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plain))
}
```

## 核心特性

- 信封加密：Seal / Open，KEK/DEK 信封 + 版本化二进制格式；
- 流式加密：EncryptStream / DecryptStream，分块 AEAD、内存有界；
- 对称认证：HMAC 签名/验签、常量时间比较；
- 摘要：SHA256 流式校验；
- 非对称签名：Ed25519 生成/签名/验签；
- 密钥管理：HKDF / PBKDF2 / 安全随机 / 内存擦除 / 轮换辅助；
- errx 错误码全集、logx 审计字段（密钥材料绝不入日志）。

## 文档

- [docs/research.md](docs/research.md) — 调研与取舍
- [docs/design.md](docs/design.md) — 设计
- [docs/architecture.md](docs/architecture.md) — 架构
- [docs/api.md](docs/api.md) — API 快照
- [docs/errors.md](docs/errors.md) — 错误码手册
- [docs/final-review.md](docs/final-review.md) — 1.0 候选终审
- [docs/roadmap.md](docs/roadmap.md) — 路线图

## License

MIT © [lcylpzls](https://github.com/lcylpzls)
