# cryptox

家族加密基座：信封加密、流式加密、签名、摘要与密钥管理辅助。
全部基于 Go 标准库 crypto/*，不自研算法，与 errx / logx 家族打通。

> 当前状态：**v1.3.0**。

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
- 非对称签名：Ed25519 生成/签名/验签、seed→私钥派生；
- X25519 密钥交换：密钥对生成、公钥推导、ECDH 共享密钥；
- 密钥管理：HKDF / PBKDF2 / 安全随机 / 内存擦除 / 轮换辅助；
- errx 错误码全集、logx 审计字段（密钥材料绝不入日志）。

## 文档

- [docs/architecture.md](docs/architecture.md) — 架构
- [docs/errors.md](docs/errors.md) — 错误码手册

## License

MIT © [lcylpzls](https://github.com/lcylpzls)
