# 架构

## 1. 包内模块

```text
cryptox（根包）
├── errors.go      错误码定义与注册
├── envelope.go    信封加密 Seal/Open（v0.1.0）
├── stream.go      分块 AEAD 流式加解密（v0.2.0）
├── hmac.go        HMAC 签名/验签与常量时间比较（v0.3.0）
├── hash.go        SHA256 流式摘要（v0.3.0）
├── ed25519.go     Ed25519 密钥/签名/验签（v0.4.0）
├── x25519.go      X25519 密钥对/公钥推导/共享密钥（v1.3.0）
├── cert.go        自签 TLS 证书（Ed25519/ECDSA，v1.4.0）
├── key.go         HKDF / PBKDF2 / RandomBytes / Wipe（v0.5.0）
└── audit.go       logx 审计字段联动（v0.6.0）
```

依赖方向：

```text
audit.go ──→ 其余模块 ──→ errors.go
```

## 2. 关键设计

- **标准库承载原语**：aes/gcm、sha256、hmac、ed25519、hkdf、pbkdf2、
  rand 全部来自标准库；
- **随机源可注入**：`randomReader` 包级变量默认为 `crypto/rand.Reader`，
  测试可注入失败分支；
- **不可变与副本**：公开 API 不持有调用方密钥切片；`Wipe` 提供显式清零；
- **负面测试**：篡改/截断/版本错误/长度错误全部有专项测试；
- **fuzz**：信封与流式头部解析对任意字节不 panic。

## 3. 后续演进扩展点

- KMS 抽象（v1.x 按需）：`KeyProvider` 接口，本地主密钥实现 +
  未来云 KMS 实现；
- 多算法注册表：信封 version/algorithm 字段已预留；
- 家族接入：filex 上提、authx/updatex/confx/dbx/httpx 等按 A/B/C
  优先级接入。
