# 设计

## 1. 定位与范围

cryptox 是家族生态的加密基座：

- 提供信封加密、流式加密、对称/非对称签名、摘要、密钥派生与管理辅助；
- 全部基于 Go 标准库 crypto/*，不自研算法；
- 与 errx（错误码）、logx（审计字段）家族打通；
- 目标消费方：filex（上提）、authx、updatex、confx、dbx、httpx、
  cachex、webx、jobx、winsvcx。

非目标：

- 不实现自定义算法与协议原语；
- 不做密钥托管服务（KMS 接口按需抽象，不内建存储）；
- 不做 TLS 栈与证书体系（那是标准库与 webx 的职责）。

## 2. 核心模型

```text
cryptox
├── 信封加密：Seal / Open（KEK → DEK → AES-256-GCM，版本化信封）
├── 流式加密：EncryptStream / DecryptStream（分块 AEAD，内存有界）
├── 对称认证：SignHMAC / VerifyHMAC / ConstantTimeEquals
├── 摘要：SHA256Hex（流式）
├── 非对称签名：GenerateEd25519Key / SignEd25519 / VerifyEd25519
└── 密钥管理：HKDF / PBKDF2 / RandomBytes / Wipe / 轮换辅助
```

## 3. 信封格式（v1）

```text
magic "CRX1" (4B)
version  (1B) = 1
algorithm (1B) = 1 (AES-256-GCM)
payloadLen (4B, BE) — 后续全部字节长度
keyNonce   (12B)
dataNonce  (12B)
wrappedDEK (48B = 32B DEK + 16B tag)
ciphertext (len(plaintext) + 16B tag)
```

- 每次加密生成随机 DEK 与随机 nonce，相同明文两次结果不同；
- 信封自描述版本与算法，Open 按版本分发，支持未来升级；
- payloadLen 用于防截断/防超长输入。

## 4. 错误与日志

- 全部错误使用 errx 结构化错误码（`cryptox_` 前缀）；
- 解密失败统一为"解密失败"，不区分密钥错误与篡改，避免攻击者探测；
- 日志字段只含算法/版本/操作/耗时，密钥材料绝不进入日志或错误消息。

## 5. 版本与兼容

- 语义化版本；pre-1.0 允许按路线图演进；
- v1.0.0 起 API 冻结，信封 v1 格式保持可读；
- 每版完成即发布 tag，CI 全绿后 Release 自动生成；
- v1.0.0 是否发布由维护者决定，cryptox 只推进到 1.0 候选即停；
- 1.0 确认后，再按 A/B/C 优先级接入 filex/authx/updatex/confx/dbx/
  httpx/cachex/webx/jobx/winsvcx。
