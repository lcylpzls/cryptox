# 更新日志

## [v0.6.3] - 2026-08-10

### 变更

- 依赖同步：logx 显式锁定 `v1.1.0`（errx/logx 家族最新版）。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.6.2] - 2026-08-10

### 新增

- 流式 AAD：`EncryptStreamWithAAD` / `DecryptStreamWithAAD`，
  将用途/路径/上下文绑定到每个数据块，防止密文流置换；
- 轮换与 AAD 组合测试：RotateKEK 后 AAD 绑定保持有效。

### 结论

- cryptox 达到 1.0 候选标准；**v1.0.0 是否发布由维护者决定**；
- 1.0 确认后按 A/B/C 优先级接入家族各库。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.6.1] - 2026-08-10

### 新增

- AAD 上下文绑定：`SealWithAAD` / `OpenWithAAD`，
  将用途/路径/上下文绑定到数据密文，防止密文置换；
- 内部 DEK 在 Seal / Open / EncryptStream / DecryptStream /
  RotateKEK 返回前自动擦除（aes.NewCipher 已拷贝密钥，不影响解密）。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.6.0] - 2026-08-10

### 新增

- logx 审计字段：`AuditFields` 输出操作/算法/规模与 errx 错误字段，
  密钥材料绝不入日志；
- 操作标识常量（seal/open/stream/sign/derive/rotate 等）；
- `docs/errors.md` 错误码手册与 `docs/final-review.md` 终审清单；
- Issue 模板与 README CI 徽章；
- 基准测试（信封/流式/HMAC/PBKDF2）。

### 结论

- cryptox 达到 1.0 候选标准；**v1.0.0 是否发布由维护者决定**。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.5.0] - 2026-08-10

### 新增

- 密钥派生：`HKDF`（RFC 5869）与 `PBKDF2`（RFC 8018），
  均基于标准库 HMAC-SHA256 实现并通过 RFC 测试向量验证；
- 安全随机：`RandomBytes`；内存擦除：`Wipe`；
- 主密钥轮换：`RotateKEK` 重新包装 DEK，密文不变、无需解出明文；
- 错误码：`CRYPTOX_INVALID_ARGUMENT`；
- `FuzzRotateKEK` 接入 CI；
- 核心保持零第三方依赖（仅 errx）。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.4.0] - 2026-08-10

### 新增

- Ed25519 密钥生成：`GenerateEd25519Key`；
- 签名/验签：`SignEd25519` / `VerifyEd25519`；
- 公钥导出：`Ed25519PublicKey`；
- hex 解析：`ParseEd25519PublicKeyHex` / `ParseEd25519PrivateKeyHex`；
- 私钥长度非法统一返回 `CRYPTOX_INVALID_KEY`；
- `FuzzVerifyEd25519` 接入 CI。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.3.0] - 2026-08-10

### 新增

- HMAC-SHA256 签名/验签：`SignHMAC` / `VerifyHMAC`（常量时间）；
- 常量时间比较：`ConstantTimeEquals`；
- SHA256 摘要：`SHA256`（单次）与 `SHA256Hex`（流式、小写十六进制）；
- 错误码：`CRYPTOX_HASH_FAILED`；
- `FuzzVerifyHMAC` 接入 CI。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.2.0] - 2026-08-10

### 新增

- 分块 AEAD 流式加解密：`EncryptStream` / `DecryptStream`；
- 64 KiB 分块 AES-256-GCM，内存占用有界，适合大文件；
- 流头部携带 KEK/DEK 信封与流随机数，块 nonce 由计数器派生，
  同一流内保证唯一；
- 块格式自描述（4B 长度 + 密文），空流合法；
- 错误码：`CRYPTOX_INVALID_STREAM` / `CRYPTOX_STREAM_READ_FAILED` /
  `CRYPTOX_STREAM_WRITE_FAILED`；
- `FuzzDecryptStream` 接入 CI。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.1.0] - 2026-08-10

### 新增

- 信封加密核心：`Seal` / `Open`；
- KEK/DEK 信封：随机 DEK + 主密钥包装，每次加密 nonce 唯一；
- 版本化二进制信封格式（v1：magic/version/algorithm/payloadLen/
  keyNonce/dataNonce/wrappedDEK/ciphertext）；
- errx 错误码：`CRYPTOX_INVALID_KEY` / `CRYPTOX_RANDOM_FAILED` /
  `CRYPTOX_INVALID_ENVELOPE` / `CRYPTOX_UNSUPPORTED_VERSION` /
  `CRYPTOX_DECRYPT_FAILED`；
- 解密失败统一消息，不区分密钥错误与篡改；
- fuzz 目标（`FuzzOpen`）接入 CI；
- 三平台 CI + Linux 多发行版容器矩阵 + Release 工作流。

### 质量

- 根包语句覆盖率 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。
