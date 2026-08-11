# 更新日志


## [v1.3.1] - 2026-08-12

### 新增

- `Ed25519PrivateKeyFromSeed(seed)`：从 32 字节 seed 派生 64 字节
  Ed25519 私钥（校验 seed 长度），消除业务侧对标准库
  `ed25519.NewKeyFromSeed` 的直接依赖；
- 审计操作标识 `OperationDeriveEd25519`。

## [v1.3.0] - 2026-08-12

### 新增

- X25519 密钥交换能力：
  - `GenerateX25519Key` 生成 32 字节密钥对；
  - `X25519PublicKey` 从私钥推导公钥；
  - `X25519SharedSecret` 计算 ECDH 共享密钥（含 RFC 7748 测试向量）；
  - `ParseX25519PublicKeyHex` / `ParseX25519PrivateKeyHex` 十六进制解析；
- 审计操作标识 `OperationGenerateX25519` /
  `OperationX25519SharedSecret`。

### 质量

- 根包与 internal/core 语句覆盖率均 100%；race / vet / staticcheck 全绿。

## [v1.2.2] - 2026-08-11

### 文档

- README / docs 与当前代码同步：版本状态、架构与错误码手册更新；
- 清理过期规划文档（research/design/roadmap/final-review/api 等）。

### 质量

- 纯文档与版本元数据变更，无需重新运行 CI；Release 工作流照常执行。

## [v1.2.1] - 2026-08-11

### 修复

- 根包补转发 `Argon2Version` 常量（internal/core 重构遗漏）。


## [v1.2.0] - 2026-08-11

### 重构

- 实现主体下沉 `internal/core`，根包仅保留公开 API（转发）；
- 白盒测试迁入 `internal/core`，根包新增黑盒冒烟测试，两处覆盖率均 100%。

## [v1.1.0] - 2026-08-11

### 变更

- errx/logx 子包移除适配：审计字段改用 `logx.FieldsFromError`；
- 依赖升级：logx v1.4.0。

## [v1.0.4] - 2026-08-10

### 变更

- 依赖升级：errx v1.5.7、logx v1.3.4、testx v1.4.5（go get -u -t all）。

## [v1.0.3] - 2026-08-10

### 变更

- 家族正式基线锁定：依赖统一指向 v1 基线已发布版本（errx v1.5.5 / logx v1.3.2 / testx v1.4.3 / validx v1.2.4 / cryptox v1.0.2 / confx v1.0.2 / webx v1.5.4 等），此后家族依赖不再前进。

### 质量

- 全部库包语句覆盖率保持 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v1.0.2] - 2026-08-10

### 变更

- 家族依赖最终对齐到 v1 正式版基线（errx v1.5.4 / logx v1.3.1 / testx v1.4.2 / validx v1.2.3 / confx v1.0.1 / cryptox v1.0.1 等），无 API 变更。

### 质量

- 全部库包语句覆盖率保持 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v1.0.1] - 2026-08-10

### 变更

- 家族依赖统一对齐到最新基线（errx v1.5.4 / logx v1.3.0 / testx v1.4.1 / validx v1.2.2 等），无 API 变更。

### 质量

- 全部库包语句覆盖率保持 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v1.0.0] - 2026-08-10

### 发布

- 家族正式版 v1.0.0：当前 API 与行为作为 v1 基线；按家族规则，v1.*.* 内允许破坏性修改，不承诺向后兼容。

### 质量

- 覆盖率、race、vet、staticcheck、fuzz、govulncheck 全绿；CI/Release 自动化发布。

## [v0.6.7] - 2026-08-10

### 修复

- `Argon2ID` 参数透传顺序修正：底层 `argon2.IDKey` 参数顺序为
  (time, memory, threads, keyLen)，现与文档（memory 在前）保持一致，
  并新增 RFC 9106 官方向量回归测试（v0.6.6 的该函数不可用，请升级）。

### 质量

- 根包语句覆盖率保持 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.6.6] - 2026-08-10

### 新增

- `Argon2ID`：Argon2id 口令派生（RFC 9106），参数非法返回错误而非 panic；
- `Argon2Version` 常量（v=19），供哈希串编码/解析使用；
- `SignHMACWithHash` / `VerifyHMACWithHash`：支持 SHA1 / SHA256 / SHA512
  的多算法 HMAC（供 TOTP 等场景）；
- `NewSHA256`：SHA256 流式哈希器（兼容 `io.Writer`，供大文件边读边哈希）；
- `Ed25519PublicKeySize` / `Ed25519PrivateKeySize` / `Ed25519SeedSize` /
  `Ed25519SignatureSize` 尺寸常量。

### 质量

- 根包语句覆盖率保持 100%；race / vet / staticcheck / fuzz / govulncheck 全绿。

## [v0.6.5] - 2026-08-10

### 变更

- go 指令与 CI/Release 工作流统一为 Go 1.26.5；
- README Go 版本徽章同步更新。

## [v0.6.4] - 2026-08-10

### 变更

- 家族统一 Go 1.21：全部 go.mod 与 CI/Release 工作流版本号对齐 1.21。

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
