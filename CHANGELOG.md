# 更新日志

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
