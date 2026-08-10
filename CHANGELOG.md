# 更新日志

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
