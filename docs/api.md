# API 快照

> 随版本更新。v0.1.0 快照如下；新版本发布后同步替换。

## v0.1.0

### 信封加密

```go
func Seal(kek, plaintext []byte) ([]byte, error)
func Open(kek, envelope []byte) ([]byte, error)
```

- `Seal` 生成随机 DEK 并用主密钥包装，返回版本化信封；
  kek 必须为 16/24/32 字节，推荐 32 字节；
- `Open` 解开信封；失败统一返回 `CRYPTOX_DECRYPT_FAILED`，
  不区分密钥错误与篡改；
- 信封可公开存储，密钥不在其中。

### 信封格式（v1）

```text
magic "CRX1" (4B) | version (1B) | algorithm (1B) | payloadLen (4B)
keyNonce (12B) | dataNonce (12B) | wrappedDEK (48B) | ciphertext
```

### 错误码

| 错误码 | 分类 | 含义 |
| --- | --- | --- |
| `CRYPTOX_INVALID_KEY` | invalid | 主密钥/数据密钥非法 |
| `CRYPTOX_RANDOM_FAILED` | unavailable | 生成安全随机数失败 |
| `CRYPTOX_INVALID_ENVELOPE` | invalid | 信封格式非法 |
| `CRYPTOX_UNSUPPORTED_VERSION` | invalid | 信封版本或算法不受支持 |
| `CRYPTOX_DECRYPT_FAILED` | data_loss | 解密失败 |
