# API 快照

> 随版本更新。v0.3.0 快照如下；新版本发布后同步替换。

## v0.3.0

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

### 流式加解密

```go
func EncryptStream(kek []byte, dst io.Writer, src io.Reader) error
func DecryptStream(kek []byte, dst io.Writer, src io.Reader) error
```

- 分块 AES-256-GCM（64 KiB/块），内存占用有界，适合大文件；
- 流头部携带 KEK/DEK 信封与流随机数，块 nonce 由计数器派生；
- 块格式：`[4B 长度][密文+标签]`；空流合法；
- 块认证失败统一返回 `CRYPTOX_DECRYPT_FAILED`。

### 流格式（v1）

```text
头部：magic "CRX1" | version | algorithm | chunkSize (4B)
      keyNonce (12B) | streamNonce (12B) | wrappedDEK (48B)
数据：块序列，每块 [4B 密文长度][密文+标签]
```

### 对称认证与摘要

```go
func SignHMAC(key, msg []byte) ([]byte, error)
func VerifyHMAC(key, msg, sig []byte) bool
func ConstantTimeEquals(a, b []byte) bool
func SHA256(data []byte) []byte
func SHA256Hex(r io.Reader) (string, error)
```

- `SignHMAC` 使用 HMAC-SHA256，返回 32 字节签名；密钥必须非空；
- `VerifyHMAC` 常量时间校验，密钥为空或签名不匹配返回 false；
- `SHA256Hex` 流式计算摘要（小写十六进制），适合大文件；
- 摘要计算读取失败返回 `CRYPTOX_HASH_FAILED`。

### 错误码

| 错误码 | 分类 | 含义 |
| --- | --- | --- |
| `CRYPTOX_INVALID_KEY` | invalid | 主密钥/数据密钥非法 |
| `CRYPTOX_RANDOM_FAILED` | unavailable | 生成安全随机数失败 |
| `CRYPTOX_INVALID_ENVELOPE` | invalid | 信封格式非法 |
| `CRYPTOX_UNSUPPORTED_VERSION` | invalid | 信封版本或算法不受支持 |
| `CRYPTOX_DECRYPT_FAILED` | data_loss | 解密失败 |
| `CRYPTOX_INVALID_STREAM` | invalid | 加密流头部或块格式非法 |
| `CRYPTOX_STREAM_READ_FAILED` | unavailable | 读取明文或密文流失败 |
| `CRYPTOX_STREAM_WRITE_FAILED` | unavailable | 写入密文或明文流失败 |
| `CRYPTOX_HASH_FAILED` | unavailable | 计算摘要失败 |
