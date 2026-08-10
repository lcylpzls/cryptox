# API 快照

> 随版本更新。v0.6.3 快照如下；新版本发布后同步替换。

## v0.6.3

### 信封加密

```go
func Seal(kek, plaintext []byte) ([]byte, error)
func Open(kek, envelope []byte) ([]byte, error)
func SealWithAAD(kek, plaintext, aad []byte) ([]byte, error)
func OpenWithAAD(kek, envelope, aad []byte) ([]byte, error)
```

- `Seal` 生成随机 DEK 并用主密钥包装，返回版本化信封；
  kek 必须为 16/24/32 字节，推荐 32 字节；
- `Open` 解开信封；失败统一返回 `CRYPTOX_DECRYPT_FAILED`，
  不区分密钥错误与篡改；
- `SealWithAAD` / `OpenWithAAD` 将附加认证数据绑定到数据密文，
  防止密文被置换到其他用途/路径/上下文；
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
func EncryptStreamWithAAD(kek []byte, dst io.Writer, src io.Reader, aad []byte) error
func DecryptStreamWithAAD(kek []byte, dst io.Writer, src io.Reader, aad []byte) error
```

- 分块 AES-256-GCM（64 KiB/块），内存占用有界，适合大文件；
- 流头部携带 KEK/DEK 信封与流随机数，块 nonce 由计数器派生；
- 块格式：`[4B 长度][密文+标签]`；空流合法；
- 块认证失败统一返回 `CRYPTOX_DECRYPT_FAILED`。
- `*WithAAD` 将附加认证数据绑定到每个数据块，防止密文流置换。

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

### 非对称签名

```go
func GenerateEd25519Key() (priv, pub []byte, err error)
func SignEd25519(priv, msg []byte) ([]byte, error)
func VerifyEd25519(pub, msg, sig []byte) bool
func Ed25519PublicKey(priv []byte) ([]byte, error)
func ParseEd25519PublicKeyHex(s string) ([]byte, error)
func ParseEd25519PrivateKeyHex(s string) ([]byte, error)
```

- 私钥 64 字节（种子 + 公钥），公钥 32 字节，签名 64 字节；
- 私钥长度非法时签名/导出返回 `CRYPTOX_INVALID_KEY`；
- `VerifyEd25519` 公钥长度非法或签名不匹配返回 false；
- hex 解析支持小写/大写十六进制，长度错误返回 `CRYPTOX_INVALID_KEY`。

### 密钥管理

```go
func HKDF(secret, salt, info []byte, length int) ([]byte, error)
func PBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error)
func RandomBytes(n int) ([]byte, error)
func Wipe(b []byte)
func RotateKEK(oldKEK, newKEK, envelope []byte) ([]byte, error)
```

- `HKDF` 为 RFC 5869（HMAC-SHA256），派生长度 1..8160 字节；
- `PBKDF2` 为 RFC 8018（HMAC-SHA256），适合口令派生；
- 两者均基于标准库实现，无第三方依赖，并通过 RFC 测试向量验证；
- `RandomBytes` 生成安全随机数；`Wipe` 清零敏感内存；
- `RotateKEK` 用新主密钥重新包装 DEK，密文不变，无需解出明文。

### 审计字段

```go
func AuditFields(operation, algorithm string, size int, err error) logx.FieldGroup
```

- 输出 `crypto.operation` / `crypto.algorithm` / `crypto.size`，
  err 非 nil 时附带 errx 结构化错误字段；
- 绝不包含密钥材料；
- 操作标识常量：`OperationSeal` / `OperationOpen` /
  `OperationEncryptStream` / `OperationDecryptStream` /
  `OperationSignHMAC` / `OperationVerifyHMAC` /
  `OperationSignEd25519` / `OperationVerifyEd25519` /
  `OperationDeriveKey` / `OperationRotateKEK`。

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
| `CRYPTOX_INVALID_ARGUMENT` | invalid | 参数非法 |
