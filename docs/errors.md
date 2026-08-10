# 错误码手册

> cryptox 全部错误使用 errx 结构化错误码；错误消息与日志字段
> 绝不包含密钥材料。

| 错误码 | 分类 | 含义 |
| --- | --- | --- |
| `CRYPTOX_INVALID_KEY` | invalid | 主密钥/数据密钥非法（长度或格式） |
| `CRYPTOX_RANDOM_FAILED` | unavailable | 生成安全随机数失败 |
| `CRYPTOX_INVALID_ENVELOPE` | invalid | 信封格式非法（长度/标识/声明不一致） |
| `CRYPTOX_UNSUPPORTED_VERSION` | invalid | 信封/流版本或算法不受支持 |
| `CRYPTOX_DECRYPT_FAILED` | data_loss | 解密失败（不区分密钥错误与篡改） |
| `CRYPTOX_INVALID_STREAM` | invalid | 加密流头部或块格式非法 |
| `CRYPTOX_STREAM_READ_FAILED` | unavailable | 读取明文或密文流失败 |
| `CRYPTOX_STREAM_WRITE_FAILED` | unavailable | 写入密文或明文流失败 |
| `CRYPTOX_HASH_FAILED` | unavailable | 计算摘要失败 |
| `CRYPTOX_INVALID_ARGUMENT` | invalid | 参数非法（派生长度/迭代次数等） |

## 安全约定

- 解密失败统一消息，避免攻击者探测密钥错误与篡改的差异；
- 审计字段（`AuditFields`）只含操作/算法/规模与错误码；
- 密钥、nonce、密文内容绝不进入错误消息或日志。
