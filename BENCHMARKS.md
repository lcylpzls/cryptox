# 基准测试

> 采集环境：Windows / AMD Ryzen 5 7600 / Go 1.26.5
> 采集日期：2026-08-10
> 命令：`go test -bench=. -benchmem -run '^$' .`

## BenchmarkSealOpen

小数据信封加解密（KEK/DEK + AES-256-GCM）：

| 指标 | 数值 |
| --- | --- |
| 耗时 | 1283 ns/op |
| 内存 | 5424 B/op |
| 分配 | 16 allocs/op |

## BenchmarkEncryptStream1MB

1 MiB 分块流式加密（64 KiB/块）：

| 指标 | 数值 |
| --- | --- |
| 耗时 | 351941 ns/op |
| 吞吐 | ~2979 MB/s |

## BenchmarkSignVerifyHMAC

HMAC-SHA256 签名 + 验签：

| 指标 | 数值 |
| --- | --- |
| 耗时 | 845 ns/op |
| 内存 | 1024 B/op |
| 分配 | 12 allocs/op |

## BenchmarkPBKDF2

PBKDF2-HMAC-SHA256（1000 次迭代，派生 32 字节）：

| 指标 | 数值 |
| --- | --- |
| 耗时 | 423015 ns/op |
| 内存 | 512080 B/op |
| 分配 | 6005 allocs/op |

## 说明

- 基准仅反映本机相对量级；CI 不设硬性性能门槛；
- PBKDF2 的分配来自标准算法逐块 XOR 循环，属于预期开销；
- 加密基座优先正确性与可审计性，性能满足常规业务需求。
