# 1.0 候选终审

> 本清单用于确认 cryptox 达到 1.0 候选标准；**v1.0.0 是否发布由维护者决定**。

## 1. API 冻结

- [x] 公开 API 签名稳定：信封/流式/签名/摘要/密钥管理语义明确；
- [x] 信封 v1 与流 v1 格式作为持久化格式冻结；
- [x] 错误码全集与 `docs/errors.md` 一致；
- [x] pre-1.0 兼容承诺：v0.1.0 起的核心行为无意外破坏。

## 2. 质量门禁

- [x] 根包语句覆盖率 100%；
- [x] 测试乱序（`-shuffle=on`）、race 全平台通过；
- [x] vet / staticcheck / govulncheck 通过；
- [x] fuzz 目标（信封/流/验签/轮换）短跑 5s 通过；
- [x] 示例模块（信封/流式/签名/派生/轮换）全绿；
- [x] RFC 测试向量（HKDF / PBKDF2）通过。

## 3. 设计确认

- [x] 全部原语来自标准库，无第三方加密依赖；
- [x] 随机源可注入，随机数失败分支有测试；
- [x] 篡改/截断/版本错误/长度错误均有负面测试；
- [x] 密钥材料不进入错误消息与日志字段；
- [x] 解密失败统一消息，不泄露密钥/篡改差异。

## 4. 性能

- [x] `BENCHMARKS.md` 记录信封/流式/HMAC/PBKDF2 基准。

## 5. 文档与安全

- [x] README / docs/api.md / docs/errors.md / docs/roadmap.md 一致；
- [x] SECURITY.md / CONTRIBUTING.md / CODEOWNERS / Issue 模板齐全；
- [x] 发布流程：tag 触发 Release，CI 全绿后发布。

## 结论

cryptox 已通过 1.0 候选终审清单，达到 1.0 候选标准。
**v1.0.0 是否发布由维护者决定**；确认发布前不再自动推进版本。
1.0 确认后，再按 A/B/C 优先级接入 filex/authx/updatex/confx/dbx/
httpx/cachex/webx/jobx/winsvcx。
