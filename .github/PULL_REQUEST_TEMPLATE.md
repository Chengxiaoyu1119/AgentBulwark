## 变更摘要

<!-- 用 2-5 句话说明解决的问题和选择的实现。 -->

## 影响范围

- [ ] API 或 OpenAI/MCP 契约
- [ ] 策略、审批或权限边界
- [ ] Provider 出口或凭证处理
- [ ] Trace、执行回执或证据链
- [ ] 控制台页面或交互
- [ ] 文档、脚本或开发流程

## 验证

- [ ] `npm run verify`
- [ ] `npm run verify:live:fixture`（适用时）
- [ ] 已执行失败、边界和重复操作检查
- [ ] `git diff --check`

验证结果：

## 数据与安全确认

- [ ] 未提交 `.env`、API Key、Agent Token、HMAC 密钥或运行数据库
- [ ] 未引入 Docker、任意命令执行或旧实验入口
- [ ] 失败默认拒绝，未添加静默 fallback
- [ ] 已说明未执行的验证和剩余风险
