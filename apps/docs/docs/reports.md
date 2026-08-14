---
id: reports
title: 证据与报告
---

# 按需证据与报告

综合报告不是运行时防护的主流程。平台在工具调用到达执行器前完成判定、阻断、审批、回执和审计；本页产物只在复核、答辩或提交时按需生成。

报告由运行记录、策略命中、审计日志和评测结果生成。它们用于回答三个问题：

1. 攻击是否能在无防护状态下复现。
2. 开启监督后是否被正确控制。
3. 控制过程是否留下可复查证据。

## 主要产物

| 产物 | 用途 |
| --- | --- |
| 攻击面证据包 | 汇总单个攻击面的样本、脚本、运行证据、策略命中和缺口 |
| 攻防有效性评测 | 对比无防护复现率、有防护控制率和证据完整率 |
| 正常业务误报评测 | 检查正常任务是否被错误拒绝、询问或隔离 |
| 连续流程误报评测 | 检查多步骤正常任务是否能在监督器下完成 |
| 策略消融实验 | 关闭指定策略后观察风险暴露和兜底策略 |
| 异常检测阈值校准 | 评估异常阈值对攻击召回率和正常误报率的影响 |
| OpenClaw 插件验收报告 | 验证插件包结构、接口契约和可选 runtime inspect |
| 赛前一键体检 | 汇总攻击面、报告、插件、截图和提交包准备情况 |

## 常用命令

```powershell
npm run cli -- surface-packs --output apps/api/sandbox/reports
npm run cli -- assess --run-compare --output apps/api/sandbox/reports/攻防有效性评测.md
npm run cli -- benign-workflows-write --output apps/api/sandbox/reports
npm run cli -- anomaly-calibration --output apps/api/sandbox/reports
npm run cli -- policy-ablation --output apps/api/sandbox/reports
npm run cli -- readiness --write --output apps/api/sandbox/reports
```

## API 入口

| 接口 | 返回内容 |
| --- | --- |
| `GET /api/report` | 按需生成控制台证据数据（可能包含固定评测，运行耗时较长） |
| `GET /api/attack_surfaces/evidence_packs` | 攻击面证据包索引 |
| `GET /api/evaluations/attack_effectiveness` | 攻防有效性评测 |
| `GET /api/evaluations/benign` | 正常业务误报评测 |
| `GET /api/evaluations/benign_workflows` | 连续流程误报评测 |
| `GET /api/evaluations/policy_ablation` | 策略消融结果 |
| `GET /api/evaluations/anomaly_calibration` | 异常阈值校准结果 |
| `GET /api/readiness` | 赛前体检数据 |

## 生成位置

默认输出目录：

```text
apps/api/sandbox/reports
```

这个目录属于本地沙箱，内容可以删除后重新生成。不要把真实密钥、真实队伍数据或个人文件放入沙箱报告目录。
