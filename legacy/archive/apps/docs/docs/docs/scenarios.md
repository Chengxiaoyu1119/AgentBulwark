---
id: scenarios
title: 攻击脚本
---

# 攻击脚本

攻击脚本是项目的可复现实验单元。一个脚本描述攻击目标、对抗输入、预期工具调用、成功标准和对应防御策略。

当前仓库维护 22 个脚本，配置文件位于：

```text
apps/api/agent_supervisor/config/scenarios.json
```

## 脚本字段

| 字段 | 说明 |
| --- | --- |
| `id` | 脚本编号，例如 `TOOL-HIJACK-001` |
| `surface_id` | 所属攻击面 |
| `title` | 脚本名称 |
| `target` | 被攻击对象或业务场景 |
| `adversarial_prompt` | 对抗输入 |
| `jailbreak_case` | 越狱或规则绕过用例 |
| `script_steps` | 复现步骤 |
| `tool_calls` | 预期工具调用 |
| `expected_policy` | 期望命中的策略 |
| `success_criteria` | 攻击成功标准 |

## 单脚本运行

```powershell
npm run cli -- run TOOL-HIJACK-001 on
```

`on` 表示开启监督器。要复现无防护风险，可以改成：

```powershell
npm run cli -- run TOOL-HIJACK-001 off
```

## 有防护/无防护对比

```powershell
npm run cli -- batch --guard compare
```

批量对比会依次运行脚本，并统计无防护暴露数量、有防护控制数量和控制率。

## 通过控制台运行

1. 启动 API 和控制台。
2. 打开 `http://127.0.0.1:5178`。
3. 进入“攻击复现实验室”。
4. 选择脚本。
5. 运行单次实验或对比实验。

## 编写新脚本的原则

- 先明确攻击面，再写工具调用。
- 对抗输入要能解释为什么会影响工具行为。
- 预期策略只写主要命中项，不把所有兜底策略都堆进去。
- 成功标准要可验证，例如“读取到敏感路径”或“触发外部邮件复核”。
- 新脚本要避免访问真实外部系统，所有数据应落在本地沙箱。
