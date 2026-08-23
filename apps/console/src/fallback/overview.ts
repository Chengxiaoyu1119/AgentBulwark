import type { Overview } from '../types';
import { fallbackScenarios } from './scenarios';

export const fallbackOverview: Overview = {
  attack_surfaces: [
    {
      id: 'prompt-injection',
      name: '提示注入',
      risk: 'high',
      status: '可复现',
      summary: '通过恶意输入覆盖系统规则，诱导智能体泄露上下文或调用危险工具。',
      samples: 18,
      scripts: 6,
      defense: '输入过滤、上下文隔离、工具意图二次确认',
      entry_points: ['用户消息', '网页/文档内容', '工具返回文本', '多 agent 转发消息'],
      protected_assets: ['系统提示词', '赛题上下文', '工具权限', '外发渠道'],
      attacker_goals: ['覆盖系统规则', '诱导外发赛题或队伍敏感摘要', '把不可信内容伪装成可信指令'],
      detection_signals: ['忽略规则类语义', '跨上下文指令跳转', '外部收件人与敏感正文同时出现'],
      evaluation_focus: ['间接注入能否触发工具调用', '上下文隔离后攻击成功率是否下降'],
      mitigations: ['输入来源标注', '指令/数据分区', '工具调用前二次确认']
    },
    {
      id: 'jailbreak',
      name: '模型越狱',
      risk: 'high',
      status: '可复现',
      summary: '使用角色扮演、多轮引导和规则改写诱导模型绕过安全约束。',
      samples: 9,
      scripts: 3,
      defense: '越狱模板识别、输出过滤、模型行为监测',
      entry_points: ['用户多轮对话', '角色扮演提示', '系统规则改写请求'],
      protected_assets: ['模型安全边界', '拒答策略', '合规输出规则'],
      attacker_goals: ['降低拒答概率', '诱导输出绕过步骤', '让模型把安全规则当成普通建议'],
      detection_signals: ['无约束角色', '禁止拒绝', '要求绕过或规避检查'],
      evaluation_focus: ['越狱提示识别率', '输出过滤阻断率', '误报率'],
      mitigations: ['越狱模板检测', '输出风险复核', '模型行为审计']
    },
    {
      id: 'data-leakage',
      name: '数据泄露',
      risk: 'critical',
      status: '可复现',
      summary: '诱导智能体读取沙箱文件、记忆内容、参赛队伍资料、赛题种子或实验训练样例。',
      samples: 18,
      scripts: 6,
      defense: '最小权限、路径约束、敏感字段脱敏',
      entry_points: ['文件读取请求', '记忆检索请求', '训练样本复述请求', '模拟业务 API 导出请求'],
      protected_assets: ['参赛队伍资料', '提交物摘要', '赛题种子', '长期记忆', '访问令牌', '实验训练样例'],
      attacker_goals: ['批量读取队伍与提交物敏感数据', '诱导复述训练样例', '绕过读取理由审计'],
      detection_signals: ['secret/token/team/flag/submission 检索词', '批量导出意图', '逐字复述训练样例请求'],
      evaluation_focus: ['敏感字段命中率', '脱敏效果', '无防护/有防护泄露差异'],
      mitigations: ['字段级脱敏', '读取目的审计', '数据访问最小权限']
    },
    {
      id: 'abuse-risk',
      name: '滥用风险',
      risk: 'medium',
      status: '可复现',
      summary: '诱导智能体批量发送通知、异常调用模拟业务接口或生成高风险赛事操作。',
      samples: 13,
      scripts: 5,
      defense: '频率限制、人工询问、异常行为基线',
      entry_points: ['批量赛事请求', '外部复盘汇总任务', '自动化邮件通知任务'],
      protected_assets: ['模拟业务接口额度', '参赛队伍触达渠道', '评测与审计记录'],
      attacker_goals: ['批量调用敏感比赛 API', '绕过审批外发队伍或赛题资料', '放大模型自动化能力'],
      detection_signals: ['高频/批量意图', '未授权外部用途', '敏感接口与外部目的同时出现'],
      evaluation_focus: ['批量动作拦截率', '询问策略覆盖率', '低风险任务误报率'],
      mitigations: ['频率限制', '任务目的校验', '人工审批']
    },
    {
      id: 'tool-hijack',
      name: '工具调用劫持',
      risk: 'critical',
      status: '可复现',
      summary: '让模型错误选择或滥用邮件、文件、API、代码执行等外部工具。',
      samples: 17,
      scripts: 6,
      defense: '工具权限矩阵、参数审计、执行前监督',
      entry_points: ['工具选择阶段', '工具参数生成阶段', '代码执行命令', '文件/API 路径'],
      protected_assets: ['沙箱文件系统', '代码执行器', '模拟业务 API 权限', '邮件通知工具'],
      attacker_goals: ['诱导危险工具调用', '构造越界参数', '让模型把危险动作当成正常任务'],
      detection_signals: ['敏感路径', '危险命令片段', '高敏 API endpoint', '工具意图与任务不一致'],
      evaluation_focus: ['工具调用拦截率', '参数审计准确率', '沙箱隔离有效性'],
      mitigations: ['工具权限矩阵', '参数白名单', '代码执行沙箱']
    },
    {
      id: 'memory-poison',
      name: '记忆中毒',
      risk: 'high',
      status: '可复现',
      summary: '向长期记忆写入恶意规则，影响后续任务和工具选择。',
      samples: 9,
      scripts: 3,
      defense: '记忆来源标记、写入审计、污染回滚',
      entry_points: ['长期偏好写入', '会话总结', '多 agent 共享记忆'],
      protected_assets: ['长期记忆库', '后续任务策略', '用户偏好可信度'],
      attacker_goals: ['植入未来越权规则', '隐藏危险动作', '污染后续工具选择'],
      detection_signals: ['以后/以后都', '不需要检查权限', '隐藏/直接执行', '来源不可信'],
      evaluation_focus: ['污染写入隔离率', '后续任务影响范围', '回滚可用性'],
      mitigations: ['记忆来源标注', '写入审批', '隔离区与回滚']
    },
    {
      id: 'environment-pollution',
      name: '环境感知污染',
      risk: 'medium',
      status: '可复现',
      summary: '伪造环境变量、配置文件或工具返回内容，误导模型判断。',
      samples: 12,
      scripts: 4,
      defense: '环境信任分级、配置签名、工具返回隔离',
      entry_points: ['环境变量读取', '配置文件解析', '工具返回内容', '网页正文'],
      protected_assets: ['授权判断', '策略开关', '工具返回可信度'],
      attacker_goals: ['伪造授权依据', '让模型信任低可信环境', '污染工具返回后续决策'],
      detection_signals: ['ALLOW_UNSAFE', 'trust=true', '工具返回中出现指令化文本'],
      evaluation_focus: ['低信任上下文隔离率', '环境配置误信率', '工具返回污染阻断率'],
      mitigations: ['环境信息低信任处理', '配置签名', '工具返回内容隔离']
    }
  ],
  student_competition_attack_map: [
    {
      id: 'team-account-portal',
      name: '参赛队伍账号与门户会话',
      risk: 'critical',
      status: '已接入脚本',
      why: '业务平台围绕队伍账号、portal token、成员资料和登录会话运转，智能体误信外部任务时可能把身份数据当成普通统计材料导出。',
      entry_points: ['队伍资料导出', '校园网会话接口', '外部复盘汇总请求'],
      protected_assets: ['portal_token', '队伍成员名单', '校园网 session', '最近提交物'],
      attacker_paths: ['伪造紧急赛事统计', '要求恢复或代管队伍会话', '把外部复盘包装成官方任务'],
      supervision: ['高敏 API 拒绝', '批量动作复核', '邮件外发询问', '审计 hash 留痕'],
      demo_scenarios: ['TEAM-ACCOUNT-001', 'CAMPUS-SESSION-001', 'ABUSE-RISK-002']
    },
    {
      id: 'challenge-materials',
      name: '赛题附件与题目种子',
      risk: 'critical',
      status: '已接入脚本',
      why: '赛题附件、flag seed、judge token 和题面草稿是比赛核心资产，攻击者可能通过附件正文或工具返回内容夹带指令。',
      entry_points: ['赛题附件说明', 'challenge seed 接口', 'confidential/challenge-seeds.json'],
      protected_assets: ['flag_seed', 'judge_token', '题面草稿', '内部评测样例'],
      attacker_paths: ['附件正文夹带提示注入', '诱导读取赛题种子', '要求复述训练或评测样例'],
      supervision: ['工具返回低信任隔离', '敏感路径拒绝', '模型输出过滤'],
      demo_scenarios: ['CHALLENGE-ATTACHMENT-001', 'JUDGE-SEED-001', 'TRAIN-DATA-LEAK-001']
    },
    {
      id: 'submission-review',
      name: '提交物与评审备注',
      risk: 'high',
      status: '已接入脚本',
      why: '提交物包含 writeup、代码、日志和评审备注，既可能泄露队伍思路，也可能成为提示注入载体。',
      entry_points: ['提交物导出接口', '评审备注创建', '复盘邮件正文'],
      protected_assets: ['writeup 压缩包', '提交日志', '评审备注', '队伍评分线索'],
      attacker_paths: ['批量导出提交物', '把评审备注发送到外部邮箱', '在提交物摘要中夹带越权指令'],
      supervision: ['批量导出询问', '敏感 API 审计', '外发内容复核'],
      demo_scenarios: ['SUBMISSION-EXFIL-001', 'PROMPT-INJECT-001', 'BUSINESS-FLOW-001']
    },
    {
      id: 'scoreboard-judge',
      name: '私有榜单与评测队列',
      risk: 'critical',
      status: '已接入脚本',
      why: '私有成绩榜、评测队列和 judge token 直接影响比赛公平性，不能被智能体根据自然语言任务随意查询或外发。',
      entry_points: ['私有成绩榜 API', '评测队列状态', 'judge token 导出'],
      protected_assets: ['私有榜单', '评测队列', 'judge_token', '未公开排名'],
      attacker_paths: ['伪造仲裁任务查询私榜', '导出评测队列定位弱队', '把 judge token 当作调试材料读取'],
      supervision: ['高敏 API 拒绝', '最小权限角色检查', '人工审批'],
      demo_scenarios: ['ABUSE-RISK-001', 'JUDGE-SEED-001']
    },
    {
      id: 'training-camp-net',
      name: '训练平台与校园网环境',
      risk: 'high',
      status: '已接入脚本',
      why: '训练平台状态、校园网会话和环境变量常被模型当作授权依据；如果这些信息被污染，智能体会错误放大工具权限。',
      entry_points: ['训练平台状态接口', '校园网 session 导出', '环境变量读取'],
      protected_assets: ['训练平台登录态', '校园网会话', '环境授权开关', '工具返回可信度'],
      attacker_paths: ['伪造 ALLOW_UNSAFE_TOOLS', '导出校园网会话', '利用训练平台返回内容覆盖规则'],
      supervision: ['环境低信任隔离', '工具返回隔离', '会话导出拒绝'],
      demo_scenarios: ['ENV-POLLUTE-001', 'ENV-POLLUTE-002', 'CAMPUS-SESSION-001']
    }
  ],
  scenarios: fallbackScenarios,
  models: [
    { provider: 'DeepSeek', configured: false, model: 'deepseek-v4-pro', mode: 'simulated' },
    { provider: '智谱', configured: false, model: 'glm-4.6v-flashx', mode: 'simulated' },
    { provider: '本地安全评测模型', configured: false, model: 'agent-supervisor-sim-guard', mode: 'fallback' }
  ],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: {
    surface_count: 7,
    scenario_count: fallbackScenarios.length,
    recent_run_count: 0,
    block_rate: 0,
    guarded_run_count: 0,
    guarded_controlled_count: 0,
    guarded_control_rate: 0,
    attack_success_rate: 0,
    avg_latency_ms: 0
  }
};

/**
 * Offline state for the product shell. It is intentionally empty: a network
 * failure must never make historical fixture metrics look like live evidence.
 */
export const offlineOverview: Overview = {
  attack_surfaces: [],
  student_competition_attack_map: [],
  scenarios: [],
  models: [],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: {
    surface_count: 0,
    scenario_count: 0,
    recent_run_count: 0,
    block_rate: 0,
    guarded_run_count: 0,
    guarded_controlled_count: 0,
    guarded_control_rate: 0,
    attack_success_rate: 0,
    avg_latency_ms: 0
  }
};
