export type CardItem = {
  title: string;
  body: string;
  meta?: string;
};

export type FeatureTone = 'gate' | 'evidence' | 'surface' | 'product';

export type FeatureSectionContent = {
  id: string;
  eyebrow: string;
  titleLines: string[];
  body: string;
  tone: FeatureTone;
  cards: CardItem[];
  reverse?: boolean;
};

export const siteLinks = {
  consoleUrl:
    import.meta.env.VITE_AGENT_SUPERVISOR_CONSOLE_URL ??
    (import.meta.env.PROD ? 'https://xa.chengxiaoyu.top:46858' : 'http://127.0.0.1:5178'),
  docsUrl:
    import.meta.env.VITE_AGENT_SUPERVISOR_DOCS_URL ??
    (import.meta.env.PROD ? 'https://docs.xa.chengxiaoyu.top:46858' : 'http://127.0.0.1:3000'),
  repoUrl: 'https://github.com/Chengxiaoyu1119/agent-security-supervisor'
} as const;

export const heroContent = {
  kicker: 'LLM Agent Attack Lab',
  title: '智安哨',
  subtitle: '把智能体每一次工具调用变成可审计、可阻断、可回放的安全链路。'
} as const;

export const gateCards: CardItem[] = [
  { title: '请求来源', body: '外部任务、邮件、文档、API 调用先进入统一入口。', meta: '上下文标记' },
  { title: '风险判定', body: '来源、工具、参数和策略命中合成一次执行前判断。', meta: '策略命中 3 项' },
  { title: '执行动作', body: '阻断、复核、隔离或放行都会形成审计记录。', meta: '动作可回放' }
];

export const evidenceCards: CardItem[] = [
  { title: '参数快照', body: '记录工具名、调用参数、目标路径和调用来源。', meta: 'arg_12c8' },
  { title: '策略命中', body: '把来源隔离、敏感路径和批量外发规则串起来。', meta: 'policy trace' },
  { title: '复核结论', body: '输出阻断原因、复核建议和可交付证据链。', meta: 'review ready' }
];

export const surfaceCards: CardItem[] = [
  { title: '提示注入', body: '识别不可信文本试图覆盖系统规则的行为。', meta: '3 脚本' },
  { title: '工具劫持', body: '拦截危险工具参数、路径越界和伪造返回。', meta: '4 脚本' },
  { title: '数据泄露', body: '检测批量读取、外发目标和敏感资源访问。', meta: '18 样本' },
  { title: '记忆中毒', body: '复核长期记忆写入，避免后续任务被污染。', meta: '2 脚本' }
];

export const storyCards: CardItem[] = [
  { title: '事件进入', body: '把工具名、参数、上下文来源统一成标准事件。', meta: '01' },
  { title: '策略融合', body: '策略命中、异常评分和敏感资源共同参与判断。', meta: '02' },
  { title: '证据输出', body: '生成参数快照、动作结论和复核链路。', meta: '03' }
];

export const productCards: CardItem[] = [
  { title: '标准事件入口', body: '控制台接收工具名、参数和上下文来源。', meta: 'event' },
  { title: '策略前置闸门', body: '执行前完成评分、阻断、询问或隔离。', meta: 'policy' },
  { title: '审计报告输出', body: '生成复核链路和接入验收材料。', meta: 'report' }
];

export const featureSections: FeatureSectionContent[] = [
  {
    id: 'gate',
    eyebrow: '调用前置闸门',
    titleLines: ['工具执行前，', '先过安全闸门。'],
    body: '外部 Agent、邮件、文件、API 和代码执行请求进入真实工具前，先由智安哨统一整理上下文、识别来源、计算风险并输出动作。',
    tone: 'gate',
    cards: gateCards
  },
  {
    id: 'evidence',
    eyebrow: '审计链路',
    titleLines: ['判定不是黑盒，', '每一步都能回放。'],
    body: '策略命中、异常评分、参数快照和最终动作会串成一条证据链，演示、验收、复盘时不用再从日志里拼答案。',
    tone: 'evidence',
    cards: evidenceCards,
    reverse: true
  },
  {
    id: 'surface',
    eyebrow: '攻防覆盖',
    titleLines: ['攻击脚本、', '样本和策略放在一起。'],
    body: '提示注入、工具调用劫持、数据泄露、记忆中毒等攻击面都能和脚本、样本、策略一一对应，适合做红队实验和防护验收。',
    tone: 'surface',
    cards: surfaceCards
  },
  {
    id: 'console',
    eyebrow: '产品工作台',
    titleLines: ['从官网理解，', '到控制台执行。'],
    body: '官网负责讲清楚判断逻辑；控制台负责跑攻击脚本、看实时事件、调策略和导出报告。',
    tone: 'product',
    cards: productCards,
    reverse: true
  }
];

export const finalContent = {
  eyebrow: 'Ready for Lab',
  title: '开始运行一次真实的工具调用监督实验。'
} as const;
