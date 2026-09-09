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
  consoleUrl: import.meta.env.VITE_AGENT_SUPERVISOR_CONSOLE_URL ?? 'http://127.0.0.1:5178',
  docsUrl: import.meta.env.VITE_AGENT_SUPERVISOR_DOCS_URL ?? 'http://127.0.0.1:3000',
  repoUrl: 'https://github.com/Chengxiaoyu1119/AgentBulwark'
} as const;

export const heroContent = {
  kicker: 'AI AGENT FIREWALL',
  title: '智垒',
  subtitle: '让每一次模型请求、上下文输入、输出和工具行动，都先经过可验证的运行时边界。'
} as const;

export const gateCards: CardItem[] = [
  { title: 'Request Guard', body: '请求、会话和外部上下文先进入统一边界。', meta: '01 · 输入检查' },
  { title: 'Policy Decision', body: '身份、工具、参数和目标共同决定行动状态。', meta: '02 · 策略判定' },
  { title: 'Tool Gate', body: '只有通过注册、Schema 和审批的行动才会继续。', meta: '03 · 执行闸门' }
];

export const evidenceCards: CardItem[] = [
  { title: 'Trace', body: '请求、响应、Tool Call 和策略命中共享同一条链路。', meta: '01 · request_id' },
  { title: 'Receipt', body: '记录工具是否真实执行，以及执行后的状态。', meta: '02 · execution state' },
  { title: 'Hash / HMAC', body: '把关键快照串成可离线验证的运行证据。', meta: '03 · evidence' }
];

export const surfaceCards: CardItem[] = [
  { title: 'Prompt & Context', body: '检查提示和外部上下文中的不可信指令。', meta: '01 · request' },
  { title: 'Model Output', body: '检查模型响应、工具定义和结构化 Tool Call。', meta: '02 · response' },
  { title: 'Tool Action', body: '约束工具、参数、目标、权限和一次性审批。', meta: '03 · action' },
  { title: 'Provider Egress', body: '固定 Provider 出口，避免凭证和请求误传。', meta: '04 · route' }
];

export const storyCards: CardItem[] = [
  { title: 'Request', body: '为每次请求绑定 Agent、Session、Provider 和输入 Hash。', meta: '01' },
  { title: 'Policy', body: '按身份、工具、Schema、目标和上下文决定 ALLOW、DENY、ASK 或 ISOLATE。', meta: '02' },
  { title: 'MCP', body: '通过真实 MCP 会话执行已授权 Tool Call，并保留会话隔离。', meta: '03' },
  { title: 'Receipt', body: '将执行回执、Trace 和 HMAC 证据绑定到同一请求链。', meta: '04' }
];

export const productCards: CardItem[] = [
  { title: 'OpenAI Gateway', body: '兼容 Chat Completions 与 Responses 请求。', meta: 'gateway' },
  { title: 'MCP Gateway', body: '连接 stdio 或 Streamable HTTP Server。', meta: 'protocol' },
  { title: 'Operator Console', body: '在防护、事件和设置页面查看处置链。', meta: 'console' }
];

export const featureSections: FeatureSectionContent[] = [
  {
    id: 'gate',
    eyebrow: 'REQUEST GUARD',
    titleLines: ['请求到达模型前，', '先经过安全边界。'],
    body: 'Agent 请求、身份、会话和外部上下文先被标准化；输入风险不通过时，不会到达 Provider。',
    tone: 'gate',
    cards: gateCards
  },
  {
    id: 'evidence',
    eyebrow: 'VERIFIABLE EVIDENCE',
    titleLines: ['处置不是黑盒，', '每一步都能核验。'],
    body: 'Trace、请求/响应 Hash、执行回执和 HMAC 证据绑定到同一请求链，复盘时可以区分“声明执行”和“真实执行”。',
    tone: 'evidence',
    cards: evidenceCards,
    reverse: true
  },
  {
    id: 'surface',
    eyebrow: 'RUNTIME CONTROL',
    titleLines: ['模型输出，', '不能绕过工具闸门。'],
    body: '从提示和上下文，到模型输出与 Tool Call，再到 MCP 执行，身份、Schema、目标和审批共同决定是否产生副作用。',
    tone: 'surface',
    cards: surfaceCards
  },
  {
    id: 'console',
    eyebrow: 'LOCAL OPERATOR CONSOLE',
    titleLines: ['从第一条请求，', '看到完整处置链。'],
    body: '控制台聚焦防护、事件和设置：查看实时行动、处理审批、管理接入，并打开完整 Trace 与执行回执。',
    tone: 'product',
    cards: productCards,
    reverse: true
  }
];

export const finalContent = {
  eyebrow: 'READY TO PROTECT',
  title: '让下一次 Agent 行动先经过智垒。'
} as const;
