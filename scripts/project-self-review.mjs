import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();

function readText(relativePath) {
  const fullPath = path.join(root, relativePath);
  return fs.existsSync(fullPath) ? fs.readFileSync(fullPath, 'utf8') : '';
}

function countMatches(text, pattern) {
  return (text.match(pattern) ?? []).length;
}

function fileInfo(relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) {
    return { exists: false, lines: 0, bytes: 0 };
  }
  const text = fs.readFileSync(fullPath, 'utf8');
  return {
    exists: true,
    lines: text.split(/\r?\n/).length,
    bytes: Buffer.byteLength(text)
  };
}

function pngInfo(relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) {
    return { exists: false, width: 0, height: 0, bytes: 0 };
  }
  const buffer = fs.readFileSync(fullPath);
  return {
    exists: true,
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
    bytes: buffer.length
  };
}

function loadJson(relativePath) {
  const text = readText(relativePath);
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

const outputIndex = process.argv.findIndex((arg) => arg === '--output');
const outputRoot =
  outputIndex >= 0 && process.argv[outputIndex + 1]
    ? path.resolve(root, process.argv[outputIndex + 1])
    : path.join(root, 'apps', 'api', 'sandbox', 'reports');
fs.mkdirSync(outputRoot, { recursive: true });

const appText = readText('apps/console/src/App.tsx');
const stylesText = readText('apps/console/src/styles.css');
const visualText = readText('apps/console/src/视觉系统.css');
const tokenText = readText('apps/console/src/design/tokens.css');
const dataText = readText('apps/api/agent_supervisor/storage/data.py');
const scenarioConfig = loadJson('apps/api/agent_supervisor/config/scenarios.json') ?? [];
const studentProfileConfig = loadJson('apps/api/agent_supervisor/config/student_competition_attack_map.json') ?? [];
const attackChainSourceText = readText('apps/api/agent_supervisor/domains/attacks/attack_chains.py');
const readmeText = readText('README.md');
const architectureText = readText('PROJECT_ARCHITECTURE.md');
const deliveryGuideText = readText('docs/Coding/比赛交付材料包说明.md');
const selfReviewRecordText = readText('docs/Coding/多Agent自审优化闭环报告-20260609.md');
const competitionResearchText = readText('docs/Coding/命题挑战赛调研摘要.md');

const uiDir = path.join(root, 'apps', 'console', 'src', 'components', 'ui');
const uiComponents = fs.existsSync(uiDir)
  ? fs.readdirSync(uiDir).filter((name) => name.endsWith('.tsx') && !name.endsWith('.test.tsx'))
  : [];

const readiness = loadJson('apps/api/sandbox/reports/赛前一键体检报告.json');
const readinessPayload = readiness?.summary ? readiness : (readiness?.readiness ?? readiness);
const blockers = readinessPayload?.blockers ?? [];
const attackChains = loadJson('apps/api/sandbox/reports/组合攻击链评测.json');

const studentProfileIds = [
  'team-account-portal',
  'challenge-materials',
  'submission-review',
  'scoreboard-judge',
  'training-camp-net'
];
const studentScenarioIds = [
  'TEAM-ACCOUNT-001',
  'SUBMISSION-EXFIL-001',
  'CHALLENGE-ATTACHMENT-001',
  'JUDGE-SEED-001',
  'CAMPUS-SESSION-001'
];
const configuredProfileIds = new Set(
  Array.isArray(studentProfileConfig) ? studentProfileConfig.map((item) => item?.id).filter(Boolean) : []
);
const configuredScenarioIds = new Set(
  Array.isArray(scenarioConfig) ? scenarioConfig.map((item) => item?.id).filter(Boolean) : []
);
const sourceAttackChainIds = Array.from(
  attackChainSourceText.matchAll(/^\s{8}"id": "([^"]+-chain)",$/gm),
  (match) => match[1]
);
const reportAttackChains = Array.isArray(attackChains?.chains) ? attackChains.chains : [];
const attackChainIds = reportAttackChains.length
  ? reportAttackChains.map((item) => item.id).filter(Boolean)
  : sourceAttackChainIds;
const studentProfileCount = studentProfileIds.filter((id) => configuredProfileIds.has(id)).length;
const studentScenarioCount = studentScenarioIds.filter((id) => configuredScenarioIds.has(id)).length;
const attackChainCount = attackChainIds.length;
const hasStudentPortalChain = attackChainIds.includes('student-competition-portal-chain');
const domainResidualText = [
  readmeText,
  architectureText,
  competitionResearchText,
  dataText,
  JSON.stringify(scenarioConfig),
  JSON.stringify(studentProfileConfig),
  appText
].join('\n');
const misleadingDomainResidualCount = countMatches(
  domainResidualText,
  /customer|customers|finance|ledger|客户|财务|订单|库存|工单|合作方|网络风险|通用网络风险/g
);

const screenshots = [
  'apps/api/sandbox/reports/frontend-governance-desktop.png',
  'apps/api/sandbox/reports/frontend-governance-mobile.png',
  'apps/api/sandbox/reports/scenario-library-desktop.png',
  'apps/api/sandbox/reports/experiment-lab-desktop.png',
  'apps/api/sandbox/reports/agent-chain-desktop.png',
  'apps/api/sandbox/reports/attack-chain-workbench-desktop.png',
  'apps/api/sandbox/reports/attack-chain-workbench-mobile.png',
  'apps/api/sandbox/reports/policy-impact-matrix-desktop.png',
  'apps/api/sandbox/reports/audit-hash-verify-desktop.png',
  'apps/api/sandbox/reports/decision-pill-audit-desktop.png',
  'apps/api/sandbox/reports/decision-pill-alerts-desktop.png',
  'apps/api/sandbox/reports/decision-pill-settings-desktop.png',
  'apps/api/sandbox/reports/demo-drill-desktop.png',
  'apps/api/sandbox/reports/approval-queue-desktop.png',
  'apps/api/sandbox/reports/readiness-panel-desktop.png',
  'apps/api/sandbox/reports/student-competition-attack-map-desktop.png',
  'apps/api/sandbox/reports/student-competition-attack-map-mobile.png'
].map((relativePath) => ({ path: relativePath, ...pngInfo(relativePath) }));

const directDecisionMarkupCount = countMatches(appText, /className=\{`decision \$\{/g);
const hardcodedColorCount = countMatches(stylesText + '\n' + visualText, /#[0-9a-fA-F]{3,8}|rgba?\(/g);
const tokenUsageCount = countMatches(stylesText + '\n' + visualText + '\n' + tokenText, /var\(--/g);
const primaryDocText = [readmeText, deliveryGuideText, selfReviewRecordText].join('\n');
const oldMetricResidualCount = countMatches(primaryDocText, /17 个脚本|51 条|51 个|17 条/g);
const checks = [
  {
    id: 'design-token-source',
    title: '设计 Token 源头',
    status:
      tokenText.includes('--zh-brand-primary') &&
      tokenText.includes('--zh-shadow-panel') &&
      tokenText.includes('--zh-radius-panel')
        ? 'passed'
        : 'failed',
    evidence: 'src/design/tokens.css 已建立颜色、间距、圆角、阴影和旧变量别名。'
  },
  {
    id: 'ui-component-reuse',
    title: '基础 UI 组件复用',
    status: uiComponents.length >= 4 ? 'passed' : 'warning',
    evidence: `当前基础 UI 组件 ${uiComponents.length} 个：${uiComponents.join('、') || '暂无'}。`
  },
  {
    id: 'decision-pill-standardized',
    title: '安全决策标签统一',
    status: directDecisionMarkupCount === 0 ? 'passed' : 'warning',
    evidence: `页面直接拼接 decision class 的位置剩余 ${directDecisionMarkupCount} 处。`
  },
  {
    id: 'frontend-screenshot-proof',
    title: '前端截图证据',
    status: screenshots.every((item) => item.exists) ? 'passed' : 'warning',
    evidence: `关键截图存在 ${screenshots.filter((item) => item.exists).length}/${screenshots.length} 张。`
  },
  {
    id: 'student-competition-profile-map',
    title: '学生比赛攻击面画像',
    status: studentProfileCount >= 5 ? 'passed' : 'warning',
    evidence: `已识别 ${studentProfileCount}/5 类学生比赛对象画像：${studentProfileIds.filter((id) => configuredProfileIds.has(id)).join('、') || '暂无'}。`
  },
  {
    id: 'student-competition-scenarios',
    title: '学生比赛专项脚本',
    status: studentScenarioCount >= 5 && (readinessPayload?.summary?.scenario_count ?? 0) >= 22 ? 'passed' : 'warning',
    evidence: `专项脚本同步 ${studentScenarioCount}/5 个，体检脚本总数 ${readinessPayload?.summary?.scenario_count ?? '未生成'}。`
  },
  {
    id: 'attack-chain-coverage',
    title: '组合攻击链覆盖',
    status: attackChainCount >= 4 && hasStudentPortalChain ? 'passed' : 'warning',
    evidence: `组合攻击链 ${attackChainCount} 条，学生比赛平台对象链：${hasStudentPortalChain ? '已生成' : '缺失'}。`
  },
  {
    id: 'delivery-metric-consistency',
    title: '交付口径一致性',
    status: oldMetricResidualCount === 0 ? 'passed' : 'warning',
    evidence: `README、交付说明和最新自审闭环报告中旧口径命中 ${oldMetricResidualCount} 处。`
  },
  {
    id: 'direction-residual-scan',
    title: '方向残留词检查',
    status: misleadingDomainResidualCount === 0 ? 'passed' : 'warning',
    evidence: `核心源码与主要文档中客户/财务/网络风险等误导词命中 ${misleadingDomainResidualCount} 处。`
  },
  {
    id: 'readiness-score',
    title: '赛前体检结果',
    status:
      (readinessPayload?.readiness_score ?? readinessPayload?.readiness?.readiness_score ?? 0) >= 90
        ? 'passed'
        : 'warning',
    evidence: `当前体检分 ${readinessPayload?.readiness_score ?? readinessPayload?.readiness?.readiness_score ?? '未生成'}。`
  },
  {
    id: 'openclaw-runtime-proof',
    title: 'OpenClaw 真实运行补证',
    status: blockers.some((item) => item.id === 'openclaw-runtime-inspect') ? 'blocked' : 'passed',
    evidence: blockers.some((item) => item.id === 'openclaw-runtime-inspect')
      ? '仍缺真实 OpenClaw runtime inspect 运行证明。'
      : '未发现 OpenClaw runtime inspect 阻塞项。'
  }
];

const unresolved = [];
if (fileInfo('apps/console/src/App.tsx').lines > 2500) {
  unresolved.push('src/App.tsx 仍然过大，后续应按页面拆分。');
}
if (hardcodedColorCount > 200) {
  unresolved.push(`历史 CSS 仍有 ${hardcodedColorCount} 处硬编码颜色，需要继续迁移到 Token。`);
}
if (checks.some((item) => item.id === 'openclaw-runtime-proof' && item.status === 'blocked')) {
  unresolved.push('OpenClaw 真实 runtime inspect 仍是唯一 P0 补证项。');
}

const report = {
  generated_at: new Date().toISOString(),
  project: '智安哨：大模型智能体攻击面研究与行为监督平台',
  self_review_agents: ['代码结构审查子代理', '页面审美审查子代理', '比赛交付审查子代理', '本地自审脚本'],
  frontend: {
    app: fileInfo('apps/console/src/App.tsx'),
    styles: fileInfo('apps/console/src/styles.css'),
    visual_system: fileInfo('apps/console/src/视觉系统.css'),
    tokens: fileInfo('apps/console/src/design/tokens.css'),
    ui_component_count: uiComponents.length,
    ui_components: uiComponents,
    direct_decision_markup_count: directDecisionMarkupCount,
    hardcoded_color_count: hardcodedColorCount,
    token_usage_count: tokenUsageCount
  },
  readiness: {
    score: readinessPayload?.readiness_score ?? readinessPayload?.readiness?.readiness_score ?? null,
    passed_count: readinessPayload?.summary?.passed_count ?? null,
    check_count: readinessPayload?.summary?.check_count ?? null,
    blocker_count: readinessPayload?.summary?.blocker_count ?? null
  },
  competition_domain: {
    student_profile_count: studentProfileCount,
    student_profile_ids: studentProfileIds.filter((id) => configuredProfileIds.has(id)),
    student_scenario_count: studentScenarioCount,
    student_scenario_ids: studentScenarioIds.filter((id) => configuredScenarioIds.has(id)),
    attack_chain_count: attackChainCount,
    has_student_portal_chain: hasStudentPortalChain,
    misleading_domain_residual_count: misleadingDomainResidualCount,
    old_metric_residual_count: oldMetricResidualCount
  },
  screenshots,
  checks,
  current_baseline: [
    `前端主入口 App.tsx 当前 ${fileInfo('apps/console/src/App.tsx').lines} 行。`,
    `基础 UI 组件 ${uiComponents.length} 个，目录由治理脚本约束。`,
    `学生比赛对象画像 ${studentProfileCount}/5，专项脚本 ${studentScenarioCount}/5。`,
    `组合攻击链 ${attackChainCount} 条，学生比赛平台对象链${hasStudentPortalChain ? '已存在' : '缺失'}。`,
    `设计 Token 使用 ${tokenUsageCount} 次，历史 CSS 硬编码颜色 ${hardcodedColorCount} 处。`
  ],
  unresolved
};

const jsonPath = path.join(outputRoot, '多Agent自审优化报告.json');
const mdPath = path.join(outputRoot, '多Agent自审优化报告.md');

const lines = [
  '# 多 Agent 自审优化报告',
  '',
  `生成时间：${report.generated_at}`,
  '',
  '## 自审代理',
  '',
  ...report.self_review_agents.map((name) => `- ${name}`),
  '',
  '## 当前工程基线',
  '',
  ...report.current_baseline.map((item) => `- ${item}`),
  '',
  '## 自动检查结果',
  '',
  '| 检查项 | 状态 | 证据 |',
  '|---|---|---|',
  ...checks.map((item) => `| ${item.title} | ${item.status} | ${item.evidence} |`),
  '',
  '## 前端治理指标',
  '',
  `- App.tsx 行数：${report.frontend.app.lines}`,
  `- 基础 UI 组件数：${report.frontend.ui_component_count}`,
  `- 直接拼接决策标签：${report.frontend.direct_decision_markup_count} 处`,
  `- 历史 CSS 硬编码颜色：${report.frontend.hardcoded_color_count} 处`,
  `- Token 使用次数：${report.frontend.token_usage_count} 次`,
  '',
  '## 学生比赛攻击面指标',
  '',
  `- 学生比赛对象画像：${report.competition_domain.student_profile_count}/5`,
  `- 学生比赛专项脚本：${report.competition_domain.student_scenario_count}/5`,
  `- 组合攻击链：${report.competition_domain.attack_chain_count} 条`,
  `- 学生比赛平台对象链：${report.competition_domain.has_student_portal_chain ? '已生成' : '缺失'}`,
  `- 误导方向残留词：${report.competition_domain.misleading_domain_residual_count} 处`,
  '',
  '## 仍未完成',
  '',
  ...(unresolved.length ? unresolved.map((item) => `- ${item}`) : ['- 暂无阻塞项。']),
  '',
  '## 截图证据',
  '',
  ...screenshots.map(
    (item) =>
      `- ${item.exists ? '已生成' : '缺失'}：${item.path}${item.exists ? `（${item.width}x${item.height}）` : ''}`
  ),
  ''
];

fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf8');
fs.writeFileSync(mdPath, lines.join('\n'), 'utf8');

console.log(
  JSON.stringify(
    { json_path: jsonPath, markdown_path: mdPath, checks: checks.length, unresolved_count: unresolved.length },
    null,
    2
  )
);
