import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  compareGatewayIdentity,
  identityNeedsWarning,
  identityNote
} from './project-self-review-identity.mjs';

const root = process.cwd();

// The API process loads the repository .env before calculating its gateway
// evidence fingerprint.  This script is a separate Node process, so it must
// reproduce that startup rule or every probe generated with repository
// configuration will look stale.  Only values absent from the process
// environment are loaded; CI/explicit shell settings keep precedence.
function loadEnvironmentFile() {
  const envPath = path.join(root, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const rawLine of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || !line.includes('=')) continue;
    const separator = line.indexOf('=');
    const key = line.slice(0, separator).trim();
    if (!/^[A-Z_][A-Z0-9_]*$/.test(key) || process.env[key] !== undefined) continue;
    let value = line.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadEnvironmentFile();

function currentGatewayFingerprint(functionName) {
  const python = process.env.AGENT_SUPERVISOR_PYTHON || process.env.PYTHON || 'python';
  const result = spawnSync(
    python,
    [
      '-c',
      `from apps.api.agent_supervisor.domains.reports.gateway_evidence import ${functionName}; print(${functionName}())`
    ],
    { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
  );
  if (result.status !== 0 || typeof result.stdout !== 'string') return '';
  const value = result.stdout.trim();
  return /^[0-9a-f]{64}$/i.test(value) ? value : '';
}

function currentGatewaySourceFingerprint() {
  return currentGatewayFingerprint('gateway_source_fingerprint');
}

function currentGatewayCodeFingerprint() {
  return currentGatewayFingerprint('gateway_code_fingerprint');
}

function readText(relativePath) {
  const fullPath = path.join(root, relativePath);
  return fs.existsSync(fullPath) ? fs.readFileSync(fullPath, 'utf8') : '';
}

function loadJson(relativePath) {
  const text = readText(relativePath);
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function countMatches(text, pattern) {
  return (text.match(pattern) ?? []).length;
}

function fileInfo(relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) return { exists: false, lines: 0, bytes: 0 };
  const text = fs.readFileSync(fullPath, 'utf8');
  return { exists: true, lines: text.split(/\r?\n/).length, bytes: Buffer.byteLength(text) };
}

function latestReport(prefix) {
  const reportsDir = path.join(root, 'apps', 'api', 'sandbox', 'reports');
  if (!fs.existsSync(reportsDir)) return '';
  const candidates = fs
    .readdirSync(reportsDir)
    .filter((name) => name.startsWith(prefix) && name.endsWith('.json'))
    .sort();
  return candidates.length ? path.join('apps/api/sandbox/reports', candidates.at(-1)) : '';
}

function latestGatewayProbe() {
  const reportsDir = path.join(root, 'apps', 'api', 'sandbox', 'reports');
  if (!fs.existsSync(reportsDir)) return '';
  const candidates = fs
    .readdirSync(reportsDir)
    // Evidence filenames changed during the gateway convergence work
    // (timestamped ``LLM网关探针-*`` artifacts and operator-selected
    // ``current-gateway-probe-*`` paths).  The schema/source contract is the
    // authoritative selector; relying on one filename prefix can silently
    // choose an older report and mark current code as stale.
    .filter((name) => name.endsWith('.json'))
    .map((name) => {
      const relative = path.join('apps/api/sandbox/reports', name);
      const payload = loadJson(relative);
      return { relative, payload };
    })
    .filter(
      ({ payload }) =>
        payload?.schema_version === 'agent-supervisor.gateway-probe.v1' &&
        payload?.probe_source === 'agent-supervisor-cli.gateway-probe' &&
        typeof payload?.gateway_evidence_fingerprint === 'string' &&
        payload.gateway_evidence_fingerprint.length === 64
    )
    .sort((left, right) =>
      String(right.payload.generated_at ?? '').localeCompare(String(left.payload.generated_at ?? ''))
    );
  return candidates.length ? candidates[0].relative : '';
}

function latestGatewayAgentRun() {
  const reportsDir = path.join(root, 'apps', 'api', 'sandbox', 'reports');
  if (!fs.existsSync(reportsDir)) return '';
  const candidates = fs
    .readdirSync(reportsDir)
    // Keep operator-selected, timestamped, and fixed paths in one candidate
    // set.  The schema/source contract below prevents unrelated JSON reports
    // from being treated as Agent gateway evidence.
    .filter((name) => name.endsWith('.json'))
    .map((name) => {
      const relative = path.join('apps/api/sandbox/reports', name);
      const payload = loadJson(relative);
      return { relative, payload };
    })
    .filter(
      ({ payload }) =>
        payload?.schema_version === 'agent-supervisor.gateway-agent-run.v1' &&
        payload?.source === 'agent-supervisor-cli.gateway-agent-run' &&
        typeof payload?.gateway_evidence_fingerprint === 'string' &&
        payload.gateway_evidence_fingerprint.length === 64
    )
    .sort((left, right) =>
      String(right.payload.generated_at ?? '').localeCompare(String(left.payload.generated_at ?? ''))
    );
  return candidates.length ? candidates[0].relative : '';
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
const readmeText = readText('README.md');
const architectureText = readText('PROJECT_ARCHITECTURE.md');
const gatewaySourceText = [
  readText('apps/api/agent_supervisor/adapters/proxy/openai_proxy.py'),
  readText('apps/api/agent_supervisor/adapters/proxy/proxy_security.py'),
  readText('apps/api/agent_supervisor/adapters/proxy/responses_compat.py'),
  readText('apps/api/agent_supervisor/routers/proxy.py'),
  readText('apps/api/agent_supervisor/domains/runtime/execution_receipts.py'),
  readText('apps/api/agent_supervisor/domains/runtime/gateway_execution.py'),
  readText('apps/api/agent_supervisor/mcp_gateway/gateway.py'),
  readText('apps/api/agent_supervisor/routers/mcp.py')
].join('\n');

// The current product artifact is the gateway readiness report. The legacy
// competition report is only a fallback for older workspaces.
const readinessPath = 'apps/api/sandbox/reports/AI Agent安全网关就绪检查.json';
const readiness = loadJson(readinessPath) ?? loadJson('apps/api/sandbox/reports/赛前一键体检报告.json');
const readinessPayload = readiness?.summary ? readiness : (readiness?.readiness ?? readiness);
const readinessSummary = readinessPayload?.summary ?? {};
const readinessChecks = Array.isArray(readinessPayload?.checks) ? readinessPayload.checks : [];
const checkById = new Map(readinessChecks.map((item) => [item?.id, item]));
const gatewayCheck = checkById.get('llm-gateway-execution-boundary');
const realModelCheck = checkById.get('real-model-agent-evidence');
const gatewayDetails = gatewayCheck?.details ?? {};
const realModelDetails = realModelCheck?.details?.summary ?? {};
const latestProbePath = latestGatewayProbe();
const latestProbe = latestProbePath ? loadJson(latestProbePath) : null;
const latestAgentRunPath = latestGatewayAgentRun();
const latestAgentRun = latestAgentRunPath ? loadJson(latestAgentRunPath) : null;
const currentSourceFingerprint = currentGatewaySourceFingerprint();
const currentCodeFingerprint = currentGatewayCodeFingerprint();
const probeIdentity = compareGatewayIdentity(latestProbe, {
  currentCodeFingerprint,
  currentSourceFingerprint
});
const agentRunIdentity = compareGatewayIdentity(latestAgentRun, {
  currentCodeFingerprint,
  currentSourceFingerprint
});
// A readiness JSON generated before the current probe is not a fresh runtime
// fact.  Require the current CLI artifact marker here; the Python readiness
// gate additionally verifies its source/config fingerprint and age.
// A probe can be internally valid yet belong to a different running gateway
// configuration.  When a current batch harness exists, require the probe and
// harness to carry the same boundary fingerprint before calling the probe
// current; otherwise an old "latest" file can create a false green check.
const probeFingerprintMatchesHarness =
  !latestAgentRun?.gateway_evidence_fingerprint ||
  latestProbe?.gateway_evidence_fingerprint === latestAgentRun.gateway_evidence_fingerprint;
const probeSourceMatchesCurrent =
  probeIdentity.source_fingerprint_matches_current;
const agentRunSourceMatchesCurrent =
  agentRunIdentity.source_fingerprint_matches_current;
const probeCodeMatchesCurrent = probeIdentity.code_fingerprint_matches_current;
const agentRunCodeMatchesCurrent = agentRunIdentity.code_fingerprint_matches_current;
const gatewayProbePassed =
  latestProbe?.contract?.passed === true &&
  Boolean(latestProbe?.gateway_evidence_fingerprint) &&
  probeFingerprintMatchesHarness &&
  probeIdentity.current_identity_valid;
const gatewayAgentRunPassed =
  latestAgentRun?.summary?.evidence_verdict === 'complete' &&
  latestAgentRun?.summary?.gateway_contract_passed_count === latestAgentRun?.summary?.case_count &&
  latestAgentRun?.gateway_path_exercised === true &&
  Boolean(latestAgentRun?.gateway_evidence_fingerprint) &&
  agentRunIdentity.current_identity_valid;
const strictRealModelReady =
  readinessSummary.real_model_strict_ready === true || realModelDetails.strict_real_api_ready === true;
const mcpGatewayConfigured = gatewayDetails.gateway_enabled === true;
const gatewayEvidenceCodeStale = Boolean(
  (latestProbe && !probeIdentity.current_identity_valid) ||
  (latestAgentRun && !agentRunIdentity.current_identity_valid)
);
const gatewayEvidenceContextMismatch = Boolean(
  (latestProbe && identityNeedsWarning(probeIdentity)) ||
  (latestAgentRun && identityNeedsWarning(agentRunIdentity))
);
const toolAllowlistCount = Number(readinessSummary.agent_tool_allowlist_count ?? 0);
const apiAllowlistCount = Number(readinessSummary.agent_api_allowlist_count ?? 0);
const modelAllowlistCount = Number(readinessSummary.agent_model_allowlist_count ?? 0);
const contextAllowlistCount = Number(readinessSummary.agent_context_allowlist_count ?? 0);
// Prefer the current HTTP evidence over the checked-in/readiness snapshot.
// The snapshot is intentionally historical between runs; using it here made
// a freshly verified production-style receipt requirement appear disabled.
const serverObservedReceiptsRequired =
  latestAgentRun?.summary?.server_observed_receipts_required === true ||
  latestProbe?.gateway?.tool_receipt_server_observed_required === true ||
  gatewayDetails.server_observed_receipts_required === true;
const receiptIntegrityImplemented =
  gatewaySourceText.includes('provider_request_hash') &&
  gatewaySourceText.includes('provider_response_hash') &&
  gatewaySourceText.includes('verify_execution_receipt');
const executionProvenanceImplemented =
  gatewaySourceText.includes('proxy_server_observed_receipts_required') &&
  gatewaySourceText.includes('execution_observed_by_server') &&
  gatewaySourceText.includes('server_observed=True');
const reviewTracks = ['网关代码路径审查', 'Provider 边界审查', 'MCP 执行边界审查', '本地确定性自审脚本'];

// A boundary statement that explicitly rejects an old direction is useful
// documentation, not an implementation residual.  Remove those lines before
// scanning so the self-review does not manufacture a warning from the very
// sentence that defines the product boundary.
const directionScanText = [readmeText, architectureText, gatewaySourceText, appText]
  .join('\n')
  .split(/\r?\n/)
  .filter((line) => !/不属于本项目当前边界|历史.*方向|不计入.*主线/.test(line))
  .join('\n');
const legacyDirectionResidualCount = countMatches(
  directionScanText,
  /\b(?:nmap|nuclei|masscan|zeek|pcap|semgrep|trivy|gitleaks)\b|网络扫描|流量分析|代码审计/gi
);
const directDecisionMarkupCount = countMatches(appText, /className=\{`decision \$\{/g);
const hardcodedColorCount = countMatches(stylesText + '\n' + visualText, /#[0-9a-fA-F]{3,8}|rgba?\(/g);
const tokenUsageCount = countMatches(stylesText + '\n' + visualText + '\n' + tokenText, /var\(--/g);
const uiDir = path.join(root, 'apps', 'console', 'src', 'components', 'ui');
const uiComponents = fs.existsSync(uiDir)
  ? fs.readdirSync(uiDir).filter((name) => name.endsWith('.tsx') && !name.endsWith('.test.tsx'))
  : [];

const checks = [
  {
    id: 'gateway-code-path',
    title: 'LLM API / MCP 真实代码路径',
    status:
      (gatewaySourceText.includes('/v1/chat/completions') || gatewaySourceText.includes('/v1/responses')) &&
      gatewaySourceText.includes('provider_called') &&
      gatewaySourceText.includes('tool_receipt') &&
      gatewaySourceText.includes('tools/call')
        ? 'passed'
        : 'blocked',
    evidence: '源码包含 OpenAI 兼容入口、Provider 阶段事实、工具回执绑定和 MCP tools/call 闸门。'
  },
  {
    id: 'gateway-http-probe',
    title: '真实 HTTP 网关契约探针',
    status: gatewayProbePassed
      ? identityNeedsWarning(probeIdentity)
        ? 'warning'
        : 'passed'
      : gatewayAgentRunPassed
        ? 'warning'
        : 'blocked',
    evidence: gatewayProbePassed
      ? `最新探针 ${latestProbePath || '由就绪报告记录'} 已通过；决策 ${latestProbe?.contract?.decision || gatewayDetails.gateway_probe_contract?.decision || '已记录'}；${identityNote(probeIdentity, '探针')}`
      : gatewayEvidenceCodeStale
        ? `已有网关证据，但${identityNote(probeIdentity, '探针')}`
      : gatewayAgentRunPassed
        ? `独立探针契约未通过；批量 Harness ${latestAgentRunPath} 已覆盖当前 HTTP 网关契约；${identityNote(probeIdentity, '探针')}`
        : '尚未找到通过的 LLM 网关契约探针；单元测试和本地 fixture 不替代 HTTP 边界证据。'
  },
  {
    id: 'gateway-agent-http-harness',
    title: '真实 Agent 批量 HTTP 网关证据',
    status: gatewayAgentRunPassed
      ? identityNeedsWarning(agentRunIdentity)
        ? 'warning'
        : 'passed'
      : gatewayProbePassed
        ? 'warning'
        : 'blocked',
    evidence: gatewayAgentRunPassed
      ? `批量 Harness ${latestAgentRunPath} 已通过，样本 ${latestAgentRun?.summary?.case_count ?? '未知'} 条；${identityNote(agentRunIdentity, 'Harness')}`
      : gatewayEvidenceCodeStale
        ? `批量 Harness ${latestAgentRunPath || '已有报告'} 身份未通过；${identityNote(agentRunIdentity, 'Harness')}`
        : '尚未找到通过的 gateway-agent-run；模型行为评测不替代真实 Agent HTTP 边界证据。'
  },
  {
    id: 'strict-real-model-evidence',
    title: '真实 Provider / Agent 工具调用证据',
    status: strictRealModelReady ? 'passed' : 'blocked',
    evidence: strictRealModelReady
      ? `真实模型严格证据已就绪，样本 ${realModelDetails.case_count ?? '未知'} 条。`
      : `当前真实模型证据状态为 ${realModelDetails.evidence_verdict ?? readinessSummary.real_model_evidence_verdict ?? '缺失'}，不能把历史报告当作当前结论。`
  },
  {
    id: 'mcp-upstream-boundary',
    title: 'MCP 强制上游边界',
    status: mcpGatewayConfigured ? 'passed' : 'warning',
    evidence: mcpGatewayConfigured
      ? 'MCP 上游已配置，需继续用独立上游 trace 验证阻断不到达。'
      : '当前没有配置 MCP 上游；MCP 网关代码存在，但本机还没有可运行的上游服务。'
  },
  {
    id: 'least-privilege-registration',
    title: 'Agent 工具、外部 API、模型最小权限',
    status: toolAllowlistCount > 0 && apiAllowlistCount > 0 && modelAllowlistCount > 0 ? 'passed' : 'warning',
    evidence: `工具白名单 ${toolAllowlistCount}，外部 API 白名单 ${apiAllowlistCount}，模型白名单 ${modelAllowlistCount}，MCP 上下文白名单 ${contextAllowlistCount}；四者是独立权限边界。`
  },
  {
    id: 'audit-receipt-integrity',
    title: '审计 Hash/HMAC 与回执内容完整性',
    status: receiptIntegrityImplemented ? 'passed' : 'blocked',
    evidence: receiptIntegrityImplemented
      ? 'Provider 请求/响应 Hash、审计 ID 与回执内容校验已实现；该项只证明记录未被替换，不等同于工具实际执行。'
      : 'Provider 请求/响应 Hash、审计 ID 或回执内容校验代码不完整。'
  },
  {
    id: 'execution-receipt-provenance',
    title: '工具执行回执来源真实性',
    status: executionProvenanceImplemented && serverObservedReceiptsRequired ? 'passed' : 'blocked',
    evidence:
      executionProvenanceImplemented && serverObservedReceiptsRequired
        ? '当前就绪快照要求 server-observed 回执，且源码仅由网关自有执行路径写入服务端观察标记。'
        : executionProvenanceImplemented
          ? '源码已区分 caller-declared 与 server-observed，但当前就绪快照尚未证明服务端观察策略为强制。'
          : '源码尚未形成调用方声明、服务端观察与生产强制策略三者闭环。'
  },
  {
    id: 'direction-residual-scan',
    title: '废弃方向残留检查',
    status: legacyDirectionResidualCount === 0 ? 'passed' : 'warning',
    evidence: `当前主线代码与主要文档中的 Nmap/流量/代码审计等历史方向残留 ${legacyDirectionResidualCount} 处；历史 Trae 文档不计入运行时主线。`
  },
  {
    id: 'frontend-runtime-entry',
    title: '控制台默认入口',
    status: readText('apps/console/src/app/navigation.tsx').includes("defaultPage: PageKey = 'gateway'")
      ? 'passed'
      : 'warning',
    evidence: '控制台默认页面应直接进入 LLM API / MCP 网关，实验室与报告仅作为按需验证入口。'
  },
  {
    id: 'readiness-source',
    title: '就绪报告来源一致性',
    status: readinessPayload ? 'passed' : 'blocked',
    evidence: readinessPayload
      ? `当前就绪分 ${readinessPayload.readiness_score ?? '未知'}，状态 ${readinessPayload.status_label ?? '未知'}。`
      : '尚未生成当前 AI Agent 网关就绪报告。'
  }
];

const unresolved = checks.filter((item) => item.status === 'blocked').map((item) => `${item.title}：${item.evidence}`);
if (fileInfo('apps/console/src/App.tsx').lines > 300) {
  unresolved.push('src/App.tsx 超过前端入口行数预算，应保持页面按需懒加载。');
}
if (hardcodedColorCount > 25) {
  unresolved.push(`CSS 硬编码颜色 ${hardcodedColorCount} 处，超过治理预算。`);
}

const report = {
  generated_at: new Date().toISOString(),
  project: '智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关',
  // This artifact is generated by one deterministic Node process.  The labels
  // below are review tracks, not independent agents or cross-model consensus.
  execution_model: 'single-process-deterministic-evidence-aggregation',
  independent_agent_count: 0,
  review_tracks: reviewTracks,
  // Keep the old field explicit and empty for consumers that still read it;
  // putting review-track names in an `agents` field would overclaim independent
  // validation and make the evidence package less trustworthy.
  self_review_agents: [],
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
    score: readinessPayload?.readiness_score ?? null,
    status: readinessPayload?.overall_status ?? null,
    passed_count: readinessSummary.passed_count ?? null,
    check_count: readinessSummary.check_count ?? null,
    blocker_count: readinessSummary.blocker_count ?? null
  },
  gateway: {
    probe_passed: gatewayProbePassed,
    current_code_fingerprint: currentCodeFingerprint,
    current_source_fingerprint: currentSourceFingerprint,
    current_deployment_source_fingerprint: currentSourceFingerprint,
    latest_probe_identity: probeIdentity,
    latest_probe_code_matches_current: probeCodeMatchesCurrent,
    latest_probe_source_matches_current: probeSourceMatchesCurrent,
    latest_probe_path: latestProbePath,
    latest_probe_contract: latestProbe?.contract ?? gatewayDetails.gateway_probe_contract ?? null,
    agent_run_passed: gatewayAgentRunPassed,
    latest_agent_run_identity: agentRunIdentity,
    latest_agent_run_code_matches_current: agentRunCodeMatchesCurrent,
    latest_agent_run_source_matches_current: agentRunSourceMatchesCurrent,
    latest_agent_run_path: latestAgentRunPath,
    latest_agent_run_summary: latestAgentRun?.summary ?? null,
    deployment_context_mismatch: gatewayEvidenceContextMismatch,
    code_identity_stale: gatewayEvidenceCodeStale,
    strict_real_model_ready: strictRealModelReady,
    mcp_upstream_configured: mcpGatewayConfigured,
    receipt_integrity_implemented: receiptIntegrityImplemented,
    execution_provenance_implemented: executionProvenanceImplemented,
    server_observed_receipts_required: serverObservedReceiptsRequired,
    tool_allowlist_count: toolAllowlistCount,
    api_allowlist_count: apiAllowlistCount,
    model_allowlist_count: modelAllowlistCount,
    context_allowlist_count: contextAllowlistCount
  },
  checks,
  current_baseline: [
    `LLM API / MCP 网关代码路径检查：${checks.find((item) => item.id === 'gateway-code-path')?.status}。`,
    `HTTP 契约探针：${gatewayProbePassed ? '通过' : '缺失或失败'}；${identityNote(probeIdentity, '探针')}`,
    `真实 Agent HTTP Harness：${gatewayAgentRunPassed ? '通过' : '缺失或失败'}；${identityNote(agentRunIdentity, 'Harness')}`,
    `真实模型严格证据：${strictRealModelReady ? '已就绪' : '未就绪'}；历史模型报告不自动继承为当前结论。`,
    `执行回执来源：${serverObservedReceiptsRequired ? '强制服务端观察' : '尚未由当前就绪快照证明'}；Hash/HMAC 不单独作为实际执行证据。`,
    `默认控制台入口：${readText('apps/console/src/app/navigation.tsx').includes("defaultPage: PageKey = 'gateway'") ? 'gateway' : '非 gateway'}。`,
    `设计 Token 使用 ${tokenUsageCount} 次，CSS 硬编码颜色 ${hardcodedColorCount} 处。`
  ],
  unresolved
};

const jsonPath = path.join(outputRoot, '多Agent自审优化报告.json');
const mdPath = path.join(outputRoot, '多Agent自审优化报告.md');
const lines = [
  '# AI Agent 网关对抗式自审报告',
  '',
  `生成时间：${report.generated_at}`,
  '',
  '> 说明：本报告由 `scripts/project-self-review.mjs` 单进程生成；下列为审查轨道，不是多个独立 Agent 的交叉结论。',
  '',
  '## 审查范围',
  '',
  ...report.review_tracks.map((name) => `- ${name}`),
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
  '## 网关证据',
  '',
  `- 最新 HTTP 探针：${report.gateway.latest_probe_path || '未找到'}`,
  `- 探针契约：${report.gateway.probe_passed ? '通过' : '缺失或失败'}`,
  `- 真实 Agent HTTP Harness：${report.gateway.agent_run_passed ? '通过' : '缺失或失败'}`,
  `- Harness 报告：${report.gateway.latest_agent_run_path || '未找到'}`,
  `- 当前代码指纹：${report.gateway.current_code_fingerprint || '未生成'}`,
  `- 当前部署 source/config 指纹：${report.gateway.current_deployment_source_fingerprint || '未生成'}`,
  `- 证据上下文：${report.gateway.deployment_context_mismatch ? 'context mismatch（代码一致、部署配置不同）' : '一致或未发现差异'}`,
  `- 源码身份：${report.gateway.code_identity_stale ? '未通过' : '当前代码一致'}`,
  `- Provider / Agent 严格证据：${report.gateway.strict_real_model_ready ? '已就绪' : '未就绪'}`,
  `- MCP 上游：${report.gateway.mcp_upstream_configured ? '已配置' : '未配置'}`,
  `- 工具结果回执：${report.gateway.server_observed_receipts_required ? '强制服务端观察' : '当前证据未证明强制'}`,
  '',
  '## 未完成项',
  '',
  ...(unresolved.length ? unresolved.map((item) => `- ${item}`) : ['- 暂无代码级阻塞项；运行时证据仍以就绪报告为准。']),
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
