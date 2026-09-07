import { expect, test, type Page } from 'playwright/test';

const ADMIN_TOKEN = 'e2e-admin-token';
const OBSERVER_TOKEN = 'e2e-observer-token';
const EXECUTOR_TOKEN = 'e2e-executor-token';
const PROVIDER_STATS_URL = 'http://127.0.0.1:18081/_fixture/stats';

async function login(page: Page, token = ADMIN_TOKEN) {
  await page.goto('/#/gateway');
  await expect(page.getByRole('heading', { name: '连接安全控制台' })).toBeVisible();
  await page.getByRole('textbox', { name: '运行 Token' }).fill(token);
  await page.getByRole('button', { name: '验证并进入' }).click();
  await expect(page.getByRole('heading', { name: '请求防护' })).toBeVisible();
}

async function sendGatewayRequest(page: Page, payload?: Record<string, unknown>) {
  if ((await page.getByRole('button', { name: '发送到网关' }).count()) === 0) {
    await page.getByRole('button', { name: '验证防护' }).click();
  }
  if (payload) {
    await page.getByRole('textbox', { name: '网关请求 JSON' }).fill(JSON.stringify(payload, null, 2));
  }
  const responsePromise = page.waitForResponse(
    (response) => response.url().endsWith('/v1/chat/completions') && response.request().method() === 'POST'
  );
  await page.getByRole('button', { name: '发送到网关' }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(200);
  return (await response.json()) as { agent_supervisor?: Record<string, unknown> };
}

async function sendStreamingGatewayRequest(page: Page, payload: Record<string, unknown>) {
  if ((await page.getByRole('button', { name: '发送到网关' }).count()) === 0) {
    await page.getByRole('button', { name: '验证防护' }).click();
  }
  await page
    .getByRole('textbox', { name: '网关请求 JSON' })
    .fill(JSON.stringify({ ...payload, stream: true }, null, 2));
  const responsePromise = page.waitForResponse(
    (response) => response.url().endsWith('/v1/chat/completions') && response.request().method() === 'POST'
  );
  await page.getByRole('button', { name: '发送到网关' }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(200);
  expect(response.headers()['content-type']).toContain('text/event-stream');
  await expect(page.getByText('安全流实时预览')).toBeVisible();
  await expect(page.getByText('已完成')).toBeVisible();
}

async function providerRequestCount(page: Page) {
  const response = await page.request.get(PROVIDER_STATS_URL);
  expect(response.ok()).toBeTruthy();
  return Number(((await response.json()) as { request_count?: number }).request_count ?? 0);
}

test.describe.serial('运营网关黑盒验收', () => {
  test('320x480 登录失败后仍可滚动到全部操作按钮', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 480 });
    await page.goto('/#/gateway');
    await page.getByRole('textbox', { name: '运行 Token' }).fill('wrong-token');
    await page.getByRole('button', { name: '验证并进入' }).click();
    await expect(page.getByText('凭证未通过校验，请检查后重新输入。')).toBeVisible();

    const authPage = page.locator('.zh-auth-page');
    await expect(authPage).toHaveCSS('overflow-y', 'auto');
    const retryButton = page.getByRole('button', { name: '重新检测后端' });
    await retryButton.scrollIntoViewIfNeeded();
    const buttonBox = await retryButton.boundingBox();
    expect(buttonBox).not.toBeNull();
    expect((buttonBox?.y ?? 0) + (buttonBox?.height ?? 0)).toBeLessThanOrEqual(480);
  });

  test('冷启动只访问公开状态，错误凭证、只读权限和会话失效都有明确反馈', async ({ page }) => {
    const bootstrapApiPaths: string[] = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.pathname.startsWith('/api/')) bootstrapApiPaths.push(url.pathname);
    });

    await page.goto('/#/gateway');
    await expect(page.getByRole('heading', { name: '连接安全控制台' })).toBeVisible();
    await expect(page.getByText('智垒', { exact: true })).toBeVisible();
    await expect(page.getByText('智安哨', { exact: true })).toHaveCount(0);
    await expect(page).toHaveTitle('智垒 · AI Agent Firewall');
    await expect(page.getByText('后端在线')).toBeVisible();
    await expect(page.locator('.zh-auth-page')).toHaveCSS('display', 'flex');
    expect([...new Set(bootstrapApiPaths)]).toEqual(['/api/public/status']);

    await page.getByRole('textbox', { name: '运行 Token' }).fill('wrong-token');
    await page.getByRole('button', { name: '验证并进入' }).click();
    await expect(page.getByText('凭证未通过校验，请检查后重新输入。')).toBeVisible();

    await page.getByRole('textbox', { name: '运行 Token' }).fill(EXECUTOR_TOKEN);
    await page.getByRole('button', { name: '验证并进入' }).click();
    await expect(page.getByText(/当前凭证用于 Agent 运行，不具备控制台查看权限/)).toBeVisible();
    await expect(page.getByRole('heading', { name: '连接安全控制台' })).toBeVisible();

    await page.getByRole('textbox', { name: '运行 Token' }).fill(OBSERVER_TOKEN);
    await page.getByRole('button', { name: '验证并进入' }).click();
    await expect(page.getByRole('heading', { name: '请求防护' })).toBeVisible();
    const productionStyleBoundary = await page.evaluate(() => {
      const cssText = Array.from(document.styleSheets)
        .flatMap((sheet) => Array.from(sheet.cssRules, (rule) => rule.cssText))
        .join('\n');
      const mainContent = document.querySelector<HTMLElement>('.zh-main-content');
      return {
        hasOperationalSelector: cssText.includes('.zh-product-page'),
        hasExperimentSelector: cssText.includes('.zh-attack-lab'),
        mainOverflowY: mainContent ? getComputedStyle(mainContent).overflowY : ''
      };
    });
    expect(productionStyleBoundary).toEqual({
      hasOperationalSelector: true,
      hasExperimentSelector: false,
      mainOverflowY: 'auto'
    });
    await page.getByRole('button', { name: '验证防护' }).click();
    await expect(page.getByRole('button', { name: '发送到网关' })).toBeDisabled();
    await expect(page.getByText('当前凭证为观测角色')).toBeVisible();

    const forbidden = await page.request.post('/v1/chat/completions', {
      headers: { Authorization: `Bearer ${OBSERVER_TOKEN}`, 'X-Agent-Session-ID': 'observer-e2e' },
      data: { model: 'e2e-fixture-model', messages: [{ role: 'user', content: 'hello' }] }
    });
    expect(forbidden.status()).toBe(403);

    await page.getByRole('button', { name: 'Close' }).click();
    // Close the transient drawer before mutating the browser session. The
    // realtime connection may observe the invalid token immediately and
    // correctly unmount the authenticated workspace before a later UI action.
    await page.evaluate(() => sessionStorage.setItem('agent-supervisor-api-token', 'expired-token'));
    await page.getByRole('button', { name: '刷新数据' }).click();
    await expect(page.getByRole('heading', { name: '连接安全控制台' })).toBeVisible();
    await expect(page.getByText('当前会话已失效，请重新验证身份。')).toBeVisible();
  });

  test('真实 HTTP Provider 的允许、前置阻断、后置 Tool Call 阻断和 SSE Trace 形成闭环', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    await login(page);

    const overview = await page.request.get('/api/overview', {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(overview.status()).toBe(200);
    const overviewBody = (await overview.json()) as Record<string, unknown>;
    expect(overviewBody).not.toHaveProperty('attack_surfaces');
    expect(overviewBody).not.toHaveProperty('scenarios');
    expect(overviewBody).not.toHaveProperty('student_competition_attack_map');
    const removedRoute = await page.request.get('/api/scenarios', {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(removedRoute.status()).toBe(404);

    const clean = await sendGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'Summarize this clean operational request.' }]
    });
    expect(clean.agent_supervisor?.decision).toBe('允许');
    expect(clean.agent_supervisor?.provider_called).toBe(true);
    const cleanRequestId = String(clean.agent_supervisor?.request_id ?? '');
    expect(cleanRequestId).not.toBe('');
    for (const field of ['request_hash', 'provider_request_hash', 'provider_response_hash']) {
      expect(String(clean.agent_supervisor?.[field] ?? '')).toMatch(/^[0-9a-f]{64}$/i);
    }
    const cleanTraceResponse = await page.request.get(`/api/gateway/traces/${encodeURIComponent(cleanRequestId)}`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(cleanTraceResponse.status()).toBe(200);
    const cleanTrace = (await cleanTraceResponse.json()) as {
      request_id?: string;
      provider_called?: boolean;
      request_hash?: string;
      provider_request_hash?: string;
      provider_response_hash?: string;
      evidence?: { request_hash_bound?: boolean; provider_hash_bound?: boolean };
    };
    expect(cleanTrace).toMatchObject({
      request_id: cleanRequestId,
      provider_called: true,
      request_hash: clean.agent_supervisor?.request_hash,
      provider_request_hash: clean.agent_supervisor?.provider_request_hash,
      provider_response_hash: clean.agent_supervisor?.provider_response_hash,
      evidence: { request_hash_bound: true, provider_hash_bound: true }
    });
    await expect(page.getByRole('button', { name: new RegExp(cleanRequestId) })).toBeVisible();

    const beforeInjection = await providerRequestCount(page);
    await page.getByRole('button', { name: '注入测试' }).click();
    const injection = await sendGatewayRequest(page);
    expect(injection.agent_supervisor?.decision).toBe('拒绝');
    expect(injection.agent_supervisor?.provider_called).toBe(false);
    expect(await providerRequestCount(page)).toBe(beforeInjection);

    const beforeToolCall = await providerRequestCount(page);
    const toolCall = await sendGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'Inspect internal cluster health.' }],
      tools: [
        {
          type: 'function',
          function: {
            name: 'api_call',
            description: 'Read an approved service endpoint.',
            parameters: {
              type: 'object',
              properties: { endpoint: { type: 'string' }, method: { type: 'string' } },
              required: ['endpoint'],
              additionalProperties: false
            }
          }
        }
      ],
      tool_choice: 'auto'
    });
    expect(toolCall.agent_supervisor?.decision).toBe('拒绝');
    expect(toolCall.agent_supervisor?.provider_called).toBe(true);
    expect(await providerRequestCount(page)).toBe(beforeToolCall + 1);

    const toolRequestId = String(toolCall.agent_supervisor?.request_id ?? '');
    await expect(page.getByRole('button', { name: new RegExp(toolRequestId) })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { name: '请求防护' })).toBeVisible();
    await expect(page.getByRole('button', { name: new RegExp(toolRequestId) })).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test('真实Provider SSE逐块显示、跨块风险收口并保留终态证据', async ({ page }) => {
    await login(page);
    await page.getByRole('button', { name: '验证防护' }).click();

    await sendStreamingGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'long streaming narrative' }]
    });
    await expect(page.getByLabel('流式响应实时内容')).toContainText('verified-event-000');
    await expect(page.getByText('bounded-safety-window')).toBeVisible();
    await expect(page.getByText('真实Provider流')).toBeVisible();
    await expect(page.getByText('Provider流Chunk')).toBeVisible();

    await sendStreamingGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'split stream injection' }]
    });
    await expect(page.getByLabel('流式响应实时内容')).not.toContainText('fixture-secret-value');
    await expect(page.getByText('content_filter')).toBeVisible();
    await expect(page.getByText('流是否中断')).toBeVisible();

    await page.getByRole('textbox', { name: '网关请求 JSON' }).fill(
      JSON.stringify(
        {
          model: 'e2e-fixture-model',
          stream: true,
          messages: [{ role: 'user', content: 'stream interruption' }]
        },
        null,
        2
      )
    );
    await page.getByRole('button', { name: '发送到网关' }).click();
    await expect(page.getByText('已中断')).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('Provider流式响应失败或在完成前中断');
    await expect(page.getByText(/中断审计 ID：/)).toBeVisible();

    await page.getByRole('textbox', { name: '网关请求 JSON' }).fill(
      JSON.stringify(
        {
          model: 'e2e-fixture-model',
          stream: true,
          messages: [{ role: 'user', content: 'cancellable streaming narrative' }]
        },
        null,
        2
      )
    );
    await page.getByRole('button', { name: '发送到网关' }).click();
    await page.getByRole('button', { name: '停止接收' }).click();
    await expect(page.getByText('已中断')).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('流式请求已取消');
    await expect
      .poll(async () => {
        const audits = await page.request.get('/api/audit_logs?limit=100', {
          headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
        });
        const rows = (await audits.json()) as Array<{ stage_context?: { provider_failure_kind?: string } }>;
        return rows.some((row) => row.stage_context?.provider_failure_kind === 'client-cancelled-stream');
      })
      .toBe(true);
  });

  test('服务端托管 Tool Call 产生可验证回执，MCP JSON-RPC 走真实子进程', async ({ page }) => {
    await login(page);

    await page.getByRole('button', { name: '验证防护' }).click();
    const managedSwitch = page.getByRole('switch');
    await managedSwitch.click();
    await expect(managedSwitch).toBeChecked();
    const beforeManaged = await providerRequestCount(page);
    const managed = await sendGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'Please use file_read for the public project overview.' }],
      tools: [
        {
          type: 'function',
          function: {
            name: 'file_read',
            description: 'Read an approved public project file.',
            parameters: {
              type: 'object',
              properties: { path: { type: 'string' } },
              required: ['path'],
              additionalProperties: false
            }
          }
        }
      ],
      tool_choice: 'auto'
    });
    expect(managed.agent_supervisor?.decision).toBe('允许');
    expect(managed.agent_supervisor?.managed_status).toBe('completed');
    expect(managed.agent_supervisor?.tool_receipts_server_observed).toBeGreaterThanOrEqual(1);
    expect(await providerRequestCount(page)).toBe(beforeManaged + 2);
    const managedRequestId = String(managed.agent_supervisor?.request_id ?? '');
    const managedTraceResponse = await page.request.get(`/api/gateway/traces/${encodeURIComponent(managedRequestId)}`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(managedTraceResponse.status()).toBe(200);
    const managedTrace = (await managedTraceResponse.json()) as {
      request_id?: string;
      server_observed_execution_count?: number;
      receipt_count?: number;
      request_hash?: string;
      provider_response_hash?: string;
    };
    expect(managedTrace).toMatchObject({ request_id: managedRequestId });
    expect(Number(managedTrace.server_observed_execution_count ?? 0)).toBeGreaterThanOrEqual(1);
    expect(Number(managedTrace.receipt_count ?? 0)).toBeGreaterThanOrEqual(1);
    expect(String(managedTrace.request_hash ?? '')).toMatch(/^[0-9a-f]{64}$/i);
    expect(String(managedTrace.provider_response_hash ?? '')).toMatch(/^[0-9a-f]{64}$/i);
    const managedAuditIds = Array.isArray(managed.agent_supervisor?.managed_audit_ids)
      ? managed.agent_supervisor.managed_audit_ids.map((value) => String(value)).filter(Boolean)
      : [];
    expect(managedAuditIds.length).toBeGreaterThan(0);
    const receiptResponse = await page.request.get(
      `/api/runtime/executions/${encodeURIComponent(managedAuditIds[0])}`,
      {
        headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
      }
    );
    expect(receiptResponse.status()).toBe(200);
    const receiptBody = (await receiptResponse.json()) as {
      audit_id?: string;
      receipt?: {
        audit_id?: string;
        status?: string;
        execution_evidence?: string;
        execution_observed_by_server?: boolean;
        receipt_hash?: string;
        receipt_signature?: string;
        result_hash?: string;
      } | null;
    };
    expect(receiptBody.audit_id).toBe(managedAuditIds[0]);
    expect(receiptBody.receipt).toMatchObject({
      audit_id: managedAuditIds[0],
      status: 'completed',
      execution_evidence: 'server-observed',
      execution_observed_by_server: true
    });
    expect(String(receiptBody.receipt?.receipt_hash ?? '')).toMatch(/^[0-9a-f]{64}$/i);
    expect(String(receiptBody.receipt?.result_hash ?? '')).toMatch(/^[0-9a-f]{64}$/i);
    expect(String(receiptBody.receipt?.receipt_signature ?? '')).not.toBe('');
    await expect(page.getByText('服务端托管执行回执')).toBeVisible();

    await page.getByRole('button', { name: 'Close' }).click();
    await page.getByRole('tab', { name: 'MCP 工具' }).click();
    await expect(page.getByText('MCP JSON-RPC 实际入口')).toBeVisible();
    await page.getByRole('textbox', { name: 'MCP Agent 会话 ID' }).fill('mcp-e2e-session');

    await expect(page.getByRole('combobox', { name: 'MCP 协议版本' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'server/discover' })).toBeVisible();
    const discoverResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/mcp') && response.request().method() === 'POST'
    );
    await page.getByRole('button', { name: 'server/discover' }).click();
    const discover = await discoverResponse;
    expect(discover.status()).toBe(200);
    expect(discover.request().headers()['mcp-protocol-version']).toBe('2026-07-28');
    expect(discover.request().headers()['mcp-method']).toBe('server/discover');
    expect(discover.request().postDataJSON()).toMatchObject({
      method: 'server/discover',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': { sampling: {}, elicitation: {}, roots: {} }
        }
      }
    });

    const toolsListResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/mcp') && response.request().method() === 'POST'
    );
    await page.getByRole('button', { name: 'tools/list' }).click();
    const toolsList = await toolsListResponse;
    expect(toolsList.status()).toBe(200);
    const toolsBody = (await toolsList.json()) as { result?: { tools?: unknown[] } };
    expect(Array.isArray(toolsBody.result?.tools)).toBe(true);
    await expect(page.getByText(/当前响应可见工具：\d+ 个/)).toBeVisible();

    await page.getByRole('button', { name: '开始订阅' }).click();
    await expect(page.getByText('订阅已连接')).toBeVisible();

    await page.getByRole('switch', { name: 'MCP 实时进度' }).click();
    await page.getByRole('combobox', { name: 'MCP 日志级别' }).click();
    await page.getByText('warning 及以上').click();

    const inputRequiredResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/mcp') && response.request().method() === 'POST'
    );
    await page.getByRole('button', { name: 'tools/call' }).click();
    const inputRequired = await inputRequiredResponse;
    expect(inputRequired.status()).toBe(200);
    expect(inputRequired.headers()['content-type']).toContain('text/event-stream');
    // Chromium does not retain a CDP response body for every Fetch-consumed
    // stream. Assert the application-parsed state, then prove the protected
    // requestState is carried by the resume request below.
    await expect(page.getByText('MCP 需要操作员输入')).toBeVisible();
    await expect(page.getByText('上游 inputRequests')).toBeVisible();
    await expect(page.locator('pre.zh-evidence-code-block').filter({ hasText: '"srv-req-1"' }).first()).toContainText(
      'sampling/createMessage'
    );

    const resumeRequest = page.waitForRequest(
      (request) => request.url().endsWith('/api/mcp') && request.method() === 'POST'
    );
    await page.getByRole('button', { name: '提交输入并恢复' }).click();
    const resumePayload = (await resumeRequest).postDataJSON() as {
      params?: { requestState?: string; inputResponses?: Record<string, unknown> };
    };
    expect(resumePayload.params?.requestState).toBeTruthy();
    expect(resumePayload.params?.inputResponses?.['srv-req-1']).toBeTruthy();
    await expect(
      page.locator('pre.zh-evidence-code-block').filter({ hasText: '"resultType": "complete"' }).first()
    ).toBeVisible();
    await expect(page.getByText('收到 3 条 MCP 请求级实时事件')).toBeVisible();
    await expect(page.getByText('最新进度：1 / 1；日志：2 条（warning、error）。')).toBeVisible();
    await expect(page.getByText('MCP 需要操作员输入')).toHaveCount(0);
    await expect(page.getByText('MCP 订阅事件 1 条')).toBeVisible();
    await page.getByRole('button', { name: '停止订阅' }).click();
    await expect(page.getByText('未订阅')).toBeVisible();
  });

  test('风险事件可在正式页面批准，并由原始 Agent 领取后提交完成回执', async ({ page }) => {
    await login(page);

    const toolCall = {
      tool: 'mail.send',
      arguments: {
        to: 'external-review@example.net',
        subject: 'Operational approval workflow',
        body: 'Controlled operational review fixture'
      }
    };
    const result = await sendGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'Run the approval workflow for this operational request.' }],
      tools: [
        {
          type: 'function',
          function: {
            name: 'mail_send',
            description: 'Send a reviewed operational notification.',
            parameters: {
              type: 'object',
              properties: {
                to: { type: 'string' },
                subject: { type: 'string' },
                body: { type: 'string' }
              },
              required: ['to', 'subject', 'body'],
              additionalProperties: false
            }
          }
        }
      ],
      tool_choice: 'auto',
      agent_supervisor: { agent_id: 'e2e-agent' }
    });
    expect(result.agent_supervisor?.decision).toBe('询问');
    const requestId = String(result.agent_supervisor?.request_id ?? '');
    const auditId = String(result.agent_supervisor?.audit_id ?? '');
    expect(requestId).not.toBe('');
    expect(auditId).not.toBe('');

    await page.getByRole('button', { name: 'Close' }).click();
    await page.getByRole('menuitem', { name: '事件' }).click();
    await expect(page.getByRole('heading', { name: '安全事件', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: new RegExp(requestId) })).toBeVisible();
    await page.getByRole('button', { name: new RegExp(requestId) }).click();
    await page.getByRole('button', { name: '处理人工复核' }).click();

    await expect(page.getByRole('tab', { name: '待人工复核（1）' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByText(new RegExp(`审计 ID：${auditId}`))).toBeVisible();
    await page.getByRole('button', { name: '批准恢复' }).click();
    await expect(page.getByText('批准后允许 Agent 恢复执行？')).toBeVisible();
    await page.getByRole('button', { name: /确\s*认/ }).click();
    await expect(page.getByText('等待Agent恢复')).toBeVisible();

    const inventory = await page.request.get('/api/approvals?status=全部&scope=operational&limit=100', {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(inventory.status()).toBe(200);
    const inventoryBody = (await inventory.json()) as {
      reviews?: Array<{ id?: string; audit_id?: string; status?: string }>;
    };
    const review = inventoryBody.reviews?.find((item) => item.audit_id === auditId);
    expect(review?.status).toBe('已批准');
    const reviewId = String(review?.id ?? '');
    expect(reviewId).not.toBe('');

    const executorHeaders = { Authorization: `Bearer ${EXECUTOR_TOKEN}` };
    const claim = await page.request.post(`/api/approvals/${encodeURIComponent(reviewId)}/claim`, {
      headers: executorHeaders,
      data: { agent_id: 'e2e-agent', tool_call: toolCall }
    });
    expect(claim.status()).toBe(200);
    const claimBody = (await claim.json()) as { granted?: boolean; claim_id?: string };
    expect(claimBody.granted).toBe(true);
    const claimId = String(claimBody.claim_id ?? '');
    expect(claimId).not.toBe('');

    const complete = await page.request.post(`/api/approvals/${encodeURIComponent(reviewId)}/complete`, {
      headers: executorHeaders,
      data: {
        agent_id: 'e2e-agent',
        claim_id: claimId,
        succeeded: true,
        result_hash: 'e2e-approved-result-hash'
      }
    });
    expect(complete.status()).toBe(200);

    await expect(page.getByText('工具已执行')).toBeVisible();
    await expect(page.getByText(/result e2e-approved-res/)).toBeVisible();
  });

  test('三个生产页面可交互导航，移动端不产生横向溢出', async ({ page }) => {
    const failedApiResponses: string[] = [];
    page.on('response', (response) => {
      const url = new URL(response.url());
      if (url.pathname.startsWith('/api/') && response.status() >= 400) {
        failedApiResponses.push(`${response.status()} ${url.pathname}`);
      }
    });
    await login(page);

    await page.getByRole('menuitem', { name: '事件' }).click();
    await expect(page.getByRole('heading', { name: '安全事件', exact: true })).toBeVisible();

    await page.getByRole('menuitem', { name: '设置' }).click();
    await expect(page.getByRole('heading', { name: '设置' })).toBeVisible();
    await page.waitForTimeout(500);
    expect(failedApiResponses).toEqual([]);

    await page.setViewportSize({ width: 375, height: 812 });
    await page.reload();
    await expect(page.getByRole('heading', { name: '设置' })).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)
    ).toBe(true);
    await page.getByRole('button', { name: '打开导航菜单' }).click();
    await page.getByRole('menuitem', { name: '防护' }).click();
    await expect(page.getByRole('heading', { name: '请求防护' })).toBeVisible();
  });

  test('标准视口和深色主题保持主要页面可用', async ({ page }) => {
    await login(page);
    const pages = [
      { hash: 'gateway', heading: '请求防护' },
      { hash: 'events', heading: '安全事件' },
      { hash: 'settings', heading: '设置' }
    ];
    const viewports = [
      { width: 390, height: 844 },
      { width: 768, height: 1024 },
      { width: 1440, height: 900 }
    ];

    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      for (const target of pages) {
        await page.goto(`/#/${target.hash}`);
        await expect(page.getByRole('heading', { name: target.heading, exact: true, level: 1 })).toBeVisible();
        expect(
          await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)
        ).toBe(true);
      }
    }

    await page.goto('/#/gateway');
    await page.getByRole('button', { name: '切换深色模式' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.getByRole('heading', { name: '请求防护' })).toBeVisible();
  });
});
