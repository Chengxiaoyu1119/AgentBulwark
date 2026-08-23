import { expect, test, type Page } from 'playwright/test';

const ADMIN_TOKEN = 'e2e-admin-token';
const OBSERVER_TOKEN = 'e2e-observer-token';
const PROVIDER_STATS_URL = 'http://127.0.0.1:18081/_fixture/stats';

async function login(page: Page, token = ADMIN_TOKEN) {
  await page.goto('/#/gateway');
  await expect(page.getByRole('heading', { name: '连接安全控制台' })).toBeVisible();
  await page.getByRole('textbox', { name: '运行 Token' }).fill(token);
  await page.getByRole('button', { name: '验证并进入' }).click();
  await expect(page.getByRole('heading', { name: '实时流量与执行闸门' })).toBeVisible();
}

async function sendGatewayRequest(page: Page, payload?: Record<string, unknown>) {
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

async function providerRequestCount(page: Page) {
  const response = await page.request.get(PROVIDER_STATS_URL);
  expect(response.ok()).toBeTruthy();
  return Number(((await response.json()) as { request_count?: number }).request_count ?? 0);
}

test.describe.serial('运营网关黑盒验收', () => {
  test('冷启动只访问公开状态，错误凭证、只读权限和会话失效都有明确反馈', async ({ page }) => {
    const bootstrapApiPaths: string[] = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.pathname.startsWith('/api/')) bootstrapApiPaths.push(url.pathname);
    });

    await page.goto('/#/gateway');
    await expect(page.getByRole('heading', { name: '连接安全控制台' })).toBeVisible();
    await expect(page.getByText('后端在线')).toBeVisible();
    expect([...new Set(bootstrapApiPaths)]).toEqual(['/api/public/status']);

    await page.getByRole('textbox', { name: '运行 Token' }).fill('wrong-token');
    await page.getByRole('button', { name: '验证并进入' }).click();
    await expect(page.getByText('凭证未通过校验，请检查后重新输入。')).toBeVisible();

    await page.getByRole('textbox', { name: '运行 Token' }).fill(OBSERVER_TOKEN);
    await page.getByRole('button', { name: '验证并进入' }).click();
    await expect(page.getByRole('heading', { name: '实时流量与执行闸门' })).toBeVisible();
    await expect(page.getByRole('button', { name: '发送到网关' })).toBeDisabled();
    await expect(page.getByText('当前凭证只有观测权限，不能发起模型请求。')).toBeVisible();

    const forbidden = await page.request.post('/v1/chat/completions', {
      headers: { Authorization: `Bearer ${OBSERVER_TOKEN}`, 'X-Agent-Session-ID': 'observer-e2e' },
      data: { model: 'e2e-fixture-model', messages: [{ role: 'user', content: 'hello' }] }
    });
    expect(forbidden.status()).toBe(403);

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
    expect(overviewBody.attack_surfaces).toEqual([]);
    expect(overviewBody.scenarios).toEqual([]);
    expect(overviewBody.student_competition_attack_map).toEqual([]);
    const labs = await page.request.get('/api/scenarios', {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(labs.status()).toBe(404);

    const clean = await sendGatewayRequest(page, {
      model: 'e2e-fixture-model',
      messages: [{ role: 'user', content: 'Summarize this clean operational request.' }]
    });
    expect(clean.agent_supervisor?.decision).toBe('允许');
    expect(clean.agent_supervisor?.provider_called).toBe(true);
    const cleanRequestId = String(clean.agent_supervisor?.request_id ?? '');
    expect(cleanRequestId).not.toBe('');
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
    await expect(page.getByRole('heading', { name: '实时流量与执行闸门' })).toBeVisible();
    await expect(page.getByRole('button', { name: new RegExp(toolRequestId) })).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test('服务端托管 Tool Call 产生可验证回执，MCP JSON-RPC 走真实子进程', async ({ page }) => {
    await login(page);

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
    await expect(page.getByText('服务端托管执行回执')).toBeVisible();

    await page.getByRole('button', { name: 'initialize' }).click();
    await expect(page.getByText('initialize', { exact: true }).last()).toBeVisible();
    await expect(page.getByText('result', { exact: true })).toBeVisible();

    await page.getByRole('button', { name: 'tools/list' }).click();
    await expect(page.getByText(/当前响应可见工具：1 个/)).toBeVisible();

    await page.getByRole('button', { name: 'tools/call' }).click();
    await expect(page.getByText('forwarded-and-completed', { exact: true })).toBeVisible();
    await expect(page.getByText(/调用已转发并收到上游结果/)).toBeVisible();
  });

  test('五个运营页面可交互导航，移动端不产生横向溢出', async ({ page }) => {
    const failedApiResponses: string[] = [];
    page.on('response', (response) => {
      const url = new URL(response.url());
      if (url.pathname.startsWith('/api/') && response.status() >= 400) {
        failedApiResponses.push(`${response.status()} ${url.pathname}`);
      }
    });
    await login(page);

    await page.getByRole('menuitem', { name: '运行总览' }).click();
    await expect(page.getByRole('heading', { name: /看见每次工具调用/ })).toBeVisible();

    await page.getByRole('menuitem', { name: '事件与复核' }).click();
    await expect(page.getByRole('heading', { name: '安全事件、人工复核与执行审计' })).toBeVisible();

    await page.getByRole('menuitem', { name: '防护策略' }).click();
    await expect(page.getByRole('heading', { name: '防护策略中心' })).toBeVisible();

    await page.getByRole('menuitem', { name: 'Agent 接入' }).click();
    await expect(page.getByRole('heading', { name: 'Agent接入与系统设置' })).toBeVisible();
    await page.waitForTimeout(500);
    expect(failedApiResponses).toEqual([]);

    await page.setViewportSize({ width: 375, height: 812 });
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Agent接入与系统设置' })).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)
    ).toBe(true);
    await page.getByRole('button', { name: '打开导航菜单' }).click();
    await page.getByRole('menuitem', { name: 'LLM API / MCP 网关' }).click();
    await expect(page.getByRole('heading', { name: '实时流量与执行闸门' })).toBeVisible();
  });
});
