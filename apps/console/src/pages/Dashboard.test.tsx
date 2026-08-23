import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Dashboard } from './Dashboard';
import type { Overview } from '../types';

const overview = {
  attack_surfaces: [
    {
      id: 'prompt-injection',
      name: '提示注入',
      risk: 'high',
      status: '已覆盖',
      summary: '',
      samples: 2,
      scripts: 1,
      defense: ''
    }
  ],
  scenarios: [{ id: 'S-1', surface_id: 'prompt-injection', title: '提示注入', severity: 'high', target: 'mail.send' }],
  models: [{ provider: 'provider', configured: true, model: 'model', mode: 'real-api' }],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: {
    surface_count: 1,
    scenario_count: 1,
    recent_run_count: 0,
    block_rate: 0,
    attack_success_rate: 0,
    avg_latency_ms: 0
  }
} as unknown as Overview;

describe('Dashboard', () => {
  it('shows the operational workflow without loading report or evidence products', () => {
    render(<Dashboard overview={overview} apiAvailable onOpenPage={vi.fn()} />);

    expect(screen.getByText('AI Agent 运行时安全网关')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '打开 LLM API / MCP 网关' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '处理事件与复核' })).toBeInTheDocument();
    expect(screen.getByText('网关运营与安全边界')).toBeInTheDocument();
    expect(screen.getByText('暂无真实网关阶段证据')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '查看场景' })).not.toBeInTheDocument();
    expect(screen.queryByText('能力地图')).not.toBeInTheDocument();
    expect(screen.queryByText('证据包管理与导出')).not.toBeInTheDocument();
  });

  it('does not turn historical supervisor events into a live gateway control rate', () => {
    const mixedOverview = {
      ...overview,
      audit_logs: [
        { decision: '拒绝', stage_context: {} },
        { decision: '允许', stage_context: { request_id: 'gateway-request-1', provider_called: true } }
      ]
    } as unknown as Overview;

    render(<Dashboard overview={mixedOverview} apiAvailable onOpenPage={vi.fn()} />);

    expect(screen.getByText('1 条网关阶段证据')).toBeInTheDocument();
    expect(screen.getByText('0%')).toBeInTheDocument();
  });
});
