import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PolicySettings } from '@/types';
import { TaskProfileEditor } from './TaskProfileEditor';

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: [],
  sensitive_path_markers: [],
  sensitive_api_markers: [],
  agent_tool_allowlists: { 'report-agent': ['file.read', 'file.write'] },
  task_profiles: {}
};

describe('TaskProfileEditor', () => {
  it('creates a task profile from an existing Agent capability', async () => {
    const onPatch = vi.fn();
    render(<TaskProfileEditor policySettings={settings} canEdit agentIds={['report-agent']} onPatch={onPatch} />);

    await userEvent.click(screen.getByRole('button', { name: '新增任务' }));

    expect(onPatch).toHaveBeenCalledWith({
      task_profiles: {
        'task-1': {
          agent_id: 'report-agent',
          name: '新任务授权',
          enabled: true,
          allowed_capabilities: ['file.read'],
          allowed_file_paths: [],
          allowed_api_origins: [],
          allowed_email_domains: [],
          require_approval: false,
          expires_at: ''
        }
      }
    });
  });

  it('keeps task creation unavailable until an Agent boundary exists', () => {
    render(
      <TaskProfileEditor
        policySettings={{ ...settings, agent_tool_allowlists: {} }}
        canEdit
        agentIds={[]}
        onPatch={vi.fn()}
      />
    );

    expect(screen.getByRole('button', { name: '新增任务' })).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent('先建立 Agent 权限边界');
  });
});
