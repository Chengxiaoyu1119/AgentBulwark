import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { PolicySettings } from '@/types';
import { AgentBoundarySettingsPanel } from './AgentBoundarySettingsPanel';

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: [],
  sensitive_path_markers: [],
  sensitive_api_markers: [],
  agent_tool_allowlists: {}
};

describe('settings field label associations', () => {
  it('associates boundary labels with their tag selectors', () => {
    render(
      <AgentBoundarySettingsPanel policySettings={settings} canEdit saving={false} onPatch={vi.fn()} onSave={vi.fn()} />
    );

    expect(screen.getByLabelText('内部邮箱域')).toHaveAttribute('id', 'policy-internal-email-domains');
    expect(screen.getByLabelText('敏感路径标记')).toHaveAttribute('id', 'policy-sensitive-path-markers');
    expect(screen.getByLabelText('高敏 API 标记')).toHaveAttribute('id', 'policy-sensitive-api-markers');
  });
});
