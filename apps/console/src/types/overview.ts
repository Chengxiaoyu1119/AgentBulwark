import type { ModelStatus } from './common';
import type { AlertItem, AuditLog } from './runtime';

export interface Overview {
  models: ModelStatus[];
  recent_runs: Array<Record<string, unknown>>;
  alerts: AlertItem[];
  audit_logs: AuditLog[];
  summary: {
    recent_run_count: number;
    block_rate: number;
    avg_latency_ms: number;
  };
  access_scope?: string;
}
