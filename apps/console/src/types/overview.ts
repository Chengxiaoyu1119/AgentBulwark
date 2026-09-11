import type { ModelStatus } from './common';
import type { AlertItem, AuditLog } from './runtime';

export type OperationalDataStatus = 'live' | 'empty' | 'stale' | 'degraded' | string;

export interface OperationalTrendBucket {
  bucket_start: string;
  request_count: number;
  allowed_count: number;
  controlled_count: number;
  denied_count: number;
  approval_count: number;
  isolated_count: number;
}

export interface OperationalAction {
  id: string;
  kind: 'approval' | 'execution' | 'evidence' | 'readiness' | string;
  title: string;
  description: string;
  count: number;
  tone: 'warning' | 'danger' | 'info' | string;
  audit_ids: string[];
  request_ids: string[];
}

export interface OperationalReadinessItem {
  status: 'ready' | 'attention' | string;
  label: string;
  description: string;
}

export interface OperationalOverviewSummary {
  recent_run_count: number;
  block_rate: number | null;
  avg_latency_ms: number | null;
  request_count?: number | null;
  allowed_count?: number | null;
  controlled_count?: number | null;
  denied_count?: number | null;
  approval_count?: number | null;
  isolated_count?: number | null;
  control_rate?: number | null;
  provider_failure_count?: number | null;
  provider_called_count?: number | null;
  pending_review_count?: number | null;
  execution_receipt_count?: number | null;
  execution_completed_count?: number | null;
  execution_failed_count?: number | null;
  execution_not_executed_count?: number | null;
  execution_unconfirmed_count?: number | null;
  evidence_verified_count?: number | null;
  evidence_pending_count?: number | null;
  evidence_invalid_count?: number | null;
}

export interface OperationalActivity {
  request_id?: string;
  trace_id?: string;
  source_app?: string;
  decision?: string;
  provider?: string;
  model?: string;
  last_seen?: string;
}

export interface Overview {
  models: ModelStatus[];
  recent_runs: Array<Record<string, unknown>>;
  alerts: AlertItem[];
  audit_logs: AuditLog[];
  summary: OperationalOverviewSummary;
  access_scope?: string;
  schema_version?: string;
  generated_at?: string;
  updated_at?: string;
  data_status?: OperationalDataStatus;
  source_errors?: Array<{ source: string; error: string }>;
  sources?: string[];
  window?: { key: string; seconds: number; start_at: string; end_at: string; sample_limit: number };
  decision_distribution?: Record<string, number>;
  trend?: OperationalTrendBucket[];
  activity?: OperationalActivity[];
  action_queue?: OperationalAction[];
  readiness?: Record<string, OperationalReadinessItem>;
}

export type OperationalOverview = Overview;
