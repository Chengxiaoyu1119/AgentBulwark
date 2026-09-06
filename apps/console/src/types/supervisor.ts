import type { RiskLevel } from './common';

export type ApprovalStatus = '待复核' | '已批准' | '已驳回' | string;

export interface ApprovalReview {
  id: string;
  audit_id: string;
  run_id: string;
  status: ApprovalStatus;
  final_decision: string;
  approval_action: string;
  tool: string;
  arguments: Record<string, unknown>;
  standard_capability?: string;
  standard_arguments?: Record<string, unknown>;
  tool_mapping?: Record<string, unknown> | null;
  policy_id: string;
  risk_level: RiskLevel | string;
  risk_score?: number;
  risk_factors?: string[];
  anomaly_score?: number;
  anomaly_signals?: string[];
  reason: string;
  recommendation: string;
  source_app: string;
  agent_id: string;
  conversation_id: string;
  model_input_excerpt: string;
  model_output_excerpt: string;
  audit_hash: string;
  previous_hash: string;
  review_previous_hash: string;
  review_hash: string;
  hash_valid: boolean;
  operator: string;
  comment: string;
  created_at: string;
  reviewed_at: string;
  due_at?: string;
  sla_minutes?: number;
  sla_breached?: boolean;
  escalation_level?: string;
  execution_note: string;
  tool_call_hash?: string;
  execution_status?: string;
  execution_claim_id?: string;
  execution_claim_agent_id?: string;
  execution_claimed_at?: string;
  execution_completed_at?: string;
  execution_result_hash?: string;
  execution_receipt_id?: string;
  execution_receipt_hash?: string;
  execution_receipt_signature?: string;
}

export interface ApprovalReviewList {
  generated_at: string;
  status_filter: string;
  summary: {
    total: number;
    pending_count: number;
    approved_count: number;
    rejected_count: number;
    high_risk_count: number;
    hash_valid_count: number;
    latest_created_at: string;
    latest_reviewed_at: string;
    sla_breached_count?: number;
  };
  reviews: ApprovalReview[];
}

export interface ApprovalDecisionResult {
  updated: boolean;
  review: ApprovalReview;
  summary: ApprovalReviewList['summary'];
}
