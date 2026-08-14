import type {
  AttackLabModulesResponse,
  AttackLabRunRequest,
  AttackLabRunResult,
  CustomAttackCompareRequest,
  CustomAttackCompareResult,
  CustomAttackChainResult,
  ExternalExecutionReceiptRequest,
  ExternalExecutionReceiptResult,
  ExternalExecutionReceiptState,
  AttackTestsetRunRequest,
  AttackTestsetRunResult,
  AttackTestsetsResponse,
  AuthorizedTargetRunRequest,
  AuthorizedTargetRunResult,
  CapabilityReplayResult,
  DualModelJailbreakRequest,
  DualModelJailbreakResult,
  JailbreakRedteamRequest,
  JailbreakRedteamResult,
  LearningLabRunRequest,
  LearningLabRunResult,
  LearningLabScenariosResponse,
  ModelDrivenAgentResult,
  RefusalRewriteEvasionRequest,
  RefusalRewriteEvasionResult,
  TargetLabState
} from '../types';
import { request } from './apiRequest';

export async function fetchAttackLabModules(): Promise<AttackLabModulesResponse> {
  return request<AttackLabModulesResponse>('/api/attack_lab/modules');
}

export async function runAttackLabModule(payload: AttackLabRunRequest): Promise<AttackLabRunResult> {
  return request<AttackLabRunResult>(
    '/api/attack_lab/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 180000, retry: 0 }
  );
}

export async function runCustomAttackCompare(payload: CustomAttackCompareRequest): Promise<CustomAttackCompareResult> {
  return request<CustomAttackCompareResult>(
    '/api/attack_lab/custom_compare',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 90000, retry: 0 }
  );
}

export async function runCustomAttackChain(result: CustomAttackCompareResult): Promise<CustomAttackChainResult> {
  return request<CustomAttackChainResult>(
    '/api/attack_lab/custom_chain/run',
    {
      method: 'POST',
      body: JSON.stringify({
        ...result.request,
        arguments: result.tool_call.arguments,
        command: '',
        execution_mode: 'sandbox',
        source_comparison_id: result.comparison_id
      })
    },
    { timeoutMs: 90000, retry: 0 }
  );
}

export async function submitExternalExecutionReceipt(
  auditId: string,
  payload: ExternalExecutionReceiptRequest
): Promise<ExternalExecutionReceiptResult> {
  return request<ExternalExecutionReceiptResult>(
    `/api/runtime/executions/${encodeURIComponent(auditId)}/complete`,
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 30000, retry: 0 }
  );
}

export async function fetchExternalExecutionReceipt(auditId: string): Promise<ExternalExecutionReceiptState> {
  return request<ExternalExecutionReceiptState>(`/api/runtime/executions/${encodeURIComponent(auditId)}`, undefined, {
    timeoutMs: 15000,
    retry: 0
  });
}

export async function fetchAttackTestsets(): Promise<AttackTestsetsResponse> {
  return request<AttackTestsetsResponse>('/api/attack_lab/testsets');
}

export async function runAttackTestset(payload: AttackTestsetRunRequest): Promise<AttackTestsetRunResult> {
  return request<AttackTestsetRunResult>(
    '/api/attack_lab/testsets/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 90000 }
  );
}

export async function runCapabilityReplay(): Promise<CapabilityReplayResult> {
  return request<CapabilityReplayResult>(
    '/api/capability_replay/run',
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 60000 }
  );
}

export async function runModelDrivenAgent(payload: {
  task: string;
  force_real_model: boolean;
  target_model?: string;
}): Promise<ModelDrivenAgentResult> {
  return request<ModelDrivenAgentResult>(
    '/api/integrations/agents/model_driven_demo',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 120000 }
  );
}

export async function fetchLearningLabScenarios(): Promise<LearningLabScenariosResponse> {
  return request<LearningLabScenariosResponse>('/api/learning_lab/scenarios');
}

export async function runLearningLabAttack(payload: LearningLabRunRequest): Promise<LearningLabRunResult> {
  return request<LearningLabRunResult>(
    '/api/learning_lab/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 45000 }
  );
}

export async function runJailbreakRedteam(payload: JailbreakRedteamRequest): Promise<JailbreakRedteamResult> {
  return request<JailbreakRedteamResult>(
    '/api/redteam_lab/jailbreak/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 45000 }
  );
}

export async function runDualModelJailbreak(payload: DualModelJailbreakRequest): Promise<DualModelJailbreakResult> {
  return request<DualModelJailbreakResult>(
    '/api/redteam_lab/jailbreak/dual_model/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 120000 }
  );
}

export async function runRefusalRewriteEvasion(
  payload: RefusalRewriteEvasionRequest
): Promise<RefusalRewriteEvasionResult> {
  return request<RefusalRewriteEvasionResult>(
    '/api/redteam_lab/jailbreak/refusal_rewrite/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 120000 }
  );
}

export async function runAuthorizedTarget(payload: AuthorizedTargetRunRequest): Promise<AuthorizedTargetRunResult> {
  return request<AuthorizedTargetRunResult>(
    '/api/redteam_lab/authorized_target/run',
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { timeoutMs: 45000 }
  );
}

export async function fetchTargetLabState(): Promise<TargetLabState> {
  return request<TargetLabState>('/api/target_lab/state');
}

export async function resetTargetLabState(): Promise<TargetLabState> {
  return request<TargetLabState>('/api/target_lab/reset', {
    method: 'POST',
    body: JSON.stringify({})
  });
}
