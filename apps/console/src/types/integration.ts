export interface AgentIntegrationExample {
  id: string;
  name: string;
  framework: string;
  runtime_stage: string;
  endpoint: string;
  status: string;
  code: string;
}

export interface AgentIntegrationBundle {
  name: string;
  version: string;
  generated_at: string;
  purpose: string;
  decision_contract: Record<string, string>;
  event_contract: {
    required_fields: string[];
    recommended_fields: string[];
    safe_default: string;
  };
  examples: AgentIntegrationExample[];
  acceptance: string[];
}
