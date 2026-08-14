import type { BatchCompareResult, CompareResult, RunResult, Scenario } from '@/types';

export interface ExperimentLabProps {
  scenario: Scenario;
  scenarios: Scenario[];
  selected: string;
  setSelected: (id: string) => void;
  guardEnabled: boolean;
  setGuardEnabled: (value: boolean) => void;
  running: boolean;
  run: () => void;
  compare: () => void;
  batchCompare: () => void;
  result: RunResult | null;
  compareResult: CompareResult | null;
  batchResult: BatchCompareResult | null;
  refresh?: () => Promise<unknown>;
  onOpenAgentChain: () => void;
}
