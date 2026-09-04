import type { Overview } from '../types';

/**
 * Offline state for the product shell. It is intentionally empty: a network
 * failure must never make historical fixture metrics look like live evidence.
 */
export const offlineOverview: Overview = {
  attack_surfaces: [],
  student_competition_attack_map: [],
  scenarios: [],
  models: [],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: {
    surface_count: 0,
    scenario_count: 0,
    recent_run_count: 0,
    block_rate: 0,
    guarded_run_count: 0,
    guarded_controlled_count: 0,
    guarded_control_rate: 0,
    attack_success_rate: 0,
    avg_latency_ms: 0
  }
};
