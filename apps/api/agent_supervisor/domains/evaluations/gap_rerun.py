from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from apps.api.agent_supervisor.domains.attacks.agents import batch_compare_scenarios
from apps.api.agent_supervisor.domains.evaluations.assessment import build_attack_effectiveness
from apps.api.agent_supervisor.domains.reports.roadmap import build_project_roadmap, write_project_roadmap
from apps.api.agent_supervisor.domains.reports.surface_pack import (
    build_surface_evidence_index,
    write_all_surface_briefing_sheets,
    write_all_surface_evidence_packs,
)
from apps.api.agent_supervisor.storage.data import get_scenarios
from apps.api.agent_supervisor.storage.database import latest_scenario_run_pairs


def run_gap_rerun() -> dict[str, Any]:
    before_runs = _competition_evidence_runs()
    before_effectiveness = build_attack_effectiveness(before_runs)
    before_index = build_surface_evidence_index(before_runs)
    scenario_ids = _scenario_ids_needing_rerun(before_effectiveness)

    run_result = batch_compare_scenarios(scenario_ids) if scenario_ids else _empty_run_result()

    after_runs = _competition_evidence_runs()
    after_effectiveness = build_attack_effectiveness(after_runs)
    surface_pack_result = write_all_surface_evidence_packs(runs=after_runs)
    briefing_result = write_all_surface_briefing_sheets(runs=after_runs)
    roadmap_result = write_project_roadmap(runs=after_runs)
    roadmap = build_project_roadmap(after_runs)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_scenario_ids": scenario_ids,
        "run_result": run_result,
        "before": {
            "evidence_gap_count": before_index["summary"]["gap_count"],
            "evidence_complete_rate": before_effectiveness["summary"]["evidence_complete_rate"],
            "defense_effective_rate": before_effectiveness["summary"]["defense_effective_rate"],
        },
        "after": {
            "evidence_gap_count": surface_pack_result["summary"]["gap_count"],
            "evidence_complete_rate": after_effectiveness["summary"]["evidence_complete_rate"],
            "defense_effective_rate": after_effectiveness["summary"]["defense_effective_rate"],
            "roadmap_score": roadmap["summary"]["overall_score"],
            "high_priority_gap_count": roadmap["summary"]["high_priority_gap_count"],
            "p0_backlog_count": roadmap["summary"]["p0_backlog_count"],
        },
        "artifacts": {
            "surface_pack_index": surface_pack_result.get("index_json_path", ""),
            "briefing_sheet_index": briefing_result.get("index_html_path", ""),
            "roadmap_json": roadmap_result.get("json_path", ""),
            "roadmap_markdown": roadmap_result.get("markdown_path", ""),
        },
    }


def _scenario_ids_needing_rerun(effectiveness: dict[str, Any]) -> list[str]:
    ids = []
    for case in effectiveness.get("cases", []):
        if (
            not case.get("attack_reproduced_without_guard")
            or not case.get("defense_effective_with_guard")
            or not case.get("expected_decision_match")
            or not case.get("evidence_complete")
        ):
            ids.append(case["scenario_id"])
    return ids


def _empty_run_result() -> dict[str, Any]:
    return {
        "scenario_ids": [],
        "comparisons": [],
        "summary": {
            "total": 0,
            "exposed_without_guard": 0,
            "controlled_with_guard": 0,
            "attack_success_reduced": 0,
            "control_rate": 0,
            "avg_latency_ms": 0,
            "blocked_count": 0,
            "asked_count": 0,
            "isolated_count": 0,
        },
    }


def _competition_evidence_runs() -> list[dict[str, Any]]:
    return latest_scenario_run_pairs([scenario["id"] for scenario in get_scenarios()])
