from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from apps.api.agent_supervisor.domains.governance.supervisor import decide
from apps.api.agent_supervisor.storage.data import get_holdout_evaluation_samples

CONTROL_DECISIONS = {"拒绝", "询问", "隔离"}


def evaluate_adversarial_holdout() -> dict[str, Any]:
    fixture = get_holdout_evaluation_samples()
    raw_samples = fixture.get("samples")
    samples = raw_samples if isinstance(raw_samples, list) else []
    records = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        raw_tool_call = sample.get("tool_call")
        tool_call: dict[str, Any] = raw_tool_call if isinstance(raw_tool_call, dict) else {}
        decision = decide(
            tool_call,
            guard_enabled=True,
            prompt=str(sample.get("prompt", "")),
            context_sources=[str(item) for item in sample.get("context_sources", [])],
        )
        expected_decisions = [str(item) for item in sample.get("expected_decisions", [])]
        expected_policies = [str(item) for item in sample.get("expected_policies", [])]
        label = str(sample.get("label", "benign"))
        predicted_attack = decision.decision in CONTROL_DECISIONS
        records.append(
            {
                "id": str(sample.get("id", "")),
                "label": label,
                "tool_call": sample.get("tool_call", {}),
                "expected_decisions": expected_decisions,
                "expected_policies": expected_policies,
                "decision": decision.decision,
                "policy_id": decision.policy_id,
                "risk_score": decision.risk_score,
                "anomaly_score": decision.anomaly_score,
                "predicted_attack": predicted_attack,
                "expected_match": decision.decision in expected_decisions and decision.policy_id in expected_policies,
            }
        )

    attack_records = [item for item in records if item["label"] == "attack"]
    benign_records = [item for item in records if item["label"] == "benign"]
    true_positive = sum(1 for item in attack_records if item["predicted_attack"])
    false_negative = len(attack_records) - true_positive
    false_positive = sum(1 for item in benign_records if item["predicted_attack"])
    true_negative = len(benign_records) - false_positive
    expected_matches = sum(1 for item in records if item["expected_match"])

    return {
        "schema_version": fixture.get("schema_version", "unknown"),
        "label_source": fixture.get("label_source", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "sample_count": len(records),
            "attack_count": len(attack_records),
            "benign_count": len(benign_records),
            "true_positive": true_positive,
            "false_negative": false_negative,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "attack_recall_rate": _rate(true_positive, len(attack_records)),
            "benign_false_positive_rate": _rate(false_positive, len(benign_records)),
            "precision": _rate(true_positive, true_positive + false_positive),
            "expected_match_count": expected_matches,
            "expected_match_rate": _rate(expected_matches, len(records)),
        },
        "records": records,
    }


def _rate(part: int, total: int) -> int:
    return round((part / total) * 100) if total else 0
