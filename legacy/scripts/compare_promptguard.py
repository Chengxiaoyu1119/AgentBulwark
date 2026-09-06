"""B-05 对比评测：智安哨三通道 vs LlamaFirewall PromptGuard 2（B-01 中文留出集）。

评测对象：
- 我方规则通道：governance.supervisor.inspect_prompt()（jailbreak-filter 策略）；
- 我方语义通道：governance.semantic_detector（B-02 中文 BERT，模型缺失时自动跳过）；
- 双通道组合：规则阻断 或 语义置信度≥0.5（与产品 decide() 的拦截语义一致：拒绝/询问均拦截）；
- 对比基线：LlamaFirewall PromptGuard 2 86M（Meta，社区 ONNX INT8 镜像）。

数据：training/dataset/test.jsonl（148 条，攻击 77 / 良性 71，正类=攻击）。

PromptGuard 操作点：
- argmax：非 benign 即判攻击（等价 1-p[0] > 0.5）；
- best-F1：对 1-p[0] 阈值扫描取最优（oracle 上界，仅作参考）。

执行：python -X utf8 scripts/compare_promptguard.py
依赖：onnxruntime、tokenizers（评测机本地安装，不进入运行时依赖）。

输出：
- 控制台摘要（Markdown 表格数据）
- training/_compare/results/detail.jsonl  逐条预测明细（本地保留，不入库）
- training/_compare/results/summary.json  汇总指标（本地保留，不入库）
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from apps.api.agent_supervisor.domains.governance.semantic_detector import (  # noqa: E402
    MODEL_DIR as SEMANTIC_MODEL_DIR,
    REJECT_THRESHOLD,
    REVIEW_THRESHOLD,
    get_semantic_detector,
)
from apps.api.agent_supervisor.domains.governance.supervisor import inspect_prompt  # noqa: E402

MODEL_DIR = PROJECT_ROOT / "training" / "_compare" / "promptguard"
DATASET = PROJECT_ROOT / "training" / "dataset" / "test.jsonl"
RESULT_DIR = MODEL_DIR.parent / "results"
MAX_LEN = 512


def load_dataset() -> list[dict]:
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    positives = sum(1 for row in rows if row["label"] == 1)
    print(f"dataset: {len(rows)} samples, attack={positives} benign={len(rows) - positives}")
    return rows


class PromptGuardRunner:
    """PromptGuard 2 86M ONNX 推理封装（仅评测用）。"""

    def __init__(self) -> None:
        import numpy as np  # noqa: F401
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        self.session = ort.InferenceSession(str(MODEL_DIR / "model.onnx"), providers=["CPUExecutionProvider"])
        self.tokenizer = Tokenizer.from_file(str(MODEL_DIR / "tokenizer.json"))
        self.input_names = [item.name for item in self.session.get_inputs()]
        self.num_classes = self.session.get_outputs()[0].shape[-1]
        if isinstance(self.num_classes, str) or not self.num_classes:
            self.num_classes = 3  # 导出图缺维度信息时按 PromptGuard 默认 3 类处理
        print(f"promptguard inputs={self.input_names} classes={self.num_classes}")

    def malicious_probability(self, text: str) -> float:
        """返回攻击概率：PromptGuard 类别序为 [benign, ...]，攻击概率 = 1 - p(benign)。"""
        np = self.np
        enc = self.tokenizer.encode(text)
        ids = enc.ids[:MAX_LEN]
        mask = enc.attention_mask[:MAX_LEN]
        pad = MAX_LEN - len(ids)
        feeds = {
            "input_ids": np.array([ids + [0] * pad], dtype=np.int64),
            "attention_mask": np.array([mask + [0] * pad], dtype=np.int64),
        }
        if "token_type_ids" in self.input_names:
            feeds["token_type_ids"] = np.zeros_like(feeds["input_ids"])
        logits = self.session.run(None, feeds)[0][0]
        exps = np.exp(logits - logits.max())
        probs = exps / exps.sum()
        return float(1.0 - probs[0])


def run_rule_channel(rows: list[dict]) -> list[dict]:
    """规则通道：inspect_prompt 命中即拦截（预测为攻击）。"""
    records = []
    for row in rows:
        started = time.perf_counter()
        blocked = inspect_prompt(row["text"]) is not None
        records.append(
            {
                "predicted": 1 if blocked else 0,
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
        )
    return records


def run_semantic_channel(rows: list[dict]) -> list[dict] | None:
    """语义通道（B-02）：模型缺失/不可用时返回 None（报告自动降级为双方案对比）。"""
    if not (SEMANTIC_MODEL_DIR / "jailbreak_bert.onnx").exists():
        print(f"[skip] 语义通道模型缺失（{SEMANTIC_MODEL_DIR}/jailbreak_bert.onnx），B-02 就绪后重跑本脚本")
        return None
    detector = get_semantic_detector()
    records = []
    for row in rows:
        started = time.perf_counter()
        result = detector.detect(row["text"])
        records.append(
            {
                "predicted": 1 if result.probability >= REJECT_THRESHOLD else 0,
                "probability": result.probability,
                "available": result.available,
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
        )
    return records


def run_promptguard(rows: list[dict], runner: PromptGuardRunner) -> list[dict]:
    records = []
    for row in rows:
        started = time.perf_counter()
        prob = runner.malicious_probability(row["text"])
        records.append(
            {
                "predicted": 1 if prob > 0.5 else 0,
                "probability": prob,
                "latency_ms": (time.perf_counter() - started) * 1000,
            }
        )
    return records


def metrics(rows: list[dict], preds: list[int]) -> dict:
    tp = sum(1 for row, p in zip(rows, preds) if row["label"] == 1 and p == 1)
    fp = sum(1 for row, p in zip(rows, preds) if row["label"] == 0 and p == 1)
    tn = sum(1 for row, p in zip(rows, preds) if row["label"] == 0 and p == 0)
    fn = sum(1 for row, p in zip(rows, preds) if row["label"] == 1 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows)
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def recall_by_category(rows: list[dict], preds: list[int]) -> dict[str, dict]:
    stats: dict[str, list[int]] = {}
    for row, p in zip(rows, preds):
        key = (row["category"], row["label"])
        stats.setdefault(str(key), [0, 0])
        stats[str(key)][1] += 1
        if p == row["label"]:
            stats[str(key)][0] += 1
    return {key: {"hit": hit, "total": total} for key, (hit, total) in sorted(stats.items())}


def best_f1_threshold(rows: list[dict], probs: list[float]) -> tuple[float, dict]:
    """阈值扫描取最佳 F1（oracle 上界）。"""
    best = (0.0, 0.0, {})
    for i in range(5, 100):
        threshold = i / 100
        preds = [1 if p > threshold else 0 for p in probs]
        score = metrics(rows, preds)
        if score["f1"] > best[1]:
            best = (threshold, score["f1"], score)
    return best[0], best[2]


def main() -> None:
    rows = load_dataset()
    runner = PromptGuardRunner()

    rule_records = run_rule_channel(rows)
    semantic_records = run_semantic_channel(rows)
    pg_records = run_promptguard(rows, runner)

    rule_metrics = metrics(rows, [r["predicted"] for r in rule_records])
    pg_argmax_metrics = metrics(rows, [r["predicted"] for r in pg_records])
    threshold, pg_best_metrics = best_f1_threshold(rows, [r["probability"] for r in pg_records])

    summary: dict = {
        "dataset": {"total": len(rows), "attack": sum(r["label"] for r in rows), "benign": len(rows) - sum(r["label"] for r in rows)},
        "rule_channel": {**rule_metrics, "avg_latency_ms": round(statistics.mean(r["latency_ms"] for r in rule_records), 3)},
        "promptguard_argmax": {**pg_argmax_metrics, "avg_latency_ms": round(statistics.mean(r["latency_ms"] for r in pg_records), 3)},
        "promptguard_best_f1": {"threshold": threshold, **pg_best_metrics},
        "promptguard_recall_by_category": recall_by_category(rows, [r["predicted"] for r in pg_records]),
        "rule_recall_by_category": recall_by_category(rows, [r["predicted"] for r in rule_records]),
    }

    if semantic_records is not None:
        # 双通道组合：规则阻断 或 语义≥REVIEW_THRESHOLD（产品 decide() 语义：拒绝/询问均拦截）
        dual_preds = [
            1 if (rule["predicted"] == 1 or sem["probability"] >= REVIEW_THRESHOLD) else 0
            for rule, sem in zip(rule_records, semantic_records)
        ]
        semantic_metrics = metrics(rows, [r["predicted"] for r in semantic_records])
        semantic_available = sum(1 for r in semantic_records if r["available"])
        summary["semantic_channel"] = {
            **semantic_metrics,
            "reject_threshold": REJECT_THRESHOLD,
            "review_threshold": REVIEW_THRESHOLD,
            "available_samples": semantic_available,
            "model_version": get_semantic_detector().model_version,
            "avg_latency_ms": round(statistics.mean(r["latency_ms"] for r in semantic_records), 3),
        }
        summary["dual_channel"] = metrics(rows, dual_preds)
        summary["dual_recall_by_category"] = recall_by_category(rows, dual_preds)

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    (RESULT_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    with (RESULT_DIR / "detail.jsonl").open("w", encoding="utf-8") as fh:
        for idx, (row, rule, pg) in enumerate(zip(rows, rule_records, pg_records)):
            record = {
                **row,
                "rule_pred": rule["predicted"],
                "pg_pred": pg["predicted"],
                "pg_prob": round(pg["probability"], 4),
            }
            if semantic_records is not None:
                sem = semantic_records[idx]
                record["sem_pred"] = sem["predicted"]
                record["sem_prob"] = round(sem["probability"], 4)
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
