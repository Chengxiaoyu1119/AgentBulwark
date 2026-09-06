"""B-01 LLM 变体生成脚本：把人工种子扩充到 1000 条标注样本。

对 training/seeds 下的攻击/正常种子调用智谱 GLM API 生成语义等价的表述变体，
与种子合并后按"种子组"划分 train/dev/test（80/10/10），避免变体与种子跨集导致数据泄漏。

性能与限流适配：
- 单次调用约 11~12s，故按批（默认 5 种子/批）请求，批内失败自动降级为逐条重试；
- 触发平台内容审查（HTTP 400）的种子记为跳过，不影响其余种子；
- checkpoint 记录已完成的种子，重跑时自动续传。

执行：python -X utf8 scripts/generate_bert_variants.py
依赖：.env 中的 ZHIPU_API_KEY（与盲测脚本同源）；无 Key 时只输出种子数据集。

输出：
- training/dataset/jailbreak_dataset_full.jsonl  全量样本
- training/dataset/train.jsonl / dev.jsonl / test.jsonl
- apps/api/sandbox/reports/bert_dataset_report.json
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from training.seeds.jailbreak_attack_seeds import ATTACK_SEEDS
from training.seeds.normal_benign_seeds import NORMAL_SEEDS

TARGET_PER_CLASS = 500
VARIANTS_PER_SEED = 3
BATCH_SIZE = 5
REQUEST_INTERVAL_SECONDS = 0.4
MAX_RETRY = 2
CHECKPOINT_PATH = PROJECT_ROOT / "training" / "dataset" / "variant_checkpoint.json"
DATASET_DIR = PROJECT_ROOT / "training" / "dataset"
REPORT_PATH = PROJECT_ROOT / "apps" / "api" / "sandbox" / "reports" / "bert_dataset_report.json"
RANDOM_SEED = 20260815

ATTACK_PROMPT = """你正在协助构建一个中文大模型安全防火墙的训练数据集（防御用途）。
下面是 {count} 条已标注的越狱攻击样本（用于训练检测器）。请为每条生成 {n} 条语义等价的变体：
- 保持相同的攻击意图（试图绕过安全规则/获取未授权内容）
- 改变句式、用词、语气或长度（有的更口语、有的更正式、有的更长）
- 不要复制原句，不要输出与攻击意图无关的内容
- 每条变体必须是独立完整的中文语句（可含少量英文）

样本列表：
{items}

只输出JSON对象，键为样本ID，值为变体数组，例如：
{{"ID-001": ["变体1", "变体2", "变体3"], "ID-002": ["变体1", "变体2", "变体3"]}}"""

NORMAL_PROMPT = """你正在协助构建一个中文大模型安全防火墙的训练数据集（防御用途）。
下面是 {count} 条已标注的正常（无害）样本。请为每条生成 {n} 条语义等价的变体：
- 保持相同的无害业务意图
- 改变句式、用词、语气或长度（有的更口语、有的更正式、有的更长）
- 不要复制原句，不要引入任何攻击性、越狱或违规意图
- 每条变体必须是独立完整的中文语句（可含少量英文）

样本列表：
{items}

只输出JSON对象，键为样本ID，值为变体数组，例如：
{{"ID-001": ["变体1", "变体2", "变体3"], "ID-002": ["变体1", "变体2", "变体3"]}}"""


def load_zhipu_key() -> str:
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("ZHIPU_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("ZHIPU_API_KEY", "")


def _post_chat(api_key: str, prompt: str, temperature: float) -> str:
    payload = {
        "model": "glm-4.6v-flashx",
        "messages": [
            {
                "role": "system",
                "content": "你是安全研究数据集助手，只输出要求的JSON，不添加任何解释。",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": 2400,
        "stream": False,
    }
    request = urllib.request.Request(
        "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        parsed = json.loads(response.read().decode("utf-8", errors="replace"))
    return (parsed.get("choices", [{}])[0].get("message", {}).get("content", "") or "").strip()


def _parse_variant_map(content: str, expected_ids: set[str]) -> dict[str, list[str]]:
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"响应中未找到JSON对象：{content[:120]}")
    data = json.loads(content[start : end + 1])
    result: dict[str, list[str]] = {}
    if not isinstance(data, dict):
        raise ValueError("响应不是JSON对象")
    for key, value in data.items():
        if str(key) not in expected_ids or not isinstance(value, list):
            continue
        result[str(key)] = [str(item).strip() for item in value if isinstance(item, (str, int, float))]
    return result


def call_batch(api_key: str, seeds: list[dict], prompt_tpl: str) -> dict[str, list[str]]:
    """批量请求：一次生成多种子的变体。返回 {seed_id: [variants]}。"""
    items = "\n".join(f"- {s['id']}：{s['text']}" for s in seeds)
    prompt = prompt_tpl.format(
        count=len(seeds), n=VARIANTS_PER_SEED, items=items
    )
    content = _post_chat(api_key, prompt, temperature=0.8)
    return _parse_variant_map(content, {str(s["id"]) for s in seeds})


def call_single(api_key: str, seed: dict, prompt_tpl: str) -> list[str]:
    """单种子请求：批量失败后的降级路径。"""
    items = f"- {seed['id']}：{seed['text']}"
    prompt = prompt_tpl.format(count=1, n=VARIANTS_PER_SEED, items=items)
    content = _post_chat(api_key, prompt, temperature=0.9)
    result = _parse_variant_map(content, {str(seed["id"])})
    return result.get(str(seed["id"]), [])


def sanitize_variant(text: str, seen: set[str]) -> str | None:
    text = text.strip()
    if not (8 <= len(text) <= 400):
        return None
    if text in seen:
        return None
    if text.startswith(("[", "{", '"')):
        return None
    return text


def load_checkpoint() -> dict:
    if CHECKPOINT_PATH.exists():
        return json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
    return {"attack": {}, "normal": {}}


def save_checkpoint(checkpoint: dict) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_PATH.write_text(
        json.dumps(checkpoint, ensure_ascii=False, indent=1), encoding="utf-8"
    )


def generate_variants(api_key: str) -> dict:
    checkpoint = load_checkpoint()
    stats = {"api_calls": 0, "api_errors": 0, "rejected_seeds": 0, "generated": 0, "skipped": 0}
    seen_texts = {
        str(item["text"]) for item in ATTACK_SEEDS
    } | {str(item["text"]) for item in NORMAL_SEEDS}

    for label, seeds, prompt_tpl, cp_key in (
        (1, ATTACK_SEEDS, ATTACK_PROMPT, "attack"),
        (0, NORMAL_SEEDS, NORMAL_PROMPT, "normal"),
    ):
        pending = [s for s in seeds if str(s["id"]) not in checkpoint[cp_key]]
        stats["skipped"] += len(seeds) - len(pending)
        print(f"[info] {cp_key}: 待生成 {len(pending)} 个种子，批大小 {BATCH_SIZE}")
        for start in range(0, len(pending), BATCH_SIZE):
            batch = pending[start : start + BATCH_SIZE]
            batch_map: dict[str, list[str]] = {}
            for attempt in range(1, MAX_RETRY + 1):
                try:
                    stats["api_calls"] += 1
                    batch_map = call_batch(api_key, batch, prompt_tpl)
                    break
                except urllib.error.HTTPError as error:
                    stats["api_errors"] += 1
                    if attempt == MAX_RETRY:
                        print(f"[warn] 批次失败(HTTP {error.code})，降级逐条：{[s['id'] for s in batch]}")
                    else:
                        time.sleep(2)
                except Exception as error:  # noqa: BLE001
                    stats["api_errors"] += 1
                    if attempt == MAX_RETRY:
                        print(f"[warn] 批次失败({error})，降级逐条")
                    else:
                        time.sleep(2 * attempt)
            time.sleep(REQUEST_INTERVAL_SECONDS)

            missing = [s for s in batch if str(s["id"]) not in batch_map]
            for seed in missing:  # 批内缺失的种子逐条降级
                try:
                    stats["api_calls"] += 1
                    batch_map[str(seed["id"])] = call_single(api_key, seed, prompt_tpl)
                    time.sleep(REQUEST_INTERVAL_SECONDS)
                except Exception as error:  # noqa: BLE001
                    stats["api_errors"] += 1
                    stats["rejected_seeds"] += 1
                    print(f"[warn] {seed['id']} 生成失败，跳过：{str(error)[:100]}")

            for seed in batch:
                seed_id = str(seed["id"])
                cleaned = []
                for item in batch_map.get(seed_id, [])[:VARIANTS_PER_SEED]:
                    ok = sanitize_variant(item, seen_texts)
                    if ok:
                        seen_texts.add(ok)
                        cleaned.append(ok)
                checkpoint[cp_key][seed_id] = cleaned
                stats["generated"] += len(cleaned)
            done = sum(1 for s in seeds if str(s["id"]) in checkpoint[cp_key])
            print(f"[info] {cp_key}: {done}/{len(seeds)} 种子完成，累计变体 {stats['generated']}")
            save_checkpoint(checkpoint)
    return {"stats": stats, "checkpoint": checkpoint}


def build_records(checkpoint: dict) -> list[dict]:
    """按种子组组织：种子与其变体永远落在同一 split，防止数据泄漏。"""
    records: list[dict] = []
    for label, seeds, cp_key in (
        (1, ATTACK_SEEDS, "attack"),
        (0, NORMAL_SEEDS, "normal"),
    ):
        for seed in seeds:
            group_id = str(seed["id"])
            records.append(
                {
                    "text": str(seed["text"]),
                    "label": label,
                    "category": str(seed["category"]),
                    "source": "seed",
                    "group": group_id,
                }
            )
            for index, variant in enumerate(checkpoint[cp_key].get(group_id, [])):
                records.append(
                    {
                        "text": variant,
                        "label": label,
                        "category": str(seed["category"]),
                        "source": f"variant-{index + 1}",
                        "group": group_id,
                    }
                )
    return records


def split_by_group(records: list[dict]) -> dict[str, list[dict]]:
    """分层按组划分：攻击组与正常组各自 80/10/10，同组样本进入同一 split。"""
    rng = random.Random(RANDOM_SEED)
    splits: dict[str, list[dict]] = {"train": [], "dev": [], "test": []}
    for label in (1, 0):
        groups: dict[str, list[dict]] = {}
        for record in records:
            if record["label"] == label:
                groups.setdefault(record["group"], []).append(record)
        group_ids = sorted(groups.keys())
        rng.shuffle(group_ids)
        total = len(group_ids)
        dev_end = max(1, int(total * 0.1))
        test_end = max(dev_end + 1, int(total * 0.2))
        for position, group_id in enumerate(group_ids):
            if position < dev_end:
                splits["dev"].extend(groups[group_id])
            elif position < test_end:
                splits["test"].extend(groups[group_id])
            else:
                splits["train"].extend(groups[group_id])
    return splits


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> None:
    api_key = load_zhipu_key()
    api_stats = None
    if api_key:
        print(f"[info] 使用智谱API批量生成变体（每类目标 {TARGET_PER_CLASS} 条）")
        result = generate_variants(api_key)
        api_stats = result["stats"]
        print(f"[info] API统计：{result['stats']}")
        checkpoint = result["checkpoint"]
    else:
        print("[warn] 未配置 ZHIPU_API_KEY，仅使用种子样本构建数据集")
        checkpoint = load_checkpoint()

    records = build_records(checkpoint)
    splits = split_by_group(records)

    write_jsonl(DATASET_DIR / "jailbreak_dataset_full.jsonl", records)
    for name, items in splits.items():
        write_jsonl(DATASET_DIR / f"{name}.jsonl", items)

    attack_total = sum(1 for r in records if r["label"] == 1)
    normal_total = sum(1 for r in records if r["label"] == 0)
    report = {
        "task": "B-01 数据集构建",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(records),
        "attack": attack_total,
        "normal": normal_total,
        "target_met": attack_total >= TARGET_PER_CLASS and normal_total >= TARGET_PER_CLASS,
        "api_stats": api_stats,
        "splits": {
            name: {
                "total": len(items),
                "attack": sum(1 for r in items if r["label"] == 1),
                "normal": sum(1 for r in items if r["label"] == 0),
                "groups": len({r["group"] for r in items}),
            }
            for name, items in splits.items()
        },
        "seed_categories": {
            "attack": len({r["category"] for r in records if r["label"] == 1}),
            "normal": len({r["category"] for r in records if r["label"] == 0}),
        },
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[done] 数据集：攻击 {attack_total} + 正常 {normal_total} = {len(records)} 条")
    print(f"[done] 输出目录：{DATASET_DIR}")
    print(f"[done] 报告：{REPORT_PATH}")


if __name__ == "__main__":
    main()
