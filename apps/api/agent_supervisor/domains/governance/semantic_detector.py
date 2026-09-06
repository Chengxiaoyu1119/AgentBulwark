"""语义检测通道（B-03）：ONNX BERT 越狱分类器的懒加载推理封装。

双通道架构：
- 规则通道：supervisor 内置策略（<5ms），先行短路明确风险；
- 语义通道：本模块（<50ms），仅在规则未拦截且 prompt 非空时兜底。

设计约束：
- onnxruntime / tokenizers 为可选依赖，未安装或模型文件缺失时整体降级为不可用，
  decide() 行为与未接入时完全一致，保证零 ML 依赖环境测试全绿；
- 推理带超时保护，超时视为本轮不可用并返回降级结果，不阻塞调用链。
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[5]
MODEL_DIR = PROJECT_ROOT / "legacy" / "training" / "model"
MODEL_PATH = MODEL_DIR / "jailbreak_bert.onnx"
TOKENIZER_PATH = MODEL_DIR / "tokenizer.json"

# 置信度阈值：>=REJECT 则拒绝，>=REVIEW 则询问（B-02 训练完成后可校准）
REJECT_THRESHOLD = 0.9
REVIEW_THRESHOLD = 0.5
INFERENCE_TIMEOUT_SECONDS = 0.045
MAX_SEQUENCE_LENGTH = 128


@dataclass
class SemanticResult:
    available: bool
    probability: float = 0.0
    latency_ms: float = 0.0
    model_version: str = ""
    degraded_reason: str = ""


class SemanticDetector:
    """线程安全的懒加载 ONNX 语义检测器（进程内单例）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session = None
        self._tokenizer = None
        self._model_version = ""
        self._load_attempted = False
        # Keep semantic inference single-flight.  A Python thread cannot be
        # force-killed when an ONNX provider hangs; creating a fresh executor
        # per request would therefore leak one worker for every timed-out
        # request and turn the detector into a resource-exhaustion vector.
        self._inference_executor: ThreadPoolExecutor | None = None
        self._inference_future: Future[float] | None = None

    # -- 生命周期 -----------------------------------------------------------

    def _try_load(self) -> bool:
        if self._load_attempted:
            return self._session is not None
        self._load_attempted = True
        if not self.enabled_by_config():
            return False
        try:

            import onnxruntime as ort  # noqa: PLC0415
            from tokenizers import Tokenizer  # noqa: PLC0415

            if not MODEL_PATH.exists() or not TOKENIZER_PATH.exists():
                return False
            session = ort.InferenceSession(
                str(MODEL_PATH),
                providers=["CPUExecutionProvider"],
            )
            tokenizer = Tokenizer.from_file(str(TOKENIZER_PATH))
            version_path = MODEL_DIR / "model_version.txt"
            version = version_path.read_text(encoding="utf-8").strip() if version_path.exists() else "unknown"
        except Exception:  # noqa: BLE001 - 任何加载失败都降级为不可用
            return False
        self._session = session
        self._tokenizer = tokenizer
        self._model_version = version
        self._input_names = [item.name for item in session.get_inputs()]
        return True

    @staticmethod
    def enabled_by_config() -> bool:
        return os.environ.get("SEMANTIC_DETECT_ENABLED", "1").strip().lower() not in {"0", "false", "off"}

    @property
    def model_version(self) -> str:
        return self._model_version

    # -- 推理 ---------------------------------------------------------------

    def detect(self, text: str) -> SemanticResult:
        """对文本做越狱概率推理；不可用/超时时返回降级结果。"""
        if not text or not text.strip():
            return SemanticResult(available=False, degraded_reason="empty-input")
        with self._lock:
            if not self._try_load():
                return SemanticResult(available=False, degraded_reason="model-unavailable")
            import time

            # A timed-out worker may still be running.  Do not enqueue another
            # inference behind it: fail open to the rule channel for this call
            # and let the single worker drain in the background.
            if self._inference_future is not None:
                if not self._inference_future.done():
                    return SemanticResult(available=False, degraded_reason="inference-busy")
                self._inference_future = None
            if self._inference_executor is None:
                self._inference_executor = ThreadPoolExecutor(
                    max_workers=1,
                    thread_name_prefix="semantic",
                )
            started = time.perf_counter()
            future = self._inference_executor.submit(self._infer, text)
            self._inference_future = future
        try:
            probability = future.result(timeout=INFERENCE_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            # ``Future.cancel`` cannot stop a running ONNX call, but clearing
            # the future here would allow unbounded queued work.  Keep it as
            # the single in-flight marker until the worker actually finishes.
            future.cancel()
            return SemanticResult(
                available=False,
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
                degraded_reason="timeout-or-error",
            )
        except Exception:  # noqa: BLE001 - 推理异常降级
            with self._lock:
                if self._inference_future is future:
                    self._inference_future = None
            return SemanticResult(
                available=False,
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
                degraded_reason="timeout-or-error",
            )
        else:
            with self._lock:
                if self._inference_future is future:
                    self._inference_future = None
            return SemanticResult(
                available=True,
                probability=probability,
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
                model_version=self._model_version,
            )

    def close(self) -> None:
        """Stop the detector's worker when a process/test is being torn down."""
        with self._lock:
            executor = self._inference_executor
            self._inference_executor = None
            self._inference_future = None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

    def _infer(self, text: str) -> float:
        assert self._tokenizer is not None and self._session is not None
        encoding = self._tokenizer.encode(text)
        input_ids = encoding.ids[:MAX_SEQUENCE_LENGTH]
        attention_mask = encoding.attention_mask[:MAX_SEQUENCE_LENGTH]
        pad_length = MAX_SEQUENCE_LENGTH - len(input_ids)
        if pad_length > 0:
            input_ids = input_ids + [0] * pad_length
            attention_mask = attention_mask + [0] * pad_length
        feeds = {
            "input_ids": [input_ids],
            "attention_mask": [attention_mask],
        }
        # 对齐 ONNX 图的实际输入名
        renamed = {}
        for name in self._input_names:
            for key in feeds:
                if key in name or name in key:
                    renamed[name] = feeds[key]
                    break
        outputs = self._session.run(None, renamed or feeds)
        logits = outputs[0][0]
        # softmax 二分类，index 1 为越狱概率
        max_logit = max(logits)
        exps = [pow(2.718281828459045, value - max_logit) for value in logits]
        total = sum(exps)
        return exps[1] / total if len(logits) > 1 else 1.0 - exps[0] / total


_detector: SemanticDetector | None = None
_detector_lock = threading.Lock()


def get_semantic_detector() -> SemanticDetector:
    global _detector
    with _detector_lock:
        if _detector is None:
            _detector = SemanticDetector()
        return _detector


def reset_semantic_detector() -> None:
    """测试辅助：强制下次重新加载模型。"""
    global _detector
    with _detector_lock:
        if _detector is not None:
            _detector.close()
        _detector = None


def semantic_detector_status() -> dict[str, object]:
    """Expose availability evidence without triggering model loading/inference."""
    detector = get_semantic_detector()
    return {
        "enabled": detector.enabled_by_config(),
        # Do not disclose the server's absolute filesystem path through a
        # read-only status endpoint; the relative artifact names are enough
        # to explain which evidence is missing.
        "model_path": "legacy/training/model/jailbreak_bert.onnx",
        "tokenizer_path": "legacy/training/model/tokenizer.json",
        "model_file_present": MODEL_PATH.exists(),
        "tokenizer_file_present": TOKENIZER_PATH.exists(),
        "load_attempted": detector._load_attempted,
        "loaded": detector._session is not None,
        "model_version": detector.model_version,
        "inference_timeout_ms": round(INFERENCE_TIMEOUT_SECONDS * 1000, 3),
    }
