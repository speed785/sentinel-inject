from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


logger = logging.getLogger("sentinel_inject.observability")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanMetrics:
    total_scans: int = 0
    injections_detected: int = 0
    injections_blocked: int = 0
    llm_calls: int = 0
    avg_confidence: float = 0.0
    avg_latency_ms: float = 0.0
    false_positives: int = 0
    llm_cost_usd: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0


class ScanLogger:
    def __init__(self, name: str = "sentinel_inject.scan_events") -> None:
        self._logger = logging.getLogger(name)
        self._lock = threading.Lock()
        self.metrics = ScanMetrics()
        self._latencies: List[float] = []

    def scan_started(self, *, content_hash: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self._emit(
            "scan_started",
            content_hash=content_hash,
            rule_ids_fired=[],
            confidence=0.0,
            action_taken="started",
            latency_ms=0.0,
            metadata=metadata or {},
        )

    def rule_matched(
        self,
        *,
        content_hash: str,
        rule_id: str,
        reason: str,
        confidence: float,
    ) -> None:
        self._emit(
            "rule_matched",
            content_hash=content_hash,
            rule_ids_fired=[rule_id],
            confidence=confidence,
            action_taken="rule_matched",
            latency_ms=0.0,
            reason=reason,
        )

    def llm_classified(
        self,
        *,
        content_hash: str,
        model: str,
        tokens_used: int,
        latency_ms: float,
        result: bool,
        confidence: float,
        cache_hit: bool,
        cost_usd: Optional[float] = None,
    ) -> None:
        with self._lock:
            if not cache_hit:
                self.metrics.llm_calls += 1
                if cost_usd is None:
                    cost_usd = (tokens_used / 1000.0) * 0.00015
                self.metrics.llm_cost_usd += float(cost_usd)

        self._emit(
            "llm_classified",
            content_hash=content_hash,
            rule_ids_fired=[],
            confidence=confidence,
            action_taken="llm_classified",
            latency_ms=latency_ms,
            model=model,
            tokens_used=tokens_used,
            result=result,
            cache_hit=cache_hit,
            cost_usd=cost_usd,
        )

    def scan_complete(
        self,
        *,
        content_hash: str,
        rule_ids_fired: List[str],
        confidence: float,
        action_taken: str,
        latency_ms: float,
        injection_detected: bool,
        injection_blocked: bool,
    ) -> None:
        with self._lock:
            self.metrics.total_scans += 1
            if injection_detected:
                self.metrics.injections_detected += 1
            if injection_blocked:
                self.metrics.injections_blocked += 1

            n = self.metrics.total_scans
            self.metrics.avg_confidence = (
                ((self.metrics.avg_confidence * (n - 1)) + confidence) / n
            )
            self.metrics.avg_latency_ms = (
                ((self.metrics.avg_latency_ms * (n - 1)) + latency_ms) / n
            )
            self._latencies.append(latency_ms)
            self.metrics.p50_latency_ms = self._percentile(self._latencies, 50)
            self.metrics.p95_latency_ms = self._percentile(self._latencies, 95)
            self.metrics.p99_latency_ms = self._percentile(self._latencies, 99)

        self._emit(
            "scan_complete",
            content_hash=content_hash,
            rule_ids_fired=rule_ids_fired,
            confidence=confidence,
            action_taken=action_taken,
            latency_ms=latency_ms,
        )

    def injection_blocked(
        self,
        *,
        content_hash: str,
        rule_ids_fired: List[str],
        confidence: float,
        latency_ms: float,
    ) -> None:
        self._emit(
            "injection_blocked",
            content_hash=content_hash,
            rule_ids_fired=rule_ids_fired,
            confidence=confidence,
            action_taken="blocked",
            latency_ms=latency_ms,
        )

    def mark_false_positive(self) -> None:
        with self._lock:
            self.metrics.false_positives += 1

    def export_prometheus(self) -> str:
        m = self.metrics
        lines = [
            "# HELP sentinel_scans_total Total number of scans",
            "# TYPE sentinel_scans_total counter",
            f"sentinel_scans_total {m.total_scans}",
            "# HELP sentinel_injections_detected_total Injections detected",
            "# TYPE sentinel_injections_detected_total counter",
            f"sentinel_injections_detected_total {m.injections_detected}",
            "# HELP sentinel_injections_blocked_total Injections blocked",
            "# TYPE sentinel_injections_blocked_total counter",
            f"sentinel_injections_blocked_total {m.injections_blocked}",
            "# HELP sentinel_false_positives_total False positives",
            "# TYPE sentinel_false_positives_total counter",
            f"sentinel_false_positives_total {m.false_positives}",
            "# HELP sentinel_llm_calls_total LLM classification calls",
            "# TYPE sentinel_llm_calls_total counter",
            f"sentinel_llm_calls_total {m.llm_calls}",
            "# HELP sentinel_llm_cost_usd_total Estimated LLM USD cost",
            "# TYPE sentinel_llm_cost_usd_total counter",
            f"sentinel_llm_cost_usd_total {m.llm_cost_usd:.8f}",
            "# HELP sentinel_scan_confidence_avg Average scan confidence",
            "# TYPE sentinel_scan_confidence_avg gauge",
            f"sentinel_scan_confidence_avg {m.avg_confidence:.6f}",
            "# HELP sentinel_scan_latency_ms_avg Average scan latency in ms",
            "# TYPE sentinel_scan_latency_ms_avg gauge",
            f"sentinel_scan_latency_ms_avg {m.avg_latency_ms:.4f}",
            "# HELP sentinel_scan_latency_ms_p50 P50 scan latency in ms",
            "# TYPE sentinel_scan_latency_ms_p50 gauge",
            f"sentinel_scan_latency_ms_p50 {m.p50_latency_ms:.4f}",
            "# HELP sentinel_scan_latency_ms_p95 P95 scan latency in ms",
            "# TYPE sentinel_scan_latency_ms_p95 gauge",
            f"sentinel_scan_latency_ms_p95 {m.p95_latency_ms:.4f}",
            "# HELP sentinel_scan_latency_ms_p99 P99 scan latency in ms",
            "# TYPE sentinel_scan_latency_ms_p99 gauge",
            f"sentinel_scan_latency_ms_p99 {m.p99_latency_ms:.4f}",
        ]
        return "\n".join(lines) + "\n"

    def _emit(self, event_name: str, **payload: Any) -> None:
        event = {
            "event": event_name,
            "timestamp": _utc_now(),
            **payload,
        }
        self._logger.info(json.dumps(event, sort_keys=True))

    @staticmethod
    def _percentile(values: List[float], percentile: float) -> float:
        if not values:
            return 0.0
        sorted_values = sorted(values)
        idx = int(round((percentile / 100.0) * (len(sorted_values) - 1)))
        return float(sorted_values[max(0, min(idx, len(sorted_values) - 1))])


class AuditTrail:
    def __init__(self, file_path: Optional[str] = None, enabled: bool = False) -> None:
        self.enabled = enabled
        self._lock = threading.Lock()
        self._path = Path(file_path) if file_path else None
        if self.enabled and self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.touch(exist_ok=True)

    def append(self, event: Dict[str, Any]) -> None:
        if not self.enabled or self._path is None:
            return
        safe_event = dict(event)
        safe_event.pop("content", None)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(safe_event, sort_keys=True) + "\n")

    def append_scan(
        self,
        *,
        content_hash: str,
        rule_ids_fired: List[str],
        confidence: float,
        action_taken: str,
        latency_ms: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.append(
            {
                "timestamp": _utc_now(),
                "event": "scan_audit",
                "content_hash": content_hash,
                "rule_ids_fired": rule_ids_fired,
                "confidence": confidence,
                "action_taken": action_taken,
                "latency_ms": latency_ms,
                "metadata": metadata or {},
            }
        )
