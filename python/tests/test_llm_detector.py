import asyncio

import pytest

from sentinel_inject.llm_detector import LLMDetector, LLMDetectorConfig  # pyright: ignore[reportImplicitRelativeImport]
from sentinel_inject.observability import ScanLogger  # pyright: ignore[reportImplicitRelativeImport]


@pytest.mark.asyncio
async def test_timeout_enforced_with_retries_then_fallback():
    calls = {"count": 0}

    async def slow_classifier(_: str) -> str:
        calls["count"] += 1
        await asyncio.sleep(0.2)
        return '{"is_injection": true, "confidence": 0.9, "reason": "x", "attack_type": "x"}'

    detector = LLMDetector(
        classifier_fn=slow_classifier,
        config=LLMDetectorConfig(timeout=0.01, graceful_fallback=True),
    )
    result = await detector.detect_async("content")

    assert result.used_fallback
    assert calls["count"] == 3


@pytest.mark.asyncio
async def test_retry_succeeds_after_transient_failures():
    calls = {"count": 0}

    async def flaky_classifier(_: str) -> str:
        calls["count"] += 1
        if calls["count"] < 3:
            raise TimeoutError("temporary timeout")
        return '{"is_injection": true, "confidence": 0.95, "reason": "attack", "attack_type": "override"}'

    detector = LLMDetector(classifier_fn=flaky_classifier)
    result = await detector.detect_async("content")

    assert calls["count"] == 3
    assert result.is_injection
    assert not result.used_fallback


@pytest.mark.asyncio
async def test_cache_avoids_duplicate_calls_within_ttl():
    calls = {"count": 0}

    async def classifier(_: str) -> str:
        calls["count"] += 1
        return '{"is_injection": false, "confidence": 0.2, "reason": "safe", "attack_type": null}'

    detector = LLMDetector(classifier_fn=classifier)

    first = await detector.detect_async("same content")
    second = await detector.detect_async("same content")

    assert first.confidence == second.confidence
    assert calls["count"] == 1


def test_strict_json_fallback_does_not_use_fragile_true_heuristic():
    detector = LLMDetector(classifier_fn=lambda _: "is_injection: true confidence: 0.99")
    result = detector.detect("anything")
    assert result.used_fallback
    assert not result.is_injection


@pytest.mark.asyncio
async def test_llm_observability_counts_calls_and_cache_hits():
    calls = {"count": 0}

    async def classifier(_: str):
        calls["count"] += 1
        return {
            "text": '{"is_injection": true, "confidence": 0.95, "reason": "attack", "attack_type": "override"}',
            "tokens_used": 200,
            "model": "test-model",
            "cost_usd": 0.002,
        }

    detector = LLMDetector(classifier_fn=classifier)
    scan_logger = ScanLogger()
    detector.set_scan_logger(scan_logger)

    first = await detector.detect_async("same content")
    second = await detector.detect_async("same content")

    assert first.is_injection
    assert second.is_injection
    assert calls["count"] == 1
    assert scan_logger.metrics.llm_calls == 1
    assert scan_logger.metrics.llm_cost_usd >= 0.002
