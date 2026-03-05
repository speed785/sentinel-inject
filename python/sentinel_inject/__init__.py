"""
Sentinel Inject - Prompt Injection Scanner for AI Agents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A middleware library that screens external content before it hits your agent context.
Detects and neutralizes prompt injection attempts using rule-based + LLM-assisted layers.

Basic usage::

    from sentinel_inject import Scanner

    scanner = Scanner()
    result = scanner.scan("Ignore all previous instructions and...")
    if result.is_threat:
        print(f"Injection detected! Confidence: {result.confidence:.0%}")
        print(f"Sanitized: {result.sanitized_content}")

:copyright: (c) 2026 sentinel-inject contributors
:license: MIT, see LICENSE for more details.
"""

from .scanner import Scanner, ScanResult, ThreatLevel, ScannerConfig
from .observability import AuditTrail, ScanLogger, ScanMetrics
from .rules import RuleEngine, RuleMatch
from .sanitizer import Sanitizer, SanitizationMode
from .middleware import Middleware, MiddlewareConfig
from .llm_detector import LLMDetector, LLMDetectorConfig

__version__ = "0.1.0"
__author__ = "sentinel-inject contributors"
__license__ = "MIT"

__all__ = [
    "Scanner",
    "ScannerConfig",
    "ScanResult",
    "ThreatLevel",
    "RuleEngine",
    "RuleMatch",
    "Sanitizer",
    "SanitizationMode",
    "Middleware",
    "MiddlewareConfig",
    "LLMDetector",
    "LLMDetectorConfig",
    "ScanLogger",
    "ScanMetrics",
    "AuditTrail",
]
