"""
Middleware - drop-in wrappers for tool results and user input.

Provides a convenient layer that sits between external content
(tool outputs, user messages, fetched web pages) and the agent context.

Usage with a generic tool runner::

    from sentinel_inject import Middleware, MiddlewareConfig, SanitizationMode

    mw = Middleware(config=MiddlewareConfig(sanitization_mode=SanitizationMode.REDACT))

    # Wrap a tool result before adding it to context
    safe_result = mw.process_tool_result(raw_tool_output, tool_name="web_search")

    # Wrap user input
    safe_input = mw.process_user_input(user_message)
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .scanner import Scanner, ScanResult, ThreatLevel
from .sanitizer import SanitizationMode

logger = logging.getLogger("sentinel_inject.middleware")


@dataclass
class MiddlewareConfig:
    """Configuration for the Middleware layer."""

    sanitization_mode: SanitizationMode = SanitizationMode.LABEL

    # Block content instead of passing sanitized version when threat found
    block_on_threat: bool = False

    # Block message returned when block_on_threat=True
    block_message: str = (
        "[SENTINEL] Content blocked: prompt injection attempt detected."
    )

    # Raise an exception instead of returning sanitized/blocked content
    raise_on_threat: bool = False

    # Sources that should always be scanned with higher scrutiny
    high_risk_sources: List[str] = field(
        default_factory=lambda: ["web_fetch", "browser", "file_read", "url"]
    )

    # Sources that are considered trusted (scanning still occurs but
    # lower thresholds are applied)
    trusted_sources: List[str] = field(default_factory=list)

    # Force LLM detection for high-risk sources
    force_llm_for_high_risk: bool = True

    # Scan user input (enable for untrusted user scenarios)
    scan_user_input: bool = True


class InjectionDetectedError(Exception):
    """Raised when raise_on_threat=True and an injection is detected."""

    def __init__(self, scan_result: ScanResult) -> None:
        self.scan_result = scan_result
        super().__init__(
            f"Prompt injection detected (confidence={scan_result.confidence:.0%}, "
            f"level={scan_result.threat_level.value})"
        )


class Middleware:
    """
    Drop-in middleware for screening external content.

    Wraps a Scanner and provides convenient methods for the most
    common use cases in AI agent pipelines.
    """

    def __init__(
        self,
        scanner: Optional[Scanner] = None,
        config: Optional[MiddlewareConfig] = None,
    ) -> None:
        self.config = config or MiddlewareConfig()
        self._scanner = scanner or Scanner(
            sanitization_mode=self.config.sanitization_mode
        )
        self._scan_history: List[ScanResult] = []

    # ------------------------------------------------------------------
    # Main processing methods
    # ------------------------------------------------------------------

    def process_tool_result(
        self,
        content: str,
        tool_name: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Screen a tool result before it enters the agent context.

        Returns the safe (possibly sanitized) content string.
        Raises InjectionDetectedError if raise_on_threat is configured.
        """
        is_high_risk = any(
            hr in tool_name.lower() for hr in self.config.high_risk_sources
        )
        force_llm = self.config.force_llm_for_high_risk and is_high_risk

        meta = {"source": "tool_result", "tool_name": tool_name, **(metadata or {})}
        result = self._scanner.scan(content, metadata=meta, force_llm=force_llm)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    async def async_process_tool_result(
        self,
        content: str,
        tool_name: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        is_high_risk = any(
            hr in tool_name.lower() for hr in self.config.high_risk_sources
        )
        force_llm = self.config.force_llm_for_high_risk and is_high_risk

        meta = {"source": "tool_result", "tool_name": tool_name, **(metadata or {})}
        result = await self._scanner.async_scan(content, metadata=meta, force_llm=force_llm)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    def process_user_input(
        self,
        content: str,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Screen user input before it enters the agent context.

        Returns safe content string.
        """
        if not self.config.scan_user_input:
            return content

        meta = {"source": "user_input", "user_id": user_id, **(metadata or {})}
        result = self._scanner.scan(content, metadata=meta)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    async def async_process_user_input(
        self,
        content: str,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not self.config.scan_user_input:
            return content

        meta = {"source": "user_input", "user_id": user_id, **(metadata or {})}
        result = await self._scanner.async_scan(content, metadata=meta)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    def process_web_content(
        self,
        content: str,
        url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Screen fetched web content (highest risk category).

        Always forces LLM detection when an LLM detector is configured.
        """
        meta = {"source": "web_content", "url": url, **(metadata or {})}
        result = self._scanner.scan(content, metadata=meta, force_llm=True)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    async def async_process_web_content(
        self,
        content: str,
        url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        meta = {"source": "web_content", "url": url, **(metadata or {})}
        result = await self._scanner.async_scan(content, metadata=meta, force_llm=True)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    def process_document(
        self,
        content: str,
        doc_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Screen document content (PDF, file reads, etc.)."""
        meta = {"source": "document", "doc_name": doc_name, **(metadata or {})}
        result = self._scanner.scan(content, metadata=meta)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    async def async_process_document(
        self,
        content: str,
        doc_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        meta = {"source": "document", "doc_name": doc_name, **(metadata or {})}
        result = await self._scanner.async_scan(content, metadata=meta)
        self._scan_history.append(result)

        return self._handle_result(result, content)

    def scan(self, content: str, **kwargs: Any) -> ScanResult:
        """
        Raw scan that returns the full ScanResult (no automatic handling).
        Use this when you want full control over the response.
        """
        return self._scanner.scan(content, **kwargs)

    def screen(self, content: str, **kwargs: Any) -> ScanResult:
        return self.scan(content, **kwargs)

    async def async_screen(self, content: str, **kwargs: Any) -> ScanResult:
        return await self._scanner.async_scan(content, **kwargs)

    # ------------------------------------------------------------------
    # Decorator / wrapper utilities
    # ------------------------------------------------------------------

    def wrap_tool(self, tool_name: Optional[str] = None) -> Callable[..., Any]:
        """
        Decorator that wraps a tool function to screen its output.

        Usage::

            @mw.wrap_tool("web_search")
            def web_search(query: str) -> str:
                ...

            # Or without decorator syntax:
            safe_fn = mw.wrap_tool("web_search")(original_fn)
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            name = tool_name or fn.__name__

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                raw_result = fn(*args, **kwargs)
                if isinstance(raw_result, str):
                    return self.process_tool_result(raw_result, tool_name=name)
                # For non-string results, convert to string, scan, return original
                # (only log a warning for non-string tool results)
                logger.debug(
                    "Tool '%s' returned non-string result (%s); skipping scan",
                    name,
                    type(raw_result).__name__,
                )
                return raw_result

            return wrapper

        return decorator

    # ------------------------------------------------------------------
    # Audit / history
    # ------------------------------------------------------------------

    @property
    def scan_history(self) -> List[ScanResult]:
        """Return all scan results recorded by this middleware instance."""
        return list(self._scan_history)

    @property
    def threat_count(self) -> int:
        """Count of scans that resulted in a threat or critical level."""
        return sum(1 for r in self._scan_history if r.is_threat)

    def clear_history(self) -> None:
        self._scan_history.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handle_result(self, result: ScanResult, original: str) -> str:
        if not result.is_threat:
            return original

        if self.config.raise_on_threat:
            raise InjectionDetectedError(result)

        if self.config.block_on_threat:
            logger.warning(
                "Content blocked (threat_level=%s, confidence=%.0f%%)",
                result.threat_level.value,
                result.confidence * 100,
            )
            return self.config.block_message

        # Return sanitized content
        return result.sanitized_content or original
