"""
Sanitizer - neutralizes detected prompt injection attempts.

Provides multiple sanitization modes ranging from warning labels
to full redaction, depending on the application's risk tolerance.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import List, Optional


class SanitizationMode(str, Enum):
    """
    How aggressively to sanitize detected injection content.

    LABEL   - Wrap suspicious content with a visible warning label.
              The original text is preserved but flagged.
    REDACT  - Replace matched injection segments with [REDACTED].
    ESCAPE  - Escape injection syntax (delimiters, special chars) to
              defuse the payload while keeping readable context.
    BLOCK   - Return a placeholder; do NOT pass any content through.
    """

    LABEL = "label"
    REDACT = "redact"
    ESCAPE = "escape"
    BLOCK = "block"


_LABEL_PREFIX = "[⚠ SENTINEL: POSSIBLE INJECTION DETECTED] "
_LABEL_SUFFIX = " [/SENTINEL]"

_BLOCK_MESSAGE = (
    "[SENTINEL] This content was blocked because it contains a detected "
    "prompt injection attempt and cannot be passed to the agent context."
)

# Patterns used for the ESCAPE mode
_ESCAPE_PATTERNS = [
    # Remove zero-width / invisible characters
    (re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]"), ""),
    # Neutralize delimiter markers (convert to visually similar but inert chars)
    (re.compile(r"<\|?(system|user|assistant|im_start|im_end)\|?>", re.IGNORECASE), r"[\1]"),
    (re.compile(r"\[INST\]|\[/INST\]", re.IGNORECASE), "[inst]"),
    (re.compile(r"<<SYS>>|<</SYS>>", re.IGNORECASE), "<<sys>>"),
    # Defuse script tags
    (re.compile(r"<script", re.IGNORECASE), "&lt;script"),
    (re.compile(r"</script>", re.IGNORECASE), "&lt;/script&gt;"),
    # Neutralize "ignore/forget previous instructions" phrases
    (
        re.compile(
            r"\b(ignore|disregard|forget|override)\b(.{0,30})\b"
            r"(previous|prior|above|all|system)\b(.{0,30})\b"
            r"(instructions?|prompts?|context|rules?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        r"[NEUTRALIZED:\1\2\3\4\5]",
    ),
]

# Patterns for locating injection segments to redact
_REDACT_PATTERNS = [
    re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,60}"
        r"\b(instructions?|prompts?|context|rules?)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(```\s*(system|user|assistant)\b.*?```"
        r"|<\|?(system|user|assistant|im_start|im_end)\|?>.*?<\|?im_end\|?>)",
        re.IGNORECASE | re.DOTALL,
    ),
]


class Sanitizer:
    """
    Content sanitizer that neutralizes prompt injection payloads.

    Usage::

        sanitizer = Sanitizer(mode=SanitizationMode.ESCAPE)
        clean = sanitizer.sanitize(content, match_spans=[(10, 45)])
    """

    def __init__(self, mode: SanitizationMode = SanitizationMode.LABEL) -> None:
        self.mode = mode

    def sanitize(
        self,
        content: str,
        match_spans: Optional[List[tuple]] = None,
    ) -> str:
        """
        Sanitize content according to the configured mode.

        Args:
            content: The original content to sanitize.
            match_spans: Optional list of (start, end) tuples from rule
                         matches. Used by REDACT mode to target specific
                         regions. If not provided, REDACT patterns are
                         applied globally.

        Returns:
            Sanitized string.
        """
        if self.mode == SanitizationMode.BLOCK:
            return _BLOCK_MESSAGE

        if self.mode == SanitizationMode.LABEL:
            return self._label(content)

        if self.mode == SanitizationMode.ESCAPE:
            return self._escape(content)

        if self.mode == SanitizationMode.REDACT:
            return self._redact(content, match_spans)

        return content  # fallback: pass-through

    # ------------------------------------------------------------------
    # Mode implementations
    # ------------------------------------------------------------------

    def _label(self, content: str) -> str:
        return f"{_LABEL_PREFIX}{content}{_LABEL_SUFFIX}"

    def _escape(self, content: str) -> str:
        result = content
        for pattern, replacement in _ESCAPE_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    def _redact(
        self,
        content: str,
        match_spans: Optional[List[tuple]] = None,
    ) -> str:
        if match_spans:
            # Redact exact matched spans (sorted, non-overlapping)
            spans = sorted(set(match_spans), key=lambda s: s[0])
            result = []
            cursor = 0
            for start, end in spans:
                result.append(content[cursor:start])
                result.append("[REDACTED]")
                cursor = end
            result.append(content[cursor:])
            return "".join(result)

        # Fallback: apply broad redaction patterns
        result = content
        for pattern in _REDACT_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def strip_zero_width(text: str) -> str:
        """Remove zero-width and invisible Unicode characters."""
        zw_pattern = re.compile(
            r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]"
        )
        return zw_pattern.sub("", text)

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        """Collapse excessive whitespace used to pad/obfuscate injections."""
        return re.sub(r"[ \t]{3,}", " ", text).strip()
