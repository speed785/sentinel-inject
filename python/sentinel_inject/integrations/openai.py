"""
OpenAI integration for sentinel-inject.

Provides a drop-in wrapper around OpenAI tool call results so they are
screened before entering the agent's context window.

Usage::

    from openai import OpenAI
    from sentinel_inject.integrations.openai import SafeOpenAIClient

    # Wrap the standard OpenAI client
    client = SafeOpenAIClient(api_key="sk-...")

    # All tool call results in chat completions are automatically screened
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[...],
        tools=[...],
    )

    # Or wrap an existing client
    from openai import OpenAI
    from sentinel_inject.integrations.openai import wrap_openai_client

    raw_client = OpenAI(api_key="sk-...")
    safe_client = wrap_openai_client(raw_client)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..middleware import Middleware, MiddlewareConfig
from ..sanitizer import SanitizationMode

logger = logging.getLogger("sentinel_inject.integrations.openai")


def screen_tool_call_results(
    tool_results: List[Dict[str, Any]],
    middleware: Optional[Middleware] = None,
) -> List[Dict[str, Any]]:
    """
    Screen a list of OpenAI tool call result messages.

    Each message should have the shape::

        {
            "role": "tool",
            "tool_call_id": "call_abc123",
            "content": "...tool output..."
        }

    Returns a new list with potentially sanitized content.

    Args:
        tool_results: List of tool result message dicts.
        middleware:   Middleware instance to use. If None, a default
                      (LABEL mode) middleware is created.

    Returns:
        List of (possibly sanitized) tool result dicts.
    """
    mw = middleware or Middleware()
    screened = []

    for msg in tool_results:
        if msg.get("role") != "tool":
            screened.append(msg)
            continue

        content = msg.get("content", "")
        tool_call_id = msg.get("tool_call_id", "unknown")

        safe_content = mw.process_tool_result(
            content,
            tool_name=f"openai_tool:{tool_call_id}",
            metadata={"tool_call_id": tool_call_id},
        )

        if safe_content != content:
            logger.info(
                "Tool call result sanitized [tool_call_id=%s]", tool_call_id
            )

        screened.append({**msg, "content": safe_content})

    return screened


class SafeOpenAIClient:
    """
    A thin wrapper around openai.OpenAI that screens tool call results.

    Behaves identically to the standard OpenAI client but intercepts
    chat completions that include tool calls and screens the follow-up
    tool result messages.

    Note: This wrapper screens content when you submit tool results
    back to the API (the ``"role": "tool"`` messages), not the final
    completion text.
    """

    def __init__(
        self,
        middleware: Optional[Middleware] = None,
        sanitization_mode: SanitizationMode = SanitizationMode.LABEL,
        **openai_kwargs: Any,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "openai package is required. Install with: pip install openai"
            ) from exc

        self._client = OpenAI(**openai_kwargs)
        self._middleware = middleware or Middleware(
            config=MiddlewareConfig(sanitization_mode=sanitization_mode)
        )
        self.chat = _SafeChatCompletions(self._client, self._middleware)

    def __getattr__(self, name: str) -> Any:
        """Delegate all other attributes to the underlying client."""
        return getattr(self._client, name)


class _SafeChatCompletions:
    def __init__(self, client: Any, middleware: Middleware) -> None:
        self._client = client
        self._middleware = middleware
        self.completions = _SafeCompletionsCreate(client, middleware)


class _SafeCompletionsCreate:
    def __init__(self, client: Any, middleware: Middleware) -> None:
        self._client = client
        self._middleware = middleware

    def create(self, messages: List[Dict], **kwargs: Any) -> Any:
        """
        Screen tool result messages in the conversation before sending.

        Tool result messages (role="tool") are screened before the
        request is sent to OpenAI.
        """
        safe_messages = []
        for msg in messages:
            if msg.get("role") == "tool":
                content = msg.get("content", "")
                tool_call_id = msg.get("tool_call_id", "unknown")
                safe_content = self._middleware.process_tool_result(
                    content,
                    tool_name=f"openai_tool:{tool_call_id}",
                    metadata={"tool_call_id": tool_call_id},
                )
                safe_messages.append({**msg, "content": safe_content})
            else:
                safe_messages.append(msg)

        return self._client.chat.completions.create(
            messages=safe_messages, **kwargs
        )


def wrap_openai_client(
    client: Any,
    middleware: Optional[Middleware] = None,
    sanitization_mode: SanitizationMode = SanitizationMode.LABEL,
) -> SafeOpenAIClient:
    """
    Wrap an existing openai.OpenAI client with injection screening.

    Returns a SafeOpenAIClient that delegates all calls to the
    provided client but screens tool results.
    """
    safe = SafeOpenAIClient.__new__(SafeOpenAIClient)
    safe._client = client
    safe._middleware = middleware or Middleware(
        config=MiddlewareConfig(sanitization_mode=sanitization_mode)
    )
    safe.chat = _SafeChatCompletions(client, safe._middleware)
    return safe
