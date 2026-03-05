"""
LangChain integration for sentinel-inject.

Provides a SafeTool wrapper that screens LangChain tool outputs
before they enter the agent's context.

Usage::

    from langchain.tools import Tool
    from sentinel_inject.integrations.langchain import SafeTool, wrap_langchain_tool

    # Method 1: Wrap an existing LangChain Tool
    from langchain_community.tools import DuckDuckGoSearchRun

    search = DuckDuckGoSearchRun()
    safe_search = wrap_langchain_tool(search)

    # Method 2: Use SafeTool as a base class
    class MyTool(SafeTool):
        name = "my_tool"
        description = "Does something"

        def _run(self, query: str) -> str:
            result = external_api_call(query)
            # Automatic screening happens in the parent class
            return result

    # Method 3: Wrap a function-based tool
    from sentinel_inject.integrations.langchain import safe_tool

    @safe_tool(name="web_fetch", description="Fetch a URL")
    def fetch_url(url: str) -> str:
        ...
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional, Type

from ..middleware import Middleware, MiddlewareConfig
from ..sanitizer import SanitizationMode

logger = logging.getLogger("sentinel_inject.integrations.langchain")


def _get_base_tool_class() -> Type:
    """Lazy import of LangChain BaseTool to avoid hard dependency."""
    try:
        from langchain_core.tools import BaseTool
        return BaseTool
    except ImportError:
        try:
            from langchain.tools import BaseTool  # type: ignore[no-redef]
            return BaseTool
        except ImportError as exc:
            raise ImportError(
                "langchain or langchain-core is required for the LangChain integration. "
                "Install with: pip install langchain-core"
            ) from exc


class SafeTool:
    """
    LangChain-compatible tool wrapper with built-in injection screening.

    Subclass this instead of BaseTool to get automatic screening of
    all tool outputs.

    Example::

        class WebSearch(SafeTool):
            name = "web_search"
            description = "Search the web"

            def _run(self, query: str) -> str:
                return actual_search(query)
    """

    _sentinel_middleware: Optional[Middleware] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    def __init__(
        self,
        middleware: Optional[Middleware] = None,
        sanitization_mode: SanitizationMode = SanitizationMode.LABEL,
        **kwargs: Any,
    ) -> None:
        # Try to init the LangChain base class
        BaseTool = _get_base_tool_class()
        if isinstance(self, BaseTool):
            # Call BaseTool.__init__ without our extra kwargs
            super().__init__(**kwargs)  # type: ignore[call-arg]

        self._sentinel_middleware = middleware or Middleware(
            config=MiddlewareConfig(sanitization_mode=sanitization_mode)
        )

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Override run to screen the output."""
        result = super().run(*args, **kwargs)  # type: ignore[misc]
        if isinstance(result, str):
            return self._sentinel_middleware.process_tool_result(  # type: ignore[union-attr]
                result, tool_name=getattr(self, "name", "langchain_tool")
            )
        return result

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async version."""
        result = await super().arun(*args, **kwargs)  # type: ignore[misc]
        if isinstance(result, str):
            return self._sentinel_middleware.process_tool_result(  # type: ignore[union-attr]
                result, tool_name=getattr(self, "name", "langchain_tool")
            )
        return result


def wrap_langchain_tool(
    tool: Any,
    middleware: Optional[Middleware] = None,
    sanitization_mode: SanitizationMode = SanitizationMode.LABEL,
) -> Any:
    """
    Wrap an existing LangChain tool to screen its outputs.

    Returns a new tool object whose run/arun methods screen results.
    The original tool is not modified.

    Args:
        tool:               Any LangChain-compatible tool.
        middleware:         Optional pre-configured Middleware instance.
        sanitization_mode:  Sanitization mode if using default middleware.

    Returns:
        Wrapped tool with screening applied.
    """
    mw = middleware or Middleware(
        config=MiddlewareConfig(sanitization_mode=sanitization_mode)
    )
    tool_name = getattr(tool, "name", "langchain_tool")

    original_run = tool.run
    original_arun = getattr(tool, "arun", None)

    @functools.wraps(original_run)
    def safe_run(*args: Any, **kwargs: Any) -> Any:
        result = original_run(*args, **kwargs)
        if isinstance(result, str):
            return mw.process_tool_result(result, tool_name=tool_name)
        return result

    tool.run = safe_run

    if original_arun is not None:
        @functools.wraps(original_arun)
        async def safe_arun(*args: Any, **kwargs: Any) -> Any:
            result = await original_arun(*args, **kwargs)
            if isinstance(result, str):
                return mw.process_tool_result(result, tool_name=tool_name)
            return result

        tool.arun = safe_arun

    return tool


def safe_tool(
    name: str,
    description: str,
    middleware: Optional[Middleware] = None,
    sanitization_mode: SanitizationMode = SanitizationMode.LABEL,
) -> Callable:
    """
    Decorator to create a safe LangChain tool from a function.

    Usage::

        @safe_tool(name="web_fetch", description="Fetch a webpage")
        def fetch_url(url: str) -> str:
            return requests.get(url).text
    """
    mw = middleware or Middleware(
        config=MiddlewareConfig(sanitization_mode=sanitization_mode)
    )

    def decorator(fn: Callable) -> Any:
        try:
            from langchain_core.tools import tool as lc_tool
        except ImportError:
            from langchain.tools import tool as lc_tool  # type: ignore[no-redef]

        @lc_tool(name, description=description)  # type: ignore[call-arg]
        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            if isinstance(result, str):
                return mw.process_tool_result(result, tool_name=name)
            return result

        return wrapped

    return decorator
