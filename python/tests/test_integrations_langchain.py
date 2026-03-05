import sys
import types

import pytest

from sentinel_inject.integrations import langchain as lc_integration


class StubMiddleware:
    def process_tool_result(self, content, tool_name="unknown", metadata=None):
        return f"safe:{tool_name}:{content}"


def test_get_base_tool_class_import_error(monkeypatch):
    monkeypatch.delitem(sys.modules, "langchain_core.tools", raising=False)
    monkeypatch.delitem(sys.modules, "langchain.tools", raising=False)
    with pytest.raises(ImportError):
        lc_integration._get_base_tool_class()


def test_wrap_langchain_tool_screens_sync_and_async():
    class Tool:
        name = "demo_tool"

        def run(self, query):
            return f"run:{query}"

        async def arun(self, query):
            return f"arun:{query}"

    tool = Tool()
    wrapped = lc_integration.wrap_langchain_tool(tool, middleware=StubMiddleware())
    assert wrapped.run("x").startswith("safe:demo_tool")


@pytest.mark.asyncio
async def test_wrap_langchain_tool_async_path():
    class Tool:
        name = "async_tool"

        def run(self, query):
            return f"run:{query}"

        async def arun(self, query):
            return f"arun:{query}"

    tool = Tool()
    wrapped = lc_integration.wrap_langchain_tool(tool, middleware=StubMiddleware())
    out = await wrapped.arun("x")
    assert out.startswith("safe:async_tool")


def test_safe_tool_decorator_with_fake_langchain(monkeypatch):
    def fake_tool(name, description):
        def decorator(fn):
            fn.name = name
            fn.description = description
            return fn

        return decorator

    fake_module = types.SimpleNamespace(tool=fake_tool)
    monkeypatch.setitem(sys.modules, "langchain_core.tools", fake_module)

    decorator = lc_integration.safe_tool(
        name="web_fetch",
        description="fetch",
        middleware=StubMiddleware(),
    )

    @decorator
    def fetch(url):
        return f"content:{url}"

    assert fetch("https://example.com").startswith("safe:web_fetch")


@pytest.mark.asyncio
async def test_safetool_class_run_and_arun_with_fake_base(monkeypatch):
    class FakeBaseTool:
        name = "fake_base"

        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def run(self, query):
            return self._run(query)

        async def arun(self, query):
            return await self._arun(query)

    fake_module = types.SimpleNamespace(BaseTool=FakeBaseTool)
    monkeypatch.setitem(sys.modules, "langchain_core.tools", fake_module)

    class DemoTool(lc_integration.SafeTool, FakeBaseTool):
        name = "demo"

        def _run(self, query):
            return f"run:{query}"

        async def _arun(self, query):
            return f"arun:{query}"

    tool = DemoTool(middleware=StubMiddleware())
    assert tool.run("q").startswith("safe:demo")
    assert (await tool.arun("q")).startswith("safe:demo")
