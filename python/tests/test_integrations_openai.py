import types

from sentinel_inject.integrations.openai import (
    SafeOpenAIClient,
    screen_tool_call_results,
    wrap_openai_client,
)


class StubMiddleware:
    def process_tool_result(self, content, tool_name="unknown", metadata=None):
        return f"safe:{tool_name}:{content}"


def test_screen_tool_call_results_screens_only_tool_messages():
    messages = [
        {"role": "system", "content": "x"},
        {"role": "tool", "tool_call_id": "call1", "content": "payload"},
    ]
    screened = screen_tool_call_results(messages, middleware=StubMiddleware())
    assert screened[0]["content"] == "x"
    assert screened[1]["content"].startswith("safe:openai_tool:call1")


def test_wrap_openai_client_intercepts_create():
    captured = {"messages": None}

    class FakeCompletions:
        def create(self, messages, **kwargs):
            captured["messages"] = messages
            return {"ok": True, "kwargs": kwargs}

    class FakeClient:
        def __init__(self):
            self.chat = types.SimpleNamespace(completions=FakeCompletions())

    client = FakeClient()
    wrapped = wrap_openai_client(client, middleware=StubMiddleware())
    response = wrapped.chat.completions.create(
        messages=[{"role": "tool", "tool_call_id": "c1", "content": "danger"}],
        model="gpt",
    )
    assert response["ok"] is True
    assert captured["messages"][0]["content"].startswith("safe:openai_tool:c1")


def test_safe_openai_client_uses_wrapped_chat_interface(monkeypatch):
    class FakeCompletions:
        def create(self, messages, **kwargs):
            return {"messages": messages, "kwargs": kwargs}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.chat = types.SimpleNamespace(completions=FakeCompletions())

    fake_module = types.SimpleNamespace(OpenAI=FakeOpenAI)
    monkeypatch.setitem(__import__("sys").modules, "openai", fake_module)

    client = SafeOpenAIClient(middleware=StubMiddleware(), api_key="x")
    result = client.chat.completions.create(
        messages=[{"role": "tool", "tool_call_id": "c2", "content": "danger"}],
        model="gpt",
    )
    assert result["messages"][0]["content"].startswith("safe:openai_tool:c2")
