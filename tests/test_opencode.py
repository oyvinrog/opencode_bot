import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from matrix_opencode_bot.opencode import OpenCodeClient, OpenCodeError


class FakeContent:
    def __init__(self, lines: list[bytes]) -> None:
        self.lines = lines

    def __aiter__(self) -> AsyncIterator[bytes]:
        async def iterate() -> AsyncIterator[bytes]:
            for line in self.lines:
                yield line
        return iterate()


class FakeResponse:
    def __init__(self, status: int, payload: object, lines: list[bytes] | None = None) -> None:
        self.status = status
        self.payload = payload
        self.content = FakeContent(lines or [])

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *_: object) -> None:
        pass

    async def text(self) -> str:
        return self.payload if isinstance(self.payload, str) else json.dumps(self.payload)


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


async def test_health_and_directory_scoped_session_creation() -> None:
    fake = FakeSession([
        FakeResponse(200, {"healthy": True, "version": "1.2"}),
        FakeResponse(200, {"id": "ses_1"}),
    ])
    client = OpenCodeClient("http://localhost:4096/", session=fake)  # type: ignore[arg-type]
    assert (await client.health())["version"] == "1.2"
    await client.create_session("/work", "Matrix")
    assert fake.calls[1][2]["params"] == {"directory": "/work"}
    assert fake.calls[1][2]["json"] == {"title": "Matrix"}


async def test_error_message_is_sanitized_from_api_payload() -> None:
    fake = FakeSession([FakeResponse(401, {"data": {"message": "bad login"}})])
    client = OpenCodeClient("http://localhost", session=fake)  # type: ignore[arg-type]
    with pytest.raises(OpenCodeError, match="HTTP 401: bad login"):
        await client.health()


async def test_prompt_uses_async_endpoint() -> None:
    fake = FakeSession([FakeResponse(204, "")])
    client = OpenCodeClient("http://localhost", session=fake)  # type: ignore[arg-type]
    await client.prompt_async("ses /1", "/work", "hello")
    method, url, kwargs = fake.calls[0]
    assert method == "POST"
    assert url.endswith("/session/ses%20%2F1/prompt_async")
    assert kwargs["json"] == {"parts": [{"type": "text", "text": "hello"}]}


async def test_verifier_prompt_options_and_session_deletion() -> None:
    fake = FakeSession([FakeResponse(204, ""), FakeResponse(200, True)])
    client = OpenCodeClient("http://localhost", session=fake)  # type: ignore[arg-type]
    await client.prompt_async(
        "verify", "/work", "check", system="read only", tools={"write": False}
    )
    assert fake.calls[0][2]["json"] == {
        "parts": [{"type": "text", "text": "check"}],
        "system": "read only",
        "tools": {"write": False},
    }
    assert await client.delete_session("verify", "/work") is True
    assert fake.calls[1][0] == "DELETE"
    assert fake.calls[1][1].endswith("/session/verify")


async def test_sse_parser_yields_global_event() -> None:
    event = {"directory": "/work", "payload": {"type": "session.idle", "properties": {"sessionID": "ses"}}}
    fake = FakeSession([FakeResponse(200, "", [f"data: {json.dumps(event)}\n".encode(), b"\n"])])
    client = OpenCodeClient("http://localhost", session=fake)  # type: ignore[arg-type]
    stop = asyncio.Event()
    stream = client.global_events(stop)
    assert await anext(stream) == event
    stop.set()
    await stream.aclose()


def test_basic_auth_is_configured_only_with_password() -> None:
    protected = OpenCodeClient("http://localhost", "user", "secret")
    unprotected = OpenCodeClient("http://localhost", "user", None)
    assert protected.headers["Authorization"].startswith("Basic ")
    assert unprotected.headers == {}
