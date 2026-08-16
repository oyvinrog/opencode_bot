"""Small asynchronous client for the OpenCode HTTP and SSE APIs."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import aiohttp

LOG = logging.getLogger("matrix_opencode.opencode")


class OpenCodeError(RuntimeError):
    """An OpenCode request failed in a form safe to show to a user."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class OpenCodeClient:
    def __init__(
        self,
        base_url: str,
        username: str = "opencode",
        password: str | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers: dict[str, str] = {}
        if password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"
        self._session = session
        self._owns_session = session is None

    async def __aenter__(self) -> "OpenCodeClient":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout, headers=self.headers)

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
        self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("OpenCodeClient.start() has not been called")
        return self._session

    async def _request(
        self,
        method: str,
        path: str,
        *,
        directory: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        params = {"directory": directory} if directory else None
        try:
            async with self.session.request(
                method,
                f"{self.base_url}{path}",
                params=params,
                json=body,
            ) as response:
                if response.status == 204:
                    return None
                raw = await response.text()
                if response.status >= 400:
                    detail = _error_detail(raw)
                    raise OpenCodeError(
                        f"OpenCode returned HTTP {response.status}: {detail}", response.status
                    )
                if not raw:
                    return None
                try:
                    return json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise OpenCodeError("OpenCode returned an invalid JSON response") from exc
        except OpenCodeError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise OpenCodeError(f"Could not reach OpenCode at {self.base_url}: {exc}") from exc

    async def health(self) -> dict[str, Any]:
        result = await self._request("GET", "/global/health")
        if not isinstance(result, dict) or result.get("healthy") is not True:
            raise OpenCodeError("OpenCode health check did not report healthy=true")
        return result

    async def create_session(self, directory: str, title: str | None = None) -> dict[str, Any]:
        body = {"title": title} if title else {}
        result = await self._request("POST", "/session", directory=directory, body=body)
        if not isinstance(result, dict) or not result.get("id"):
            raise OpenCodeError("OpenCode did not return a session ID")
        return result

    async def get_session(self, session_id: str, directory: str) -> dict[str, Any]:
        result = await self._request(
            "GET", f"/session/{quote(session_id, safe='')}", directory=directory
        )
        if not isinstance(result, dict):
            raise OpenCodeError("OpenCode returned an invalid session")
        return result

    async def session_status(self, directory: str) -> dict[str, dict[str, Any]]:
        result = await self._request("GET", "/session/status", directory=directory)
        return result if isinstance(result, dict) else {}

    async def prompt_async(
        self,
        session_id: str,
        directory: str,
        text: str,
        *,
        system: str | None = None,
        tools: dict[str, bool] | None = None,
    ) -> None:
        body: dict[str, Any] = {"parts": [{"type": "text", "text": text}]}
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools
        await self._request(
            "POST",
            f"/session/{quote(session_id, safe='')}/prompt_async",
            directory=directory,
            body=body,
        )

    async def delete_session(self, session_id: str, directory: str) -> bool:
        result = await self._request(
            "DELETE", f"/session/{quote(session_id, safe='')}", directory=directory
        )
        return bool(result)

    async def messages(
        self, session_id: str, directory: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        path = f"/session/{quote(session_id, safe='')}/message"
        params_directory = directory
        # limit is not handled by _request because it is the only extra query parameter used here.
        try:
            async with self.session.get(
                f"{self.base_url}{path}",
                params={"directory": params_directory, "limit": str(limit)},
            ) as response:
                raw = await response.text()
                if response.status >= 400:
                    raise OpenCodeError(
                        f"OpenCode returned HTTP {response.status}: {_error_detail(raw)}",
                        response.status,
                    )
                result = json.loads(raw)
        except OpenCodeError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
            raise OpenCodeError(f"Could not read OpenCode messages: {exc}") from exc
        return result if isinstance(result, list) else []

    async def diff(self, session_id: str, directory: str) -> list[dict[str, Any]]:
        result = await self._request(
            "GET", f"/session/{quote(session_id, safe='')}/diff", directory=directory
        )
        return result if isinstance(result, list) else []

    async def abort(self, session_id: str, directory: str) -> bool:
        result = await self._request(
            "POST", f"/session/{quote(session_id, safe='')}/abort", directory=directory
        )
        return bool(result)

    async def reply_permission(
        self,
        session_id: str,
        permission_id: str,
        directory: str,
        response: str,
    ) -> bool:
        result = await self._request(
            "POST",
            f"/session/{quote(session_id, safe='')}/permissions/"
            f"{quote(permission_id, safe='')}",
            directory=directory,
            body={"response": response},
        )
        return bool(result)

    async def global_events(self, stop: asyncio.Event) -> AsyncIterator[dict[str, Any]]:
        """Yield global events, reconnecting until stop is set."""
        delay = 1.0
        while not stop.is_set():
            try:
                timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=None)
                async with self.session.get(
                    f"{self.base_url}/global/event",
                    headers={"Accept": "text/event-stream"},
                    timeout=timeout,
                ) as response:
                    if response.status >= 400:
                        raw = await response.text()
                        raise OpenCodeError(
                            f"OpenCode event stream returned HTTP {response.status}: "
                            f"{_error_detail(raw)}"
                        )
                    delay = 1.0
                    data_lines: list[str] = []
                    async for raw_line in response.content:
                        if stop.is_set():
                            return
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if not line:
                            if data_lines:
                                raw_data = "\n".join(data_lines)
                                data_lines.clear()
                                try:
                                    event = json.loads(raw_data)
                                except json.JSONDecodeError:
                                    LOG.warning("Ignoring invalid JSON from OpenCode event stream")
                                    continue
                                if isinstance(event, dict):
                                    yield event
                            continue
                        if line.startswith("data:"):
                            data_lines.append(line[5:].lstrip())
                    raise OpenCodeError("OpenCode event stream ended")
            except asyncio.CancelledError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, OpenCodeError) as exc:
                if stop.is_set():
                    return
                LOG.warning("OpenCode event stream disconnected: %s; retrying in %.0fs", exc, delay)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                except TimeoutError:
                    pass
                delay = min(delay * 2, 30.0)


def _error_detail(raw: str) -> str:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw.strip()[:300] or "request failed"
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict) and data.get("message"):
            return str(data["message"])[:300]
        if payload.get("message"):
            return str(payload["message"])[:300]
        if payload.get("name"):
            return str(payload["name"])[:300]
    return "request failed"
