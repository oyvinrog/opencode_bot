import asyncio
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

import pytest

from matrix_opencode_bot import checkers
from matrix_opencode_bot.checkers import run_command_checker, run_state_checker, workspace_revision


class _FakeReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)

    async def read(self, _size: int) -> bytes:
        await asyncio.sleep(0)
        return self.chunks.pop(0) if self.chunks else b""


class _FakeProcess:
    def __init__(self, chunks: list[bytes], returncode: int = 0) -> None:
        self.stdout = _FakeReader(chunks)
        self.returncode = returncode
        self.killed = False

    async def wait(self) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True


def _mark_command_executed(args: tuple[str, ...]) -> None:
    marker_destination = args.index(checkers._EXEC_MARKER_DESTINATION)
    marker_source = Path(args[marker_destination - 1])
    separator = args.index("--")
    token = args[separator + 5]
    marker_source.write_text(token)


def test_exec_wrapper_marks_then_executes_requested_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "marker"
    marker.touch()
    requested = ["requested-tool", "literal arg", "$(not-a-shell)"]
    captured: dict[str, Any] = {}

    class ExecReached(Exception):
        pass

    def execvpe(executable: str, argv: list[str], environment: dict[str, str]) -> None:
        captured["executable"] = executable
        captured["argv"] = argv
        captured["environment"] = environment
        raise ExecReached

    monkeypatch.setattr(os, "execvpe", execvpe)
    monkeypatch.setattr(
        sys, "argv", ["-c", str(marker), "controller-token", *requested]
    )

    with pytest.raises(ExecReached):
        exec(checkers._EXEC_WRAPPER, {})

    assert marker.read_text() == "controller-token"
    assert captured["executable"] == "requested-tool"
    assert captured["argv"] == requested
    assert captured["environment"] is os.environ


async def test_command_checker_uses_network_namespace_and_argv_without_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "input.txt").write_text("safe")
    captured: dict[str, Any] = {}

    async def create_process(*args: str, **kwargs: Any) -> _FakeProcess:
        captured["args"] = args
        captured["kwargs"] = kwargs
        _mark_command_executed(args)
        return _FakeProcess([b"literal argument"])

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    hostile_argument = "$(touch should-not-exist); `id`"
    result = await run_command_checker(
        workspace,
        argv=["printf", "%s", hostile_argument],
        stdout_contains="literal",
    )

    assert result.status == "pass"
    command = list(captured["args"])
    assert "--unshare-net" in command
    assert "--disable-userns" in command
    assert "--clearenv" in command
    assert ["--ro-bind", "/", "/"] != command[:3]
    separator = command.index("--")
    assert command[separator + 6 :] == ["printf", "%s", hostile_argument]
    assert captured["kwargs"]["env"] == checkers._checker_environment()
    assert not (workspace / "should-not-exist").exists()


async def test_command_checker_fails_closed_when_isolation_does_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    async def create_process(*_args: str, **_kwargs: Any) -> _FakeProcess:
        # Model-visible output cannot forge the controller-owned execution marker.
        return _FakeProcess([b'{"child-pid": 999}\n'], returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    result = await run_command_checker(workspace, argv=["true"])

    assert result.status == "unverifiable"
    assert "isolation could not be established" in result.summary
    assert result.exit_code is None


async def test_command_checker_bounds_output_but_searches_the_full_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    async def create_process(*args: str, **_kwargs: Any) -> _FakeProcess:
        _mark_command_executed(args)
        return _FakeProcess([b"x" * 20_000, b"NEE", b"DLE"])

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    result = await run_command_checker(
        workspace, argv=["producer"], stdout_contains="NEEDLE"
    )

    assert result.status == "pass"
    assert len(result.raw_output.encode("utf-8")) < checkers.MAX_CHECK_OUTPUT + 100
    assert "output truncated" in result.raw_output


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"argv": []}, "argv"),
        ({"argv": ["true"], "cwd": "../escape"}, "inside"),
        ({"argv": ["true"], "timeout_seconds": 0}, "timeout"),
        ({"argv": ["true"], "stdout_contains": ""}, "output"),
        ({"argv": ["true"], "expected_exit": True}, "exit"),
    ],
)
async def test_command_checker_rejects_invalid_specs(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    result = await run_command_checker(tmp_path, **kwargs)
    assert result.status == "unverifiable"
    assert message in result.summary.lower()


async def test_command_checker_rejects_workspace_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("secret")
    (workspace / "escape").symlink_to(outside)

    result = await run_command_checker(workspace, argv=["true"])
    assert result.status == "unverifiable"
    assert "symlink escapes" in result.summary


async def test_command_checker_accepts_system_symlink_in_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "python").symlink_to("/usr/bin/python3")

    async def create_process(*args: str, **_kwargs: Any) -> _FakeProcess:
        _mark_command_executed(args)
        return _FakeProcess([])

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    result = await run_command_checker(workspace, argv=["true"])
    assert result.status == "pass"


async def test_command_checker_rejects_special_files_without_opening_them(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    os.mkfifo(workspace / "blocking-fifo")

    result = await asyncio.wait_for(
        run_command_checker(workspace, argv=["true"]), timeout=2
    )
    assert result.status == "unverifiable"
    assert "special file" in result.summary


async def test_real_command_checker_never_mutates_source_and_fails_closed_if_unsupported(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.txt"
    source.write_text("original")
    sibling_secret = tmp_path / "secret.txt"
    sibling_secret.write_text("hidden")
    script = (
        "from pathlib import Path; "
        "Path('source.txt').write_text('changed'); "
        "Path('created.txt').write_text('temporary'); "
        f"print(Path({str(sibling_secret)!r}).exists())"
    )

    result = await run_command_checker(
        workspace,
        argv=["python3", "-c", script],
        timeout_seconds=30,
        stdout_contains="False",
    )

    assert result.status in {"pass", "unverifiable"}
    if result.status == "unverifiable":
        assert "isolation" in result.summary.lower()
    assert source.read_text() == "original"
    assert not (workspace / "created.txt").exists()
    assert sibling_secret.read_text() == "hidden"


async def test_workspace_revision_tracks_content_permissions_and_git_state(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "script.sh"
    file_path.write_text("echo ok\n")
    git_file = tmp_path / ".git" / "index"
    git_file.parent.mkdir()
    git_file.write_bytes(b"one")
    original = await workspace_revision(tmp_path)

    file_path.chmod(0o755)
    permission_change = await workspace_revision(tmp_path)
    assert permission_change != original

    git_file.write_bytes(b"two")
    git_change = await workspace_revision(tmp_path)
    assert git_change != permission_change

    file_path.write_text("echo changed\n")
    assert await workspace_revision(tmp_path) != git_change


async def test_path_state_checker_is_read_only_and_rejects_escapes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "result.json"
    target.write_text('{"ok": true}')
    target.chmod(0o640)
    before = (target.read_bytes(), target.stat().st_mode)

    result = await run_state_checker(
        workspace,
        {"path": "result.json", "predicate": "json_equals", "expected": {"ok": True}},
    )
    traversal = await run_state_checker(
        workspace, {"path": "../result.json", "predicate": "exists"}
    )
    outside = tmp_path / "outside"
    outside.write_text("secret")
    (workspace / "link").symlink_to(outside)
    symlink = await run_state_checker(
        workspace, {"path": "link", "predicate": "contains", "expected": "secret"}
    )

    assert result.status == "pass"
    assert traversal.status == "unverifiable"
    assert symlink.status == "unverifiable"
    assert (target.read_bytes(), target.stat().st_mode) == before


@pytest.mark.parametrize(
    "spec",
    [
        {"path": "x", "url": "https://example.test"},
        {"path": "x", "predicate": "contains", "expected": 3},
        {"url": "file:///tmp/x"},
        {"url": "https://user:secret@example.test"},
        {"url": "https://example.test", "predicate": "delete"},
    ],
)
async def test_state_checker_rejects_non_read_only_or_ambiguous_specs(
    tmp_path: Path, spec: dict[str, Any]
) -> None:
    result = await run_state_checker(tmp_path, spec)
    assert result.status == "unverifiable"


async def test_url_state_checker_issues_only_credential_free_get(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, size: int) -> bytes:
            captured["read_size"] = size
            return b'{"ready": true}'

    class Opener:
        def open(self, req: request.Request, timeout: int) -> Response:
            captured["method"] = req.get_method()
            captured["data"] = req.data
            captured["url"] = req.full_url
            captured["timeout"] = timeout
            return Response()

    def build_opener(*handlers: Any) -> Opener:
        captured["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(request, "build_opener", build_opener)
    result = await run_state_checker(
        tmp_path,
        {
            "url": "https://example.test/status",
            "predicate": "json_equals",
            "expected": {"ready": True},
        },
        timeout_seconds=12,
    )

    assert result.status == "pass"
    assert captured["method"] == "GET"
    assert captured["data"] is None
    assert captured["timeout"] == 12
    assert captured["read_size"] == checkers.MAX_STATE_READ_BYTES + 1
    assert any(isinstance(item, request.ProxyHandler) for item in captured["handlers"])
    proxy_handler = next(
        item for item in captured["handlers"] if isinstance(item, request.ProxyHandler)
    )
    assert proxy_handler.proxies == {}


def test_redirect_handler_rejects_non_http_and_credentials() -> None:
    handler = checkers._SafeRedirectHandler()
    original = request.Request("https://example.test/start")

    with pytest.raises(error.URLError):
        handler.redirect_request(original, None, 302, "found", {}, "file:///tmp/secret")
    with pytest.raises(error.URLError):
        handler.redirect_request(
            original, None, 302, "found", {}, "https://user:secret@example.test/next"
        )


async def test_state_checker_rejects_oversized_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, _size: int) -> bytes:
            return b"x" * (checkers.MAX_STATE_READ_BYTES + 1)

    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> Response:
            return Response()

    monkeypatch.setattr(request, "build_opener", lambda *_args: Opener())
    result = await run_state_checker(
        tmp_path, {"url": "https://example.test", "predicate": "status", "expected": 200}
    )
    assert result.status == "unverifiable"
    assert "exceeds" in result.summary
