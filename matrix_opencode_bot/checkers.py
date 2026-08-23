"""Controller-owned pursuit checkers.

The language model may propose these checks, but it cannot create their results.  Command
checks run without a shell inside a disposable workspace copy.  State checks perform a
small, explicit set of read-only predicates.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import stat
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_CHECK_OUTPUT = 12_000
MAX_STATE_READ_BYTES = 2_000_000
MAX_COMMAND_ARGS = 256
MAX_COMMAND_ARG_BYTES = 32_768
MAX_CONTAINS_BYTES = 4_096
MAX_SNAPSHOT_BYTES = 2_000_000_000
MAX_SNAPSHOT_ENTRIES = 200_000

_CHECKER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_EXEC_MARKER_DESTINATION = "/openbot-exec-status"
_EXEC_WRAPPER = """\
import os
import sys

marker, token, *command = sys.argv[1:]
descriptor = os.open(marker, os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC)
try:
    os.write(descriptor, token.encode("ascii"))
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.execvpe(command[0], command, os.environ)
"""


@dataclass(frozen=True)
class CheckerExecution:
    """Raw result produced by controller code, never by the worker model."""

    status: str
    summary: str
    source: str
    raw_output: str = ""
    exit_code: int | None = None


async def workspace_revision(directory: str | Path) -> str:
    """Return a content fingerprint used to invalidate observations after mutations."""

    return await _run_blocking(_workspace_revision_sync, Path(directory).resolve())


async def run_command_checker(
    directory: str | Path,
    *,
    argv: list[str],
    cwd: str = ".",
    timeout_seconds: int = 300,
    expected_exit: int = 0,
    stdout_contains: str | None = None,
) -> CheckerExecution:
    """Run an argv-only command in a disposable copy isolated by bubblewrap.

    Refusing to run when bubblewrap is unavailable is intentional: silently falling back to
    an unrestricted process would make the advertised isolation false.
    """

    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > MAX_COMMAND_ARGS
        or not all(isinstance(item, str) and item and "\0" not in item for item in argv)
    ):
        return CheckerExecution("unverifiable", "Invalid command argv", "command")
    try:
        argv_bytes = sum(len(item.encode("utf-8")) for item in argv)
        cwd.encode("utf-8") if isinstance(cwd, str) else b""
    except UnicodeEncodeError:
        return CheckerExecution("unverifiable", "Command arguments must be valid UTF-8", "command")
    if argv_bytes > MAX_COMMAND_ARG_BYTES:
        return CheckerExecution("unverifiable", "Command argv is too large", "command")
    if not isinstance(cwd, str) or "\0" in cwd:
        return CheckerExecution("unverifiable", "Invalid checker cwd", "command")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
        return CheckerExecution("unverifiable", "Command timeout must be an integer", "command")
    if timeout_seconds <= 0 or timeout_seconds > 1800:
        return CheckerExecution(
            "unverifiable", "Command timeout must be between 1 and 1800 seconds", "command"
        )
    if isinstance(expected_exit, bool) or not isinstance(expected_exit, int):
        return CheckerExecution("unverifiable", "Expected exit must be an integer", "command")
    if stdout_contains is not None:
        try:
            expected_output_bytes = (
                len(stdout_contains.encode("utf-8")) if isinstance(stdout_contains, str) else 0
            )
        except UnicodeEncodeError:
            expected_output_bytes = MAX_CONTAINS_BYTES + 1
        if (
            not isinstance(stdout_contains, str)
            or not stdout_contains
            or expected_output_bytes > MAX_CONTAINS_BYTES
            or "\0" in stdout_contains
        ):
            return CheckerExecution(
                "unverifiable", "Expected output must be a non-empty bounded string", "command"
            )
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return CheckerExecution(
            "unverifiable",
            "Command checker isolation is unavailable because bubblewrap is not installed",
            "command",
        )

    root = Path(directory).resolve()
    relative_cwd = Path(cwd)
    if relative_cwd.is_absolute() or ".." in relative_cwd.parts:
        return CheckerExecution("unverifiable", "Checker cwd must stay inside the workspace", cwd)

    # Use an explicit system temporary directory rather than TMPDIR.  A caller-controlled
    # TMPDIR inside the workspace could otherwise make copytree recursively copy its own
    # destination.
    with tempfile.TemporaryDirectory(prefix="openbot-check-", dir="/tmp") as temporary:
        snapshot = Path(temporary) / "workspace"
        try:
            await _run_blocking(_create_workspace_snapshot, root, snapshot)
        except (OSError, ValueError) as exc:
            return CheckerExecution(
                "unverifiable", f"Could not create checker snapshot: {exc}", str(root)
            )
        check_cwd = (snapshot / relative_cwd).resolve()
        if not check_cwd.is_relative_to(snapshot) or not check_cwd.is_dir():
            return CheckerExecution("unverifiable", "Checker cwd does not exist", cwd)
        try:
            workspace_mounts = _workspace_mount_arguments(root, snapshot)
        except ValueError as exc:
            return CheckerExecution("unverifiable", str(exc), str(root))

        # Only system executables/libraries and the disposable snapshot are mounted.  User
        # homes, credentials, sibling workspaces, and runtime sockets are absent.  Network
        # isolation is mandatory: if the kernel refuses --unshare-net, the controller reports
        # "unverifiable" and never falls back to a host-network process.  We also deliberately
        # avoid a controller shell, so metacharacters in argv remain ordinary argument bytes.
        execution_marker = Path(temporary) / "exec-status"
        execution_marker.write_bytes(b"")
        execution_marker.chmod(0o600)
        execution_token = secrets.token_hex(32)
        command = [
            bwrap,
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-cgroup-try",
            "--disable-userns",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/sbin",
            "/sbin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--ro-bind-try",
            "/nix/store",
            "/nix/store",
            "--dir",
            "/etc",
            "--ro-bind-try",
            "/etc/alternatives",
            "/etc/alternatives",
            "--ro-bind-try",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--ro-bind-try",
            "/etc/passwd",
            "/etc/passwd",
            "--ro-bind-try",
            "/etc/group",
            "/etc/group",
            "--ro-bind-try",
            "/etc/nsswitch.conf",
            "/etc/nsswitch.conf",
            "--ro-bind-try",
            "/etc/localtime",
            "/etc/localtime",
            "--ro-bind-try",
            "/etc/ssl/certs",
            "/etc/ssl/certs",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--bind",
            str(execution_marker),
            _EXEC_MARKER_DESTINATION,
            *workspace_mounts,
            "--chdir",
            str(root / relative_cwd),
            "--clearenv",
            *_environment_arguments(_checker_environment()),
            "--",
            "/usr/bin/python3",
            "-c",
            _EXEC_WRAPPER,
            _EXEC_MARKER_DESTINATION,
            execution_token,
            *argv,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=_checker_environment(),
            )
            try:
                output_bytes, output_truncated, contains_found = await asyncio.wait_for(
                    _capture_process_output(process, stdout_contains), timeout=timeout_seconds
                )
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                with contextlib.suppress(Exception):
                    await process.wait()
                if not _execution_marker_seen(execution_marker, execution_token):
                    return CheckerExecution(
                        "unverifiable",
                        "Command checker isolation could not be established before timeout",
                        _display_command(argv),
                    )
                return CheckerExecution(
                    "fail",
                    f"Command timed out after {timeout_seconds}s",
                    _display_command(argv),
                    exit_code=None,
                )
            except asyncio.CancelledError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                with contextlib.suppress(Exception):
                    await process.wait()
                raise
            except Exception as exc:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                with contextlib.suppress(Exception):
                    await process.wait()
                return CheckerExecution(
                    "unverifiable",
                    f"Command checker output could not be captured: {exc}",
                    _display_command(argv),
                )
        except (OSError, ValueError) as exc:
            return CheckerExecution(
                "unverifiable", f"Could not launch command checker: {exc}", _display_command(argv)
            )

        if not _execution_marker_seen(execution_marker, execution_token):
            output = _decode_output(output_bytes, output_truncated)
            return CheckerExecution(
                "unverifiable",
                "Command checker isolation could not be established",
                _display_command(argv),
                raw_output=output,
                exit_code=None,
            )

        output = _decode_output(output_bytes, output_truncated)
        passed = process.returncode == expected_exit
        if stdout_contains is not None:
            passed = passed and contains_found
        expectation = f"exit {expected_exit}"
        if stdout_contains is not None:
            expectation += f" and output containing {stdout_contains!r}"
        summary = (
            f"Command satisfied {expectation}"
            if passed
            else f"Command did not satisfy {expectation}; actual exit was {process.returncode}"
        )
        return CheckerExecution(
            "pass" if passed else "fail",
            summary,
            _display_command(argv),
            raw_output=output,
            exit_code=process.returncode,
        )


async def run_state_checker(
    directory: str | Path,
    spec: dict[str, Any],
    *,
    timeout_seconds: int = 30,
) -> CheckerExecution:
    """Evaluate a local-path or HTTP GET predicate without changing external state."""

    if not isinstance(spec, dict):
        return CheckerExecution("unverifiable", "State checker spec must be an object", "state")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
        return CheckerExecution("unverifiable", "State timeout must be an integer", "state")
    if timeout_seconds <= 0 or timeout_seconds > 60:
        return CheckerExecution(
            "unverifiable", "State timeout must be between 1 and 60 seconds", "state"
        )
    has_path = isinstance(spec.get("path"), str)
    has_url = isinstance(spec.get("url"), str)
    if has_path and has_url:
        return CheckerExecution(
            "unverifiable", "State checker cannot combine path and URL sources", "state"
        )
    if has_path:
        return await _run_blocking(_check_path_state, Path(directory).resolve(), spec)
    if has_url:
        return await _run_blocking(_check_url_state, spec, timeout_seconds)
    return CheckerExecution(
        "unverifiable", "State checker requires either a relative path or a URL", "state"
    )


def _check_path_state(root: Path, spec: dict[str, Any]) -> CheckerExecution:
    relative = Path(str(spec["path"]))
    if relative.is_absolute() or ".." in relative.parts:
        return CheckerExecution(
            "unverifiable", "State path must stay inside the workspace", str(relative)
        )
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        return CheckerExecution(
            "unverifiable", "State path resolves outside the workspace", str(relative)
        )
    predicate = str(spec.get("predicate") or "exists")
    expected = spec.get("expected")
    if predicate in {"contains", "equals"}:
        try:
            expected_bytes = len(expected.encode("utf-8")) if isinstance(expected, str) else 0
        except UnicodeEncodeError:
            expected_bytes = MAX_CONTAINS_BYTES + 1
        if not isinstance(expected, str) or expected_bytes > MAX_CONTAINS_BYTES:
            return CheckerExecution(
                "unverifiable",
                f"Expected value for {predicate} must be a bounded string",
                str(relative),
            )
    try:
        if predicate == "exists":
            passed = target.exists()
        elif predicate == "not_exists":
            passed = not target.exists()
        elif predicate == "file":
            passed = target.is_file()
        elif predicate == "directory":
            passed = target.is_dir()
        elif predicate == "nonempty":
            passed = target.is_file() and target.stat().st_size > 0
        elif predicate in {"contains", "equals", "json_equals"}:
            if not target.is_file():
                passed = False
            elif target.stat().st_size > MAX_STATE_READ_BYTES:
                return CheckerExecution(
                    "unverifiable",
                    f"State file exceeds {MAX_STATE_READ_BYTES} bytes",
                    str(relative),
                )
            else:
                text = target.read_text(encoding="utf-8")
                if predicate == "contains":
                    passed = isinstance(expected, str) and expected in text
                elif predicate == "equals":
                    passed = isinstance(expected, str) and text == expected
                else:
                    passed = json.loads(text) == expected
        else:
            return CheckerExecution(
                "unverifiable", f"Unsupported state predicate: {predicate}", str(relative)
            )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return CheckerExecution(
            "fail", f"State predicate could not be evaluated: {exc}", str(relative)
        )
    return CheckerExecution(
        "pass" if passed else "fail",
        f"Path predicate {predicate} {'passed' if passed else 'failed'}",
        str(relative),
    )


def _check_url_state(spec: dict[str, Any], timeout_seconds: int) -> CheckerExecution:
    url = str(spec["url"])
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return CheckerExecution("unverifiable", f"Invalid state URL: {exc}", url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return CheckerExecution("unverifiable", "State URL must use HTTP or HTTPS", url)
    if parsed.username is not None or parsed.password is not None:
        return CheckerExecution("unverifiable", "State URL must not contain credentials", url)
    predicate = str(spec.get("predicate") or "status")
    expected = spec.get("expected", 200)
    if predicate == "status" and (
        isinstance(expected, bool) or not isinstance(expected, (int, str))
    ):
        return CheckerExecution("unverifiable", "Expected status must be an integer", url)
    if predicate == "contains" and not isinstance(expected, str):
        return CheckerExecution(
            "unverifiable", "Expected value for contains must be a string", url
        )
    if predicate not in {"status", "contains", "json_equals"}:
        return CheckerExecution(
            "unverifiable", f"Unsupported URL predicate: {predicate}", url
        )
    request = urllib.request.Request(url, headers={"User-Agent": "openbot-state-checker/1"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SafeRedirectHandler())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            body_bytes = response.read(MAX_STATE_READ_BYTES + 1)
            status_code = int(response.status)
    except urllib.error.HTTPError as response:
        with response:
            body_bytes = response.read(MAX_STATE_READ_BYTES + 1)
            status_code = int(response.code)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return CheckerExecution("fail", f"State URL could not be read: {exc}", url)
    if len(body_bytes) > MAX_STATE_READ_BYTES:
        return CheckerExecution(
            "unverifiable", f"State response exceeds {MAX_STATE_READ_BYTES} bytes", url
        )
    body = body_bytes.decode("utf-8", errors="replace")
    if predicate == "status":
        try:
            passed = status_code == int(expected)
        except (TypeError, ValueError):
            return CheckerExecution("unverifiable", "Expected status must be an integer", url)
    elif predicate == "contains":
        passed = isinstance(expected, str) and expected in body
    elif predicate == "json_equals":
        try:
            passed = json.loads(body) == expected
        except json.JSONDecodeError:
            passed = False
    output = body[:MAX_CHECK_OUTPUT]
    return CheckerExecution(
        "pass" if passed else "fail",
        f"URL predicate {predicate} {'passed' if passed else 'failed'} (HTTP {status_code})",
        url,
        raw_output=output,
        exit_code=status_code,
    )


def _workspace_revision_sync(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.is_dir():
        raise ValueError(f"Workspace does not exist: {root}")
    root_info = root.lstat()
    digest.update(b"root\0")
    digest.update(str(stat.S_IFMT(root_info.st_mode)).encode())
    digest.update(b"\0")
    digest.update(str(stat.S_IMODE(root_info.st_mode)).encode())
    digest.update(b"\0")
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(str(stat.S_IFMT(info.st_mode)).encode())
        digest.update(b"\0")
        digest.update(str(stat.S_IMODE(info.st_mode)).encode())
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        elif path.is_file():
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _checker_environment() -> dict[str, str]:
    return {
        "PATH": _CHECKER_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "CI": "1",
    }


def _display_command(argv: list[str]) -> str:
    # This string is display/provenance only and is never evaluated by a shell.
    return "argv:" + json.dumps(argv, ensure_ascii=False)


def _create_workspace_snapshot(root: Path, snapshot: Path) -> None:
    """Copy a bounded, ordinary-file workspace without following symlinks."""

    if not root.is_dir():
        raise ValueError(f"Workspace does not exist: {root}")
    entries = 0
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_SNAPSHOT_ENTRIES:
                    raise ValueError(
                        f"workspace exceeds {MAX_SNAPSHOT_ENTRIES} snapshot entries"
                    )
                info = entry.stat(follow_symlinks=False)
                mode = info.st_mode
                entry_path = Path(entry.path)
                if stat.S_ISDIR(mode):
                    pending.append(entry_path)
                elif stat.S_ISREG(mode):
                    total_bytes += info.st_size
                    if total_bytes > MAX_SNAPSHOT_BYTES:
                        raise ValueError(
                            f"workspace exceeds {MAX_SNAPSHOT_BYTES} snapshot bytes"
                        )
                elif stat.S_ISLNK(mode):
                    target = (entry_path.parent / os.readlink(entry_path)).resolve()
                    safe_system_target = any(
                        target == prefix or target.is_relative_to(prefix)
                        for prefix in (
                            Path("/usr"),
                            Path("/bin"),
                            Path("/sbin"),
                            Path("/lib"),
                            Path("/lib64"),
                            Path("/nix/store"),
                        )
                    )
                    if not target.is_relative_to(root) and not safe_system_target:
                        raise ValueError(
                            f"workspace symlink escapes snapshot: {entry_path.relative_to(root)}"
                        )
                else:
                    raise ValueError(
                        f"workspace contains unsupported special file: {entry_path.relative_to(root)}"
                    )

    free_bytes = shutil.disk_usage("/tmp").free
    if total_bytes > free_bytes * 3 // 4:
        raise ValueError("workspace snapshot would consume too much temporary storage")

    def copy_regular_file(source: str, destination: str) -> str:
        info = os.lstat(source)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"snapshot source changed type while copying: {source}")
        if info.st_size > MAX_SNAPSHOT_BYTES:
            raise OSError(f"snapshot source is too large: {source}")
        return shutil.copy2(source, destination, follow_symlinks=False)

    shutil.copytree(
        root,
        snapshot,
        symlinks=True,
        ignore_dangling_symlinks=False,
        copy_function=copy_regular_file,
    )


def _workspace_mount_arguments(root: Path, snapshot: Path) -> list[str]:
    protected = (
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc"),
        Path("/dev"),
        Path("/proc"),
        Path("/nix/store"),
    )
    if root == Path("/") or any(root == path or root.is_relative_to(path) for path in protected):
        raise ValueError("Workspace path overlaps a protected checker system mount")
    arguments: list[str] = []
    for parent in reversed(root.parents):
        if parent in {Path("/"), Path("/tmp")}:
            continue
        arguments.extend(("--dir", str(parent)))
    arguments.extend(("--bind", str(snapshot), str(root)))
    return arguments


def _environment_arguments(environment: dict[str, str]) -> list[str]:
    arguments: list[str] = []
    for key, value in sorted(environment.items()):
        arguments.extend(("--setenv", key, value))
    return arguments


async def _capture_process_output(
    process: asyncio.subprocess.Process, stdout_contains: str | None
) -> tuple[bytes, bool, bool]:
    """Drain output with bounded memory while searching across chunk boundaries."""

    if process.stdout is None:
        await process.wait()
        return b"", False, stdout_contains is None
    needle = stdout_contains.encode("utf-8") if stdout_contains is not None else None
    found = needle is None
    tail = b""
    captured = bytearray()
    truncated = False
    while True:
        chunk = await process.stdout.read(64 * 1024)
        if not chunk:
            break
        remaining = MAX_CHECK_OUTPUT - len(captured)
        if remaining > 0:
            captured.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
        if needle is not None and not found:
            combined = tail + chunk
            found = needle in combined
            tail = combined[-(len(needle) - 1) :] if len(needle) > 1 else b""
    await process.wait()
    return bytes(captured), truncated, found


def _decode_output(output: bytes, truncated: bool) -> str:
    text = output.decode("utf-8", errors="replace")
    if truncated:
        text += "\n… output truncated …"
    return text


def _execution_marker_seen(path: Path, token: str) -> bool:
    try:
        return secrets.compare_digest(path.read_text(encoding="ascii"), token)
    except (OSError, UnicodeError):
        return False


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep a read-only state request on credential-free HTTP(S) redirects."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        redirected = urllib.parse.urljoin(req.full_url, newurl)
        try:
            parsed = urllib.parse.urlsplit(redirected)
        except ValueError as exc:
            raise urllib.error.URLError(f"invalid redirect URL: {exc}") from exc
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise urllib.error.URLError("redirect left credential-free HTTP(S)")
        return super().redirect_request(req, fp, code, msg, headers, redirected)


async def _run_blocking(function: Any, *args: Any) -> Any:
    """Run bounded blocking checker work without tying up the controller event loop.

    A private daemon thread avoids sharing the application's default executor with session
    streaming and shutdown.  Delivery is controller-owned and cancellation-safe.
    """

    future: concurrent.futures.Future[Any] = concurrent.futures.Future()

    def worker() -> None:
        try:
            value = function(*args)
        except BaseException as exc:
            future.set_exception(exc)
        else:
            future.set_result(value)

    thread = threading.Thread(target=worker, name="openbot-checker", daemon=True)
    thread.start()
    # Polling avoids coupling checker completion to the application's executor or its
    # cross-thread wakeup descriptor; the 10 ms bound is negligible beside external checks.
    while not future.done():
        await asyncio.sleep(0.01)
    return future.result()
