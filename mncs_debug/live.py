"""Durable live debug sessions over the canonical VM.

A live session is a resident handle over a currently running/stopped VM
execution, served by one ``mncs-vm debug --serve`` daemon. It complements
the evidence sessions in :mod:`mncs_debug.session` (resident views over
completed immutable witnesses) without changing their meaning:

- evidence session: ``mncs.debug-resident-session/1`` over ``witness.json``;
- live session: ``mncs.debug-live-session/1`` over a VM daemon socket.

Layout::

    <root>/
      session.json   # mncs.debug-live-session/1 (handle + current token)
      stops.json     # appended stop records (bounded)
      finish.json    # immutable terminal evidence (when finished)
      daemon.log     # daemon stderr (one startup line in practice)
      debug.sock     # daemon socket (live only)

Evidence rule: ``stops.json`` entries and ``finish.json`` are append-only /
write-once. The session handle (token, stop sequence, state) is mutable
because it tracks the live execution; terminal evidence never is. Closing a
session shuts the daemon down; removing it never touches anything outside
the session directory.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .protocol import (
    LIVE_SESSION_SCHEMA as SESSION_SCHEMA,
    PROTOCOL_VERSION,
    identity,
    load_json,
    sha256_file,
)

VM_SCHEMA_VERSION = "mncs.vm.debug/1"
VM_CLI_SCHEMA_VERSION = "mncs.vm.debug-cli/1"
MAX_STOP_HISTORY = 4096
MAX_SOCKET_LINE_BYTES = 64 * 1024 * 1024


class LiveError(RuntimeError):
    """A live-session operation failed (typed daemon errors included)."""


def resolve_mncs_vm(value: str | None = None) -> Path:
    """Resolve the ``mncs-vm`` driver binary like ``resolve_mncs``."""

    candidates: list[Path] = []
    if value:
        candidates.append(Path(value))
    env_value = os.environ.get("MNCS_VM")
    if env_value:
        candidates.append(Path(env_value))
    # Prefer an optimized driver: release compiles ~15x faster than debug
    # with byte-identical artifacts. The serving binary is recorded in
    # session.json, so the choice stays evidenced, never silent.
    candidates.append(Path(__file__).resolve().parents[2] / "mncs-vm/target/release/mncs-vm")
    candidates.append(Path(__file__).resolve().parents[2] / "mncs-vm/target/debug/mncs-vm")
    which = shutil.which("mncs-vm")
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    raise LiveError("no executable mncs-vm driver found; pass --mncs-vm or set MNCS_VM")


def default_sessions_root() -> Path:
    """Conventional root for live sessions (overridable per command)."""

    override = os.environ.get("MNCS_DEBUG_LIVE_ROOT")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / "mncs-debug" / "live"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _session_id(material: dict[str, Any]) -> str:
    return identity("live-session", material)


class LiveClient:
    """One short JSONL conversation with a debug daemon.

    One connection per call, closed before returning: the daemon
    serves one connection at a time, so clients must never hold a
    connection open across operations. Connection setup is ~50 us;
    persistence belongs in the client process (see :class:`LivePipe`),
    not on the wire.
    """

    def __init__(self, socket_path: Path, timeout_seconds: float = 30.0) -> None:
        self._socket_path = socket_path
        self._timeout = timeout_seconds
        self._next_id = 0

    def _connect(self) -> socket.socket:
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(self._timeout)
            connection.connect(os.fspath(self._socket_path))
        except OSError as exc:
            raise LiveError(f"cannot reach debug daemon at {self._socket_path}: {exc}") from exc
        return connection

    def call(self, op: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send one request and return the ``result`` or raise ``LiveError``."""

        self._next_id += 1
        request = {"id": self._next_id, "op": op, "params": params or {}}
        connection = self._connect()
        try:
            payload = (json.dumps(request) + "\n").encode("utf-8")
            connection.sendall(payload)
            chunks: list[bytes] = []
            total = 0
            while True:
                try:
                    data = connection.recv(65536)
                except socket.timeout as exc:
                    raise LiveError(f"debug daemon timed out on op {op!r}") from exc
                if not data:
                    break
                total += len(data)
                if total > MAX_SOCKET_LINE_BYTES:
                    raise LiveError(f"debug daemon response for op {op!r} exceeds bounds")
                chunks.append(data)
                if b"\n" in data:
                    break
            line = b"".join(chunks).decode("utf-8").strip()
        except OSError as exc:
            raise LiveError(f"debug daemon I/O failed on op {op!r}: {exc}") from exc
        finally:
            connection.close()
        if not line:
            raise LiveError(f"debug daemon closed without answering op {op!r}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LiveError(f"debug daemon answered op {op!r} with invalid JSON: {exc}") from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            error = response.get("error") if isinstance(response, dict) else None
            code = error.get("code") if isinstance(error, dict) else "unknown"
            message = error.get("message") if isinstance(error, dict) else line[:512]
            raise LiveError(f"debug daemon refused op {op!r} [{code}]: {message}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise LiveError(f"debug daemon answered op {op!r} without a result object")
        return result


def _wait_for_socket(socket_path: Path, timeout_seconds: float = 10.0) -> None:
    deadline = time.time() + timeout_seconds
    last: OSError | None = None
    while time.time() < deadline:
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(1.0)
            probe.connect(os.fspath(socket_path))
            probe.close()
            return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise LiveError(f"debug daemon did not serve {socket_path} in time: {last}")


def _read_session_document(root: Path) -> dict[str, Any]:
    document = load_json(root / "session.json")
    if not isinstance(document, dict) or document.get("schema_version") != SESSION_SCHEMA:
        raise LiveError(f"session at {root} is not {SESSION_SCHEMA}")
    return document


def _read_stops(root: Path) -> list[dict[str, Any]]:
    path = root / "stops.json"
    if not path.exists():
        return []
    value = load_json(path)
    if not isinstance(value, list):
        raise LiveError(f"session stops at {path} are not a list")
    return [entry for entry in value if isinstance(entry, dict)]


def start_session(
    *,
    root: Path,
    vm_path: Path,
    target: dict[str, Any],
    arguments: list[Any],
    envelope: dict[str, Any] | None = None,
    providers: dict[str, Any] | None = None,
    artifact_path: Path | None = None,
    artifact: dict[str, Any] | None = None,
    compile_path: Path | None = None,
    capture: str = "none",
    max_events: int = 256,
    max_values: int = 128,
    max_value_bytes: int = 4096,
    selected_operations: list[str] | None = None,
    stops: list[dict[str, Any]] | None = None,
    stop_on_abnormal_terminal: bool = True,
    timeout_seconds: float = 120.0,
) -> dict[str, Any]:
    """Spawn a debug daemon and start one live execution.

    Returns the session handle document. When the execution finishes
    immediately the daemon is retired and terminal evidence is written;
    otherwise the handle tracks the stopped execution.
    """

    sources = [artifact_path is not None, artifact is not None, compile_path is not None]
    if sum(sources) != 1:
        raise LiveError("start needs exactly one of artifact_path, artifact, or compile_path")
    root = root.resolve()
    if (root / "session.json").exists():
        raise LiveError(f"session directory {root} is already a live session")
    root.mkdir(parents=True, exist_ok=True)
    socket_path = root / "debug.sock"
    if socket_path.exists():
        try:
            socket_path.unlink()
        except OSError as exc:
            raise LiveError(f"cannot clear stale socket {socket_path}: {exc}") from exc
    log_path = root / "daemon.log"
    with log_path.open("wb") as log:
        try:
            process = subprocess.Popen(
                [os.fspath(vm_path), "debug", "--serve", os.fspath(socket_path)],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            raise LiveError(f"cannot spawn debug daemon: {exc}") from exc
    try:
        _wait_for_socket(socket_path)
    except LiveError:
        process.poll()
        raise
    client = LiveClient(socket_path, timeout_seconds=timeout_seconds)
    try:
        capabilities = client.call("capabilities")
    except LiveError:
        _shutdown_daemon(socket_path, process)
        raise
    if capabilities.get("contract") != VM_SCHEMA_VERSION:
        _shutdown_daemon(socket_path, process)
        raise LiveError(
            f"daemon speaks {capabilities.get('contract')}, want {VM_SCHEMA_VERSION}"
        )
    params: dict[str, Any] = {
        "target": target,
        "arguments": arguments,
        "debug": {
            "policy": {
                "schema_version": "mncs.execution-observation-policy/1",
                "capture": capture,
                "max_events": max_events,
                "max_values": max_values,
                "max_value_bytes": max_value_bytes,
                "include_frames": True,
                "include_effects": True,
                "selected_operations": selected_operations or [],
            },
            "stops": stops or [],
            "stop_on_abnormal_terminal": stop_on_abnormal_terminal,
        },
    }
    if envelope is not None:
        params["envelope"] = envelope
    if providers is not None:
        params["providers"] = providers
    if artifact_path is not None:
        params["artifact_path"] = os.fspath(artifact_path.resolve())
    if artifact is not None:
        params["artifact"] = artifact
    if compile_path is not None:
        params["compile"] = os.fspath(compile_path.resolve())
    try:
        result = client.call("start", params)
    except LiveError:
        _shutdown_daemon(socket_path, process)
        raise
    session_id = _session_id(
        {
            "root": root.as_posix(),
            "target": target,
            "created_at": _utcnow(),
            "daemon_pid": process.pid,
        }
    )
    if result.get("event") == "finished":
        document = {
            "schema_version": SESSION_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "session_id": session_id,
            "state": "finished",
            "socket": socket_path.as_posix(),
            "daemon_pid": None,
            "vm_binary": os.fspath(vm_path),
            "execution": (result.get("record") or {}).get("artifact_id"),
            "artifact": (result.get("record") or {}).get("artifact_id"),
            "callable": target,
            "stop_sequence": 0,
            "continuation_token": None,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
            "finish": result.get("outcome"),
        }
        _atomic_write(root / "session.json", document)
        _atomic_write(root / "finish.json", _finish_evidence(result, []))
        _shutdown_daemon(socket_path, process)
        return {"session": document, "event": result}
    if result.get("event") != "stopped" or not isinstance(result.get("stop"), dict):
        _shutdown_daemon(socket_path, process)
        raise LiveError(f"daemon start answered without a stop or finish: {result!r}"[:512])
    stop = result["stop"]
    document = {
        "schema_version": SESSION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id,
        "state": "live",
        "socket": socket_path.as_posix(),
        "daemon_pid": process.pid,
        "vm_binary": os.fspath(vm_path),
        "execution": stop.get("execution"),
        "artifact": stop.get("artifact"),
        "callable": target,
        "stop_sequence": stop.get("stop_sequence"),
        "continuation_token": stop.get("continuation_token"),
        "created_at": _utcnow(),
        "updated_at": _utcnow(),
        "finish": None,
    }
    _atomic_write(root / "session.json", document)
    _atomic_write(root / "stops.json", [stop])
    return {"session": document, "event": result}


def _finish_evidence(result: dict[str, Any], stops: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "mncs.debug-live-evidence/1",
        "protocol_version": PROTOCOL_VERSION,
        "outcome": result.get("outcome"),
        "record": result.get("record"),
        "stream": result.get("stream"),
        "stops": stops,
        "finalized_at": _utcnow(),
    }


def _shutdown_daemon(socket_path: Path, process: subprocess.Popen[bytes] | None = None) -> None:
    try:
        client = LiveClient(socket_path, timeout_seconds=5.0)
        client.call("shutdown")
    except LiveError:
        pass
    if process is not None:
        try:
            process.wait(timeout=5.0)
        except (OSError, subprocess.SubprocessError):
            pass


def _live_document(root: Path) -> dict[str, Any]:
    document = _read_session_document(root)
    if document.get("state") != "live":
        raise LiveError(f"session at {root} is {document.get('state')}, not live")
    token = document.get("continuation_token")
    if not isinstance(token, str) or not token:
        raise LiveError(f"session at {root} has no continuation token")
    return document


def _drive(root: Path, op: str, timeout_seconds: float) -> dict[str, Any]:
    document = _live_document(root)
    client = LiveClient(Path(str(document["socket"])), timeout_seconds=timeout_seconds)
    return _drive_with(root, document, client, op)


def _drive_with(
    root: Path, document: dict[str, Any], client: LiveClient, op: str
) -> dict[str, Any]:
    result = client.call(op, {"token": document.get("continuation_token")})
    return _absorb_event(root, document, result, client)


def _absorb_event(
    root: Path, document: dict[str, Any], result: dict[str, Any], client: LiveClient
) -> dict[str, Any]:
    if result.get("event") == "stopped" and isinstance(result.get("stop"), dict):
        stop = result["stop"]
        document["stop_sequence"] = stop.get("stop_sequence")
        document["continuation_token"] = stop.get("continuation_token")
        document["updated_at"] = _utcnow()
        _atomic_write(root / "session.json", document)
        stops = _read_stops(root)
        stops.append(stop)
        _atomic_write(root / "stops.json", stops[-MAX_STOP_HISTORY:])
        return {"session": document, "event": result}
    if result.get("event") == "finished":
        stops = _read_stops(root)
        document["state"] = "finished"
        document["stop_sequence"] = document.get("stop_sequence")
        document["continuation_token"] = None
        document["daemon_pid"] = None
        document["updated_at"] = _utcnow()
        document["finish"] = result.get("outcome")
        _atomic_write(root / "session.json", document)
        _atomic_write(root / "finish.json", _finish_evidence(result, stops))
        try:
            client.call("shutdown")
        except LiveError:
            pass
        return {"session": document, "event": result}
    raise LiveError(f"daemon answered without a stop or finish: {result!r}"[:512])


def resume_session(root: Path, timeout_seconds: float = 120.0) -> dict[str, Any]:
    """Resume the stopped execution until the next stop or finish."""

    return _drive(root, "resume", timeout_seconds)


def continue_session(root: Path, timeout_seconds: float = 120.0) -> dict[str, Any]:
    """Run until another bound stop, failure, completion, or bound."""

    return _drive(root, "continue", timeout_seconds)


def step_session(root: Path, mode: str, timeout_seconds: float = 120.0) -> dict[str, Any]:
    """Advance one semantic step: ``in`` (into calls), ``over``, ``out``."""

    if mode not in ("in", "over", "out"):
        raise LiveError(f"unknown step mode {mode!r}; want in, over, or out")
    return _drive(root, f"step_{mode}", timeout_seconds)


def inspect_session(
    root: Path,
    view: str = "stack",
    *,
    max_frames: int = 16,
    max_values: int = 64,
    max_value_bytes: int = 4096,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Read-only inspection: stack, observation, effects, or stops."""

    if view == "stops":
        return {"stops": _read_stops(root)}
    document = _read_session_document(root)
    if document.get("state") == "finished":
        finish_path = root / "finish.json"
        if not finish_path.exists():
            raise LiveError(f"finished session at {root} has no finish.json")
        finish = load_json(finish_path)
        if view == "observation":
            return {"observation": (finish or {}).get("stream")}
        if view == "effects":
            return {"effects": ((finish or {}).get("record") or {}).get("effects")}
        raise LiveError(f"finished sessions answer observation/effects/stops, not {view!r}")
    if document.get("state") != "live":
        raise LiveError(f"session at {root} is {document.get('state')}")
    return _inspect_live(
        document,
        LiveClient(Path(str(document["socket"])), timeout_seconds=timeout_seconds),
        view,
        max_frames=max_frames,
        max_values=max_values,
        max_value_bytes=max_value_bytes,
    )


def _inspect_live(
    document: dict[str, Any],
    client: LiveClient,
    view: str,
    *,
    max_frames: int,
    max_values: int,
    max_value_bytes: int,
) -> dict[str, Any]:
    return client.call(
        "inspect",
        {
            "token": document.get("continuation_token"),
            "view": view,
            "max_frames": max_frames,
            "max_values": max_values,
            "max_value_bytes": max_value_bytes,
        },
    )


def bind_stop(root: Path, target: dict[str, Any], stop_id: str | None = None) -> dict[str, Any]:
    """Bind a stop condition on the live execution."""

    document = _live_document(root)
    client = LiveClient(Path(str(document["socket"])))
    return _bind_with(document, client, target, stop_id)


def _bind_with(
    document: dict[str, Any], client: LiveClient, target: dict[str, Any], stop_id: str | None
) -> dict[str, Any]:
    params: dict[str, Any] = {"token": document.get("continuation_token"), "target": target}
    if stop_id is not None:
        params["id"] = stop_id
    return client.call("bind_stop", params)


def clear_stop(root: Path, stop_id: str) -> dict[str, Any]:
    """Clear one bound stop condition by id."""

    document = _live_document(root)
    client = LiveClient(Path(str(document["socket"])))
    return _clear_with(document, client, stop_id)


def _clear_with(document: dict[str, Any], client: LiveClient, stop_id: str) -> dict[str, Any]:
    return client.call("clear_stop", {"token": document.get("continuation_token"), "id": stop_id})


def terminate_session(root: Path, timeout_seconds: float = 60.0) -> dict[str, Any]:
    """Terminate the live execution and finalize terminal evidence."""

    document = _live_document(root)
    client = LiveClient(Path(str(document["socket"])), timeout_seconds=timeout_seconds)
    return _terminate_with(root, document, client)


def _terminate_with(
    root: Path, document: dict[str, Any], client: LiveClient
) -> dict[str, Any]:
    result = client.call("terminate", {"token": document.get("continuation_token")})
    if result.get("event") != "finished":
        raise LiveError(f"terminate did not finish the execution: {result!r}"[:512])
    return _absorb_event(root, document, result, client)


def attach_session(root: Path, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """Validate a live session and report status plus orientation.

    Never drives the execution. Stale sessions (socket gone, daemon
    dead, token desynchronized) are reported with an explicit reason;
    use :func:`close_session` to retire them.
    """

    root = root.resolve()
    try:
        document = _read_session_document(root)
    except (LiveError, OSError, ValueError) as exc:
        return {"root": root.as_posix(), "attached": False, "stale": True, "stale_reason": str(exc)[:512]}
    state = document.get("state")
    stops = []
    try:
        stops = _read_stops(root)
    except (LiveError, OSError, ValueError):
        pass
    orientation: dict[str, Any] = {
        "root": root.as_posix(),
        "attached": True,
        "stale": False,
        "state": state,
        "session_id": document.get("session_id"),
        "execution": document.get("execution"),
        "artifact": document.get("artifact"),
        "stop_sequence": document.get("stop_sequence"),
        "stop_count": len(stops),
        "finish": document.get("finish"),
    }
    if state == "finished":
        finish_path = root / "finish.json"
        orientation["finish_evidence"] = finish_path.exists()
        if finish_path.exists():
            try:
                orientation["finish_sha256"] = sha256_file(finish_path)
            except OSError:
                pass
        return orientation
    if state == "closed":
        orientation["stale"] = True
        orientation["stale_reason"] = "session is closed"
        return orientation
    if state != "live":
        orientation["stale"] = True
        orientation["stale_reason"] = f"unknown session state {state!r}"
        return orientation
    socket_path = Path(str(document.get("socket", "")))
    if not socket_path.exists():
        orientation["stale"] = True
        orientation["stale_reason"] = f"daemon socket {socket_path} is gone"
        return orientation
    return _attach_live_status(
        document, stops, orientation, LiveClient(socket_path, timeout_seconds=timeout_seconds)
    )


def _attach_live_status(
    document: dict[str, Any],
    stops: list[dict[str, Any]],
    orientation: dict[str, Any],
    client: LiveClient,
) -> dict[str, Any]:
    try:
        capabilities = client.call("capabilities")
    except LiveError as exc:
        orientation["stale"] = True
        orientation["stale_reason"] = f"daemon does not answer: {exc}"
        return orientation
    if capabilities.get("contract") != VM_SCHEMA_VERSION:
        orientation["stale"] = True
        orientation["stale_reason"] = f"daemon speaks {capabilities.get('contract')}"
        return orientation
    try:
        stack = client.call(
            "inspect",
            {"token": document.get("continuation_token"), "view": "stack",
             "max_frames": 1, "max_values": 0, "max_value_bytes": 1},
        )
    except LiveError as exc:
        orientation["stale"] = True
        orientation["stale_reason"] = f"continuation token desynchronized: {exc}"
        return orientation
    frames = (stack.get("stack") or {}).get("frames") or []
    if frames:
        orientation["current_function"] = frames[0].get("function")
        orientation["current_block"] = frames[0].get("block")
        orientation["current_depth"] = frames[0].get("depth")
    orientation["stop_count"] = len(stops)
    return orientation


def close_session(root: Path, *, remove: bool = False) -> dict[str, Any]:
    """Shut the daemon down; optionally remove the session directory.

    Live executions are terminated first so terminal evidence is
    finalized. Stale sessions (daemon already gone) close cleanly:
    this is the evidenced repair path for dead-daemon sessions.
    """

    root = root.resolve()
    try:
        document = _read_session_document(root)
    except (LiveError, OSError, ValueError) as exc:
        # No handle to drive: without --remove this is a plain error;
        # with --remove it still retires whatever the directory holds.
        if not remove:
            raise LiveError(f"cannot close session at {root}: {exc}") from exc
        return _wipe_session_dir(root, {"state": "unknown", "close_note": f"no session handle: {exc}"})
    terminated: dict[str, Any] | None = None
    if document.get("state") == "live":
        try:
            terminated = terminate_session(root)
            document = terminated["session"]
        except LiveError as exc:
            # The daemon is unreachable: mark closed with the evidence
            # we have rather than failing the repair.
            document["state"] = "closed"
            document["continuation_token"] = None
            document["daemon_pid"] = None
            document["updated_at"] = _utcnow()
            document["close_note"] = f"daemon unreachable at close: {exc}"
            _atomic_write(root / "session.json", document)
    else:
        document["state"] = "closed"
        document["continuation_token"] = None
        document["updated_at"] = _utcnow()
        _atomic_write(root / "session.json", document)
    # Belt and suspenders: a lingering daemon is asked to exit.
    socket_path = Path(str(document.get("socket", root / "debug.sock")))
    _shutdown_daemon(socket_path)
    if remove:
        return _wipe_session_dir(root, document, terminated=terminated is not None)
    return {"session": document, "terminated": terminated is not None, "removed": False}


class LivePipe:
    """Many session operations over one client process.

    One-shot CLI commands pay full process startup per query; a pipe
    holds the session root in memory and re-reads the small session
    handle per op, so interleaved one-shot commands stay safe (their
    token wins; ours then fails closed). Each op still uses one short
    daemon connection — the daemon serves one connection at a time,
    so holding one open would starve every other client.
    Bookkeeping (session.json, stops.json, finish.json) is identical
    to the one-shot path: the same ``_drive_with``/``_absorb_event``
    helpers run in both.
    """

    def __init__(self, root: Path, timeout_seconds: float = 120.0) -> None:
        self._root = root.resolve()
        self._timeout = timeout_seconds
        self._client: LiveClient | None = None

    def close(self) -> None:
        """Forget cached client state (the session stays resident)."""

        self._client = None

    def _client_for(self, document: dict[str, Any]) -> LiveClient:
        socket_path = Path(str(document.get("socket", "")))
        if self._client is None or self._client._socket_path != socket_path:
            self._client = LiveClient(socket_path, timeout_seconds=self._timeout)
        return self._client

    def dispatch(self, op: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one session operation; raise ``LiveError`` on failure."""

        root = self._root
        if op in ("resume", "continue", "step_in", "step_over", "step_out"):
            document = _live_document(root)
            return _drive_with(root, document, self._client_for(document), op)
        if op == "terminate":
            document = _live_document(root)
            return _terminate_with(root, document, self._client_for(document))
        if op == "inspect":
            return self._inspect(params)
        if op == "bind_stop":
            document = _live_document(root)
            target = params.get("target")
            if not isinstance(target, dict):
                raise LiveError("bind_stop needs a target object")
            stop_id = params.get("id")
            if stop_id is not None and not isinstance(stop_id, str):
                raise LiveError("bind_stop id must be a string")
            return _bind_with(document, self._client_for(document), target, stop_id)
        if op == "clear_stop":
            document = _live_document(root)
            stop_id = params.get("id")
            if not isinstance(stop_id, str) or not stop_id:
                raise LiveError("clear_stop needs a string id")
            return _clear_with(document, self._client_for(document), stop_id)
        if op == "status":
            return self._status()
        if op == "close":
            result = close_session(root, remove=bool(params.get("remove", False)))
            self.close()
            return result
        raise LiveError(
            "unknown pipe op "
            f"{op!r}; want resume, continue, step_in, step_over, step_out,"
            " terminate, inspect, bind_stop, clear_stop, status, close"
        )

    def _inspect(self, params: dict[str, Any]) -> dict[str, Any]:
        views = params.get("views")
        if views is None:
            views = [params.get("view", "stack")]
        if (
            not isinstance(views, list)
            or not views
            or any(not isinstance(view, str) for view in views)
        ):
            raise LiveError("inspect needs a view string or a non-empty views list")
        for view in views:
            if view not in ("stack", "observation", "effects", "stops"):
                raise LiveError(f"unknown inspect view {view!r}")
        try:
            bounds = {
                "max_frames": int(params.get("max_frames", 16)),
                "max_values": int(params.get("max_values", 64)),
                "max_value_bytes": int(params.get("max_value_bytes", 4096)),
            }
        except (TypeError, ValueError) as exc:
            raise LiveError(f"inspect bounds must be integers: {exc}") from exc
        if len(views) == 1:
            return self._one_view(views[0], bounds)
        # Batched read-only views: one request, no state transition.
        return {"views": {view: self._one_view(view, bounds) for view in views}}

    def _one_view(self, view: str, bounds: dict[str, int]) -> dict[str, Any]:
        root = self._root
        if view == "stops":
            return {"stops": _read_stops(root)}
        document = _read_session_document(root)
        if document.get("state") == "finished":
            finish_path = root / "finish.json"
            if not finish_path.exists():
                raise LiveError(f"finished session at {root} has no finish.json")
            finish = load_json(finish_path)
            if view == "observation":
                return {"observation": (finish or {}).get("stream")}
            if view == "effects":
                return {"effects": ((finish or {}).get("record") or {}).get("effects")}
            raise LiveError(f"finished sessions answer observation/effects/stops, not {view!r}")
        if document.get("state") != "live":
            raise LiveError(f"session at {root} is {document.get('state')}")
        return _inspect_live(document, self._client_for(document), view, **bounds)

    def _status(self) -> dict[str, Any]:
        root = self._root
        try:
            document = _read_session_document(root)
        except (LiveError, OSError, ValueError) as exc:
            return {
                "root": root.as_posix(),
                "attached": False,
                "stale": True,
                "stale_reason": str(exc)[:512],
            }
        state = document.get("state")
        try:
            stops = _read_stops(root)
        except (LiveError, OSError, ValueError):
            stops = []
        orientation: dict[str, Any] = {
            "root": root.as_posix(),
            "attached": True,
            "stale": False,
            "state": state,
            "session_id": document.get("session_id"),
            "execution": document.get("execution"),
            "artifact": document.get("artifact"),
            "stop_sequence": document.get("stop_sequence"),
            "stop_count": len(stops),
            "finish": document.get("finish"),
        }
        if state == "finished":
            finish_path = root / "finish.json"
            orientation["finish_evidence"] = finish_path.exists()
            if finish_path.exists():
                try:
                    orientation["finish_sha256"] = sha256_file(finish_path)
                except OSError:
                    pass
            return orientation
        if state == "closed":
            orientation["stale"] = True
            orientation["stale_reason"] = "session is closed"
            return orientation
        if state != "live":
            orientation["stale"] = True
            orientation["stale_reason"] = f"unknown session state {state!r}"
            return orientation
        socket_path = Path(str(document.get("socket", "")))
        if not socket_path.exists():
            orientation["stale"] = True
            orientation["stale_reason"] = f"daemon socket {socket_path} is gone"
            return orientation
        return _attach_live_status(document, stops, orientation, self._client_for(document))


def run_pipe(root: Path, infile: Any, outfile: Any, timeout_seconds: float = 120.0) -> int:
    """Serve JSONL session operations until stdin closes.

    Request lines: ``{"id": <any>, "op": <name>, "params": {...}}``.
    Response lines: ``{"id": <same>, "ok": true, "result": {...}}`` or
    ``{"id": <same>, "ok": false, "error": {"message": ...}}``.
    Blank lines are ignored. The session stays resident on exit.
    """

    pipe = LivePipe(root, timeout_seconds=timeout_seconds)
    try:
        for raw in infile:
            line = raw.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                outfile.write(json.dumps({"id": None, "ok": False, "error": {"message": f"request is not JSON: {exc}"}}) + "\n")
                outfile.flush()
                continue
            request_id = request.get("id") if isinstance(request, dict) else None
            op = request.get("op") if isinstance(request, dict) else None
            params = request.get("params") if isinstance(request, dict) else None
            if not isinstance(op, str) or not op:
                outfile.write(json.dumps({"id": request_id, "ok": False, "error": {"message": "request needs a string op"}}) + "\n")
                outfile.flush()
                continue
            if params is None:
                params = {}
            if not isinstance(params, dict):
                outfile.write(json.dumps({"id": request_id, "ok": False, "error": {"message": "request params must be an object"}}) + "\n")
                outfile.flush()
                continue
            try:
                result = pipe.dispatch(op, params)
            except LiveError as exc:
                outfile.write(json.dumps({"id": request_id, "ok": False, "error": {"message": str(exc)[:2048]}}) + "\n")
            except (OSError, ValueError) as exc:
                outfile.write(json.dumps({"id": request_id, "ok": False, "error": {"message": str(exc)[:2048]}}) + "\n")
            else:
                outfile.write(json.dumps({"id": request_id, "ok": True, "result": result}) + "\n")
            outfile.flush()
    finally:
        pipe.close()
    return 0


def _wipe_session_dir(
    root: Path, document: dict[str, Any], *, terminated: bool = False
) -> dict[str, Any]:
    removed = False
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return {"session": document, "terminated": terminated, "removed": removed}
    for child in entries:
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                # Files, symlinks, and stale socket inodes all unlink.
                child.unlink()
        except OSError:
            pass
    try:
        root.rmdir()
        removed = True
    except OSError:
        pass
    return {"session": document, "terminated": terminated, "removed": removed}
