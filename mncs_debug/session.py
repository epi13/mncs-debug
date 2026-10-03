"""Durable resident debug sessions over immutable witnesses.

A resident session binds one recorded witness to a session directory holding
precomputed indexes and a content-addressed memo of query results. It gives
agents attach/reconnect semantics, warm repeated queries, and clean teardown
without requiring a live suspended process: the witness remains the immutable
evidence, while derived state (indexes, memo entries, statistics) is
explicitly rebuildable.

Layout::

    <root>/
      session.json        # mncs.debug-resident-session/1
      witness.json        # immutable evidence copy
      indexes/
        events.json       # event counts and kind/operation/id lookups
        values.json       # value counts and binding lookups
        operations.json   # static operation correspondence + hit counts
        frames.json       # compact frame ancestry
      memo/
        <sha256>.json     # memoized query results by request identity

Evidence rule: ``witness.json`` is never mutated or "repaired". A digest
mismatch marks the session stale and refuses queries; only derived state is
rebuilt automatically. Closing or wiping a session never touches the witness
the session was opened from.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analysis import (
    compiler_phases,
    diagnostic_loop,
    diagnostic_sufficiency,
    inspect_witness,
    load_witness,
    provenance_query,
    replay_trace,
    trace_slice,
)
from .protocol import (
    PROTOCOL_VERSION,
    RESIDENT_SESSION_SCHEMA as SESSION_SCHEMA,
    identity,
    load_json,
    sha256_bytes,
    sha256_file,
)

MAX_MEMO_ENTRIES = 64
MAX_MEMO_BYTES = 4 * 1024 * 1024
MAX_QUERY_PARAMS_BYTES = 256 * 1024

QUERY_OPERATIONS = ("inspect", "trace", "why", "replay", "sufficiency", "diagnose", "phases")


class SessionError(RuntimeError):
    """The session root is missing, corrupt, stale, or misused."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _session_id(witness_id: str) -> str:
    return identity("resident-session", {"witness_id": witness_id, "mode": "resident"})


def _memo_key(witness_id: str, operation: str, params: dict[str, Any]) -> str:
    return identity("memo", {"witness_id": witness_id, "operation": operation, "params": params})


def _memo_filename(key: str) -> str:
    return key.rsplit(":", 1)[-1] + ".json"


def _event_index(witness: dict[str, Any]) -> dict[str, Any]:
    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    events = trace.get("events") if isinstance(trace.get("events"), list) else []
    by_kind: dict[str, list[int]] = {}
    by_operation: dict[str, list[int]] = {}
    by_id: dict[str, int] = {}
    for position, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        kind = event.get("kind")
        if isinstance(kind, str):
            by_kind.setdefault(kind, []).append(position)
        operation = event.get("operation")
        if isinstance(operation, str):
            by_operation.setdefault(operation, []).append(position)
        event_id = event.get("event_id")
        if isinstance(event_id, str):
            by_id[event_id] = position
    return {
        "count": len(events),
        "truncated": bool(trace.get("truncated", False)),
        "by_kind": {kind: positions for kind, positions in sorted(by_kind.items())},
        "by_operation": by_operation,
        "by_id": by_id,
        "observation_identity": trace.get("observation_identity"),
        "completeness": trace.get("completeness", {}),
    }


def _value_index(witness: dict[str, Any]) -> dict[str, Any]:
    runtime = witness.get("runtime") if isinstance(witness.get("runtime"), dict) else {}
    observation = runtime.get("observation") if isinstance(runtime.get("observation"), dict) else {}
    values = observation.get("values") if isinstance(observation.get("values"), list) else []
    by_binding: dict[str, list[str]] = {}
    for value in values:
        if not isinstance(value, dict):
            continue
        identity_value = value.get("identity")
        binding = value.get("binding")
        if isinstance(identity_value, str) and isinstance(binding, str):
            by_binding.setdefault(binding, []).append(identity_value)
    completeness = observation.get("completeness") if isinstance(observation.get("completeness"), dict) else {}
    return {
        "count": len(values),
        "by_binding": {binding: sorted(identities) for binding, identities in sorted(by_binding.items())},
        "captured_values": completeness.get("captured_values"),
        "dropped_values": completeness.get("dropped_values"),
        "observation_identity": observation.get("identity"),
    }


def _operation_index(witness: dict[str, Any]) -> dict[str, Any]:
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    operations = static.get("operations") if isinstance(static.get("operations"), list) else []
    entries: dict[str, Any] = {}
    for operation in operations:
        if not isinstance(operation, dict) or not isinstance(operation.get("identity"), str):
            continue
        entries[operation["identity"]] = {
            "function_identity": operation.get("function_identity"),
            "block_identity": operation.get("block_identity"),
            "source_span": operation.get("source_span"),
            "synthetic": operation.get("synthetic"),
            "correspondence": operation.get("correspondence"),
            "kind": operation.get("kind"),
        }
    event_index = _event_index(witness)
    hits = event_index.get("by_operation", {})
    for operation_id, entry in entries.items():
        entry["event_count"] = len(hits.get(operation_id, []))
    functions = static.get("functions") if isinstance(static.get("functions"), list) else []
    function_names = {
        item.get("identity"): item.get("name")
        for item in functions
        if isinstance(item, dict) and isinstance(item.get("identity"), str)
    }
    return {
        "count": len(entries),
        "operations": entries,
        "functions": function_names,
        "truncated": bool(static.get("truncated", False)),
    }


def _frame_index(witness: dict[str, Any]) -> dict[str, Any]:
    runtime = witness.get("runtime") if isinstance(witness.get("runtime"), dict) else {}
    observation = runtime.get("observation") if isinstance(runtime.get("observation"), dict) else {}
    frames = observation.get("frames") if isinstance(observation.get("frames"), list) else []
    entries = []
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        entries.append(
            {
                "identity": frame.get("identity"),
                "function": frame.get("function"),
                "parent": frame.get("parent"),
                "call_operation": frame.get("call_operation"),
                "depth": frame.get("depth"),
            }
        )
    return {"count": len(entries), "frames": entries}


def _build_indexes(witness: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "events": _event_index(witness),
        "values": _value_index(witness),
        "operations": _operation_index(witness),
        "frames": _frame_index(witness),
    }


def _index_digest(indexes: dict[str, dict[str, Any]]) -> str:
    material = {name: indexes[name] for name in sorted(indexes)}
    return sha256_bytes(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _read_session_document(root: Path) -> dict[str, Any]:
    path = root / "session.json"
    if not path.is_file():
        raise SessionError(f"no debug session at {root}: session.json is missing")
    try:
        document = load_json(path)
    except ValueError as exc:
        raise SessionError(f"session at {root} is unreadable: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != SESSION_SCHEMA:
        raise SessionError(f"session at {root} is not {SESSION_SCHEMA}")
    return document


def _witness_path(root: Path) -> Path:
    return root / "witness.json"


def _load_session_witness(root: Path, document: dict[str, Any]) -> dict[str, Any]:
    witness = load_witness(_witness_path(root))
    if witness.get("witness_id") != document.get("witness_id"):
        raise SessionError(
            f"session at {root} binds witness {document.get('witness_id')} "
            f"but holds {witness.get('witness_id')}"
        )
    return witness


def _check_freshness(root: Path, document: dict[str, Any]) -> tuple[bool, str | None]:
    """Compare the held evidence against the recorded digest.

    Returns (fresh, observed_digest). A missing witness is stale, never
    silently reopened: evidence must be re-supplied deliberately.
    """

    path = _witness_path(root)
    if not path.is_file():
        return False, None
    try:
        observed = sha256_file(path)
    except OSError:
        return False, None
    return observed == document.get("witness_sha256"), observed


def _read_indexes(root: Path) -> dict[str, dict[str, Any]] | None:
    indexes: dict[str, dict[str, Any]] = {}
    for name in ("events", "values", "operations", "frames"):
        path = root / "indexes" / f"{name}.json"
        if not path.is_file():
            return None
        try:
            value = load_json(path)
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        indexes[name] = value
    return indexes


def _write_indexes(root: Path, indexes: dict[str, dict[str, Any]]) -> None:
    for name, index in indexes.items():
        _atomic_write(root / "indexes" / f"{name}.json", index)


def _memo_dir(root: Path) -> Path:
    return root / "memo"


def _memo_stats(root: Path) -> dict[str, int]:
    directory = _memo_dir(root)
    entries = 0
    total = 0
    if directory.is_dir():
        for path in directory.glob("*.json"):
            try:
                total += path.stat().st_size
                entries += 1
            except OSError:
                continue
    return {"entries": entries, "bytes": total}


def _memo_evict(root: Path) -> int:
    """Enforce memo bounds; returns the number of evicted entries."""

    directory = _memo_dir(root)
    if not directory.is_dir():
        return 0
    candidates = []
    for path in directory.glob("*.json"):
        try:
            stat = path.stat()
        except OSError:
            continue
        candidates.append((stat.st_mtime, stat.st_size, path))
    candidates.sort(key=lambda item: item[0])
    entries = len(candidates)
    total = sum(size for _, size, _ in candidates)
    evicted = 0
    while candidates and (entries > MAX_MEMO_ENTRIES or total > MAX_MEMO_BYTES):
        _, size, path = candidates.pop(0)
        try:
            path.unlink()
        except OSError:
            continue
        entries -= 1
        total -= size
        evicted += 1
    return evicted


def _memo_lookup(root: Path, key: str, witness_id: str) -> dict[str, Any] | None:
    path = _memo_dir(root) / _memo_filename(key)
    if not path.is_file():
        return None
    try:
        envelope = load_json(path)
    except ValueError:
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("memo_key") != key
        or envelope.get("witness_id") != witness_id
        or "result" not in envelope
    ):
        return None
    return envelope


def _memo_store(root: Path, key: str, witness_id: str, operation: str, params: dict[str, Any], result: Any) -> int:
    envelope = {
        "memo_key": key,
        "witness_id": witness_id,
        "operation": operation,
        "params": params,
        "result": result,
    }
    _atomic_write(_memo_dir(root) / _memo_filename(key), envelope)
    return _memo_evict(root)


def open_session(*, witness_path: Path, root: Path, force: bool = False) -> dict[str, Any]:
    """Bind a witness copy to a new resident session directory."""

    witness = load_witness(witness_path)
    root = root.resolve()
    session_path = root / "session.json"
    if session_path.exists() and not force:
        raise SessionError(f"a debug session already exists at {root}; pass force to reopen")
    witness_bytes = witness_path.resolve().read_bytes()
    # Evidence is copied byte-verbatim: the recorded digest covers the exact
    # source bytes, and any re-serialization would mark the session stale.
    target = _witness_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".witness.json.{os.getpid()}.tmp"
    temporary.write_bytes(witness_bytes)
    os.replace(temporary, target)
    indexes = _build_indexes(witness)
    _write_indexes(root, indexes)
    outcome = witness.get("outcome") if isinstance(witness.get("outcome"), dict) else {}
    document = {
        "schema_version": SESSION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "session_id": _session_id(str(witness.get("witness_id"))),
        "state": "open",
        "witness_id": witness.get("witness_id"),
        "witness_sha256": sha256_bytes(witness_bytes),
        "witness_bytes": len(witness_bytes),
        "execution_identity": witness.get("execution_identity"),
        "failure_class": outcome.get("failure_class"),
        "indexes": {name: f"indexes/{name}.json" for name in ("events", "values", "operations", "frames")},
        "index_digest": _index_digest(indexes),
        "memo": {"entries": 0, "bytes": 0, "hits": 0, "misses": 0, "evictions": 0},
        "queries": 0,
        "opened_at": _utcnow(),
        "last_query_at": None,
        "source_path": witness_path.resolve().as_posix(),
        "transport": {
            "kind": "resident_directory",
            "resumable": True,
            "note": "File-backed resident inspection session; attach with the session root.",
        },
    }
    _atomic_write(session_path, document)
    return document


def attach_session(root: Path) -> dict[str, Any]:
    """Validate a session root and report status plus compact orientation.

    Derived indexes are rebuilt automatically when missing or corrupt; the
    held witness is never mutated. A digest mismatch marks the session
    stale and refuses further queries until it is reopened or closed.
    """

    root = root.resolve()
    document = _read_session_document(root)
    if document.get("state") == "closed":
        return {**document, "orientation": None, "indexes_rebuilt": False}
    fresh, observed = _check_freshness(root, document)
    if not fresh:
        document["state"] = "stale"
        document["stale_reason"] = (
            "held witness is missing" if observed is None else "held witness digest changed"
        )
        document["observed_witness_sha256"] = observed
        _atomic_write(root / "session.json", document)
        return {**document, "orientation": None, "indexes_rebuilt": False}
    indexes = _read_indexes(root)
    rebuilt = False
    if indexes is None:
        witness = _load_session_witness(root, document)
        indexes = _build_indexes(witness)
        _write_indexes(root, indexes)
        document["index_digest"] = _index_digest(indexes)
        rebuilt = True
    stats = _memo_stats(root)
    memo = document.get("memo") if isinstance(document.get("memo"), dict) else {}
    memo.update({"entries": stats["entries"], "bytes": stats["bytes"]})
    document["memo"] = memo
    if rebuilt:
        _atomic_write(root / "session.json", document)
    orientation = {
        "witness_id": document.get("witness_id"),
        "execution_identity": document.get("execution_identity"),
        "failure_class": document.get("failure_class"),
        "event_count": indexes["events"].get("count", 0),
        "event_kinds": sorted((indexes["events"].get("by_kind") or {}).keys()),
        "events_truncated": indexes["events"].get("truncated", False),
        "value_count": indexes["values"].get("count", 0),
        "value_bindings": sorted((indexes["values"].get("by_binding") or {}).keys()),
        "operation_count": indexes["operations"].get("count", 0),
        "functions": indexes["operations"].get("functions", {}),
        "frame_count": indexes["frames"].get("count", 0),
        "frames": indexes["frames"].get("frames", []),
    }
    return {**document, "orientation": orientation, "indexes_rebuilt": rebuilt}


def _normalize_params(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    allowed: dict[str, tuple[str, ...]] = {
        "inspect": ("event_id",),
        "trace": ("kind", "operation", "start", "limit"),
        "why": ("question", "value", "operation"),
        "replay": (),
        "sufficiency": ("inspection", "evidence_artifacts", "supplemental_operation"),
        "diagnose": ("inspection", "evidence_artifacts", "max_steps"),
        "phases": ("kind",),
    }
    fields = allowed.get(operation)
    if fields is None:
        raise SessionError(f"unknown session query operation: {operation}")
    normalized = {key: params[key] for key in fields if key in params and params[key] is not None}
    for key in ("start", "limit", "max_steps"):
        if key in normalized:
            try:
                normalized[key] = int(normalized[key])
            except (TypeError, ValueError):
                raise SessionError(f"session query param {key!r} must be an integer") from None
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_QUERY_PARAMS_BYTES:
        raise SessionError(
            f"session query params exceed {MAX_QUERY_PARAMS_BYTES} bytes; narrow the artifacts"
        )
    return normalized


def _execute_query(
    witness: dict[str, Any],
    operation: str,
    params: dict[str, Any],
    *,
    mncs_path: Path | None,
    core_path: Path | None,
) -> Any:
    if operation == "inspect":
        return inspect_witness(witness, event_id=params.get("event_id"))
    if operation == "trace":
        return trace_slice(
            witness,
            kind=params.get("kind"),
            operation=params.get("operation"),
            start=params.get("start"),
            limit=int(params.get("limit", 256)),
        )
    if operation == "why":
        return provenance_query(
            witness,
            question=params.get("question"),
            value=params.get("value"),
            operation=params.get("operation"),
        )
    if operation == "replay":
        return replay_trace(witness)
    if mncs_path is None:
        raise SessionError(f"session query {operation!r} needs an mncs runtime; pass --mncs")
    if operation == "phases":
        return compiler_phases(witness, mncs_path=mncs_path, kind=str(params.get("kind", "all")))
    if operation == "sufficiency":
        return diagnostic_sufficiency(
            witness,
            params.get("inspection"),
            mncs_path=mncs_path,
            core_path=core_path,
            evidence_artifacts=params.get("evidence_artifacts") or (),
            supplemental_operation=params.get("supplemental_operation"),
        )
    if operation == "diagnose":
        return diagnostic_loop(
            witness,
            mncs_path=mncs_path,
            core_path=core_path,
            max_steps=int(params.get("max_steps", 4)),
            initial_inspection=params.get("inspection"),
            initial_evidence_artifacts=params.get("evidence_artifacts") or (),
        )
    raise SessionError(f"unknown session query operation: {operation}")


def query_session(
    root: Path,
    operation: str,
    params: dict[str, Any] | None = None,
    *,
    mncs_path: Path | None = None,
    core_path: Path | None = None,
) -> dict[str, Any]:
    """Answer one query against a resident session, memoizing the result."""

    if operation not in QUERY_OPERATIONS:
        raise SessionError(
            f"unsupported session query {operation!r}; "
            "reexecute and minimize produce new witnesses, so run them against "
            "the session witness with the top-level commands and open a new session"
        )
    root = root.resolve()
    attached = attach_session(root)
    if attached.get("state") != "open":
        raise SessionError(
            f"session at {root} is {attached.get('state')}: "
            f"{attached.get('stale_reason', 'closed sessions answer no queries')}"
        )
    normalized = _normalize_params(operation, params or {})
    witness_id = str(attached["witness_id"])
    key = _memo_key(witness_id, operation, normalized)
    cached = _memo_lookup(root, key, witness_id)
    document = _read_session_document(root)
    memo = document.get("memo") if isinstance(document.get("memo"), dict) else {}
    if cached is not None:
        memo["hits"] = int(memo.get("hits", 0)) + 1
        document["memo"] = memo
        document["queries"] = int(document.get("queries", 0)) + 1
        document["last_query_at"] = _utcnow()
        _atomic_write(root / "session.json", document)
        return {"memo_hit": True, "memo_key": key, "result": cached["result"]}
    witness = _load_session_witness(root, document)
    result = _execute_query(witness, operation, normalized, mncs_path=mncs_path, core_path=core_path)
    evicted = _memo_store(root, key, witness_id, operation, normalized, result)
    stats = _memo_stats(root)
    memo.update({"entries": stats["entries"], "bytes": stats["bytes"]})
    memo["misses"] = int(memo.get("misses", 0)) + 1
    memo["evictions"] = int(memo.get("evictions", 0)) + evicted
    document["memo"] = memo
    document["queries"] = int(document.get("queries", 0)) + 1
    document["last_query_at"] = _utcnow()
    _atomic_write(root / "session.json", document)
    return {"memo_hit": False, "memo_key": key, "result": result}


def close_session(root: Path, *, wipe: bool = False) -> dict[str, Any]:
    """Close a session, optionally removing the session directory."""

    root = root.resolve()
    document = _read_session_document(root)
    document["state"] = "closed"
    document["closed_at"] = _utcnow()
    if wipe:
        import shutil

        _atomic_write(root / "session.json", document)
        shutil.rmtree(root, ignore_errors=False)
        return {**document, "wiped": True}
    _atomic_write(root / "session.json", document)
    return {**document, "wiped": False}
