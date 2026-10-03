"""Semantic stop sets and value watches over bounded execution.

Live suspension does not exist in the current runtime, so `break` and `watch`
are targeted-observation operations rather than interactive debugger controls:

- `break` resolves a semantic target (function, operation, or source line) to
  an exact operation set through the compiler-owned source map, then records
  with selected capture so the resulting witness carries only the targeted
  observations plus its normal verdict. Against an existing witness it
  resolves without executing anything.
- `watch` resolves a value binding (or identity) to runtime value
  observations plus the native origin chain, reusing the provenance contract.

Both refuse to guess: unresolvable targets produce explicit unresolved
documents instead of approximate matches.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .analysis import provenance_query
from .protocol import (
    PROVENANCE_SCHEMA,
    PROTOCOL_VERSION,
    STOP_SET_SCHEMA,
    identity,
    validate_language_source_map,
)
from .runner import build_witness, libraries_for_run, observe_request


class TargetError(RuntimeError):
    """A semantic target could not be resolved or recorded."""


class NoSourceMap(TargetError):
    """The program legitimately has no compiler source map (a manifest)."""


def fetch_source_map(
    *,
    mncs_path: Path,
    program_path: Path,
    request_path: Path,
    cwd: Path,
    timeout_seconds: float,
    library_paths: list[Path] | None = None,
) -> dict[str, Any]:
    """Fetch the compiler-owned source map with a capture-free observation."""

    libraries = libraries_for_run(library_paths, None)
    environment = dict(os.environ)
    if libraries:
        environment["MNCS_LIBRARY_PATH"] = os.pathsep.join(os.fspath(path) for path in libraries)
    else:
        environment.pop("MNCS_LIBRARY_PATH", None)
    observation, _ = observe_request(
        mncs_path=mncs_path,
        program_path=program_path,
        request_path=request_path,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        capture_policy="none",
        max_events=8,
        max_values=8,
        max_value_bytes=256,
        environment=environment,
    )
    document = observation.json
    if observation.timed_out:
        raise TargetError("correspondence fetch timed out")
    if not isinstance(document, dict) or not isinstance(document.get("execution"), dict):
        raise TargetError("correspondence fetch returned no execution document")
    source_map = document.get("source_map")
    if not isinstance(source_map, dict):
        raise NoSourceMap(
            "program has no compiler source map; semantic targets need an mncs "
            "source program, while manifests accept only explicit --operation ids"
        )
    errors = validate_language_source_map(source_map)
    if errors:
        raise TargetError("compiler source map failed membrane validation: " + "; ".join(errors))
    return source_map


def _source_map_functions(source_map: dict[str, Any]) -> list[dict[str, Any]]:
    functions = source_map.get("functions")
    if not isinstance(functions, list):
        return []
    return [item for item in functions if isinstance(item, dict) and isinstance(item.get("identity"), str)]


def _source_map_operations(source_map: dict[str, Any]) -> list[dict[str, Any]]:
    operations = source_map.get("operations")
    if not isinstance(operations, list):
        return []
    return [item for item in operations if isinstance(item, dict) and isinstance(item.get("identity"), str)]


def _operation_entry(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "identity": operation.get("identity"),
        "function_identity": operation.get("function_identity"),
        "block_identity": operation.get("block_identity"),
        "source_span": operation.get("source_span"),
        "synthetic": bool(operation.get("synthetic", True)),
    }


def resolve_function(source_map: dict[str, Any], name: str) -> dict[str, Any]:
    """Resolve a function name to its exact operation set."""

    matches = [
        item for item in _source_map_functions(source_map)
        if item.get("name") == name or item.get("identity") == name
    ]
    if not matches:
        return {"status": "unresolved", "operations": [], "note": f"no function named {name!r} in the source map"}
    if len(matches) > 1:
        return {
            "status": "ambiguous",
            "operations": [],
            "candidates": [item.get("identity") for item in matches],
            "note": f"{len(matches)} functions match {name!r}; refine with an exact function identity",
        }
    function = matches[0]
    operations = [
        _operation_entry(item)
        for item in _source_map_operations(source_map)
        if item.get("function_identity") == function["identity"]
    ]
    operations.sort(key=lambda item: str(item.get("identity")))
    return {
        "status": "resolved",
        "function": {"identity": function["identity"], "name": function.get("name"), "declaration_span": function.get("declaration_span")},
        "operations": operations,
        "synthetic_count": sum(1 for item in operations if item["synthetic"]),
    }


def resolve_operation(source_map: dict[str, Any], identity_value: str) -> dict[str, Any]:
    """Resolve one exact semantic operation identity."""

    for item in _source_map_operations(source_map):
        if item.get("identity") == identity_value:
            return {"status": "resolved", "operations": [_operation_entry(item)]}
    return {
        "status": "unresolved",
        "operations": [],
        "note": f"operation {identity_value!r} is not in the source map; identities must match exactly",
    }


def resolve_line(source_map: dict[str, Any], line: int) -> dict[str, Any]:
    """Resolve a 1-based source line to every operation spanning it."""

    if line < 1:
        return {"status": "unresolved", "operations": [], "note": "line must be >= 1"}
    matches = []
    for item in _source_map_operations(source_map):
        span = item.get("source_span")
        if isinstance(span, dict) and span.get("line") == line:
            matches.append(_operation_entry(item))
    matches.sort(key=lambda item: str(item.get("identity")))
    if not matches:
        return {"status": "unresolved", "operations": [], "note": f"no mapped operation spans line {line}"}
    return {"status": "resolved", "line": line, "operations": matches}


def _static_source_map(witness: dict[str, Any]) -> dict[str, Any] | None:
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    source = static.get("source") if isinstance(static.get("source"), dict) else {}
    source_map = source.get("source_map")
    if isinstance(source_map, dict) and source_map.get("schema_version"):
        return source_map
    return None


def resolve_witness_target(witness: dict[str, Any], kind: str, value: str) -> dict[str, Any]:
    """Resolve a target against a retained witness without executing."""

    source_map = _static_source_map(witness)
    if source_map is not None:
        if kind == "function":
            return resolve_function(source_map, value)
        if kind == "operation":
            return resolve_operation(source_map, value)
        if kind == "line":
            try:
                line = int(value)
            except ValueError:
                return {"status": "unresolved", "operations": [], "note": f"line must be an integer, got {value!r}"}
            return resolve_line(source_map, line)
        raise TargetError(f"unknown target kind: {kind}")
    # Manifest witnesses carry no compiler map; only observed operation ids
    # from the retained trace are addressable, and only exactly.
    if kind != "operation":
        return {
            "status": "unresolved",
            "operations": [],
            "note": "witness has no compiler source map; only --operation ids observed in its trace are addressable",
        }
    observed = _trace_operations(witness)
    if value in observed:
        return {"status": "observed_only", "operations": [{"identity": value}], "note": "operation observed in trace without static correspondence"}
    return {"status": "unresolved", "operations": [], "note": f"operation {value!r} was not observed in this witness trace"}


def _trace_operations(witness: dict[str, Any]) -> set[str]:
    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    events = trace.get("events") if isinstance(trace.get("events"), list) else []
    return {operation for operation in (_event_operation(event) for event in events) if operation}


def _event_operation(event: Any) -> str | None:
    if not isinstance(event, dict):
        return None
    location = event.get("location")
    runtime = location.get("runtime") if isinstance(location, dict) else None
    operation = runtime.get("operation") if isinstance(runtime, dict) else None
    if isinstance(operation, str):
        return operation
    payload = event.get("payload")
    identity_value = payload.get("operation_identity") if isinstance(payload, dict) else None
    return identity_value if isinstance(identity_value, str) else None


def matched_events(witness: dict[str, Any], operation_ids: set[str]) -> list[str]:
    """Return retained trace event ids produced by the operation set."""

    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    events = trace.get("events") if isinstance(trace.get("events"), list) else []
    matched = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if _event_operation(event) in operation_ids and isinstance(event.get("event_id"), str):
            matched.append(event["event_id"])
    return matched


def build_stop_set(
    *,
    kind: str,
    value: str,
    resolution: dict[str, Any],
    witness_id: str | None = None,
    executions: int = 0,
    capture_policy: str | None = None,
    matched: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the versioned stop-set document for one target."""

    material = {
        "kind": kind,
        "value": value,
        "resolution": resolution,
        "witness_id": witness_id,
        "executions": executions,
        "capture_policy": capture_policy,
        "matched_events": matched or [],
    }
    return {
        "schema_version": STOP_SET_SCHEMA,
        "protocol_version": 1,
        "stop_set_id": identity("stop-set", material),
        "target": {"kind": kind, "value": value},
        "resolution": resolution,
        "witness_id": witness_id,
        "executions": executions,
        "capture_policy": capture_policy,
        "matched_events": matched or [],
        "matched_event_count": len(matched or []),
        "suspension": {
            "supported": False,
            "note": "Stop sets are targeted capture positions over a bounded run, not live suspension points.",
        },
    }


def record_stop_set(
    *,
    mncs_path: Path,
    program_path: Path,
    request_path: Path,
    cwd: Path,
    kind: str,
    value: str,
    timeout_seconds: float = 30.0,
    max_events: int = 512,
    max_values: int = 1024,
    max_value_bytes: int = 4096,
    core_path: Path | None = None,
    library_paths: list[Path] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve a target, record with selected capture, return (witness, stop set)."""

    try:
        source_map = fetch_source_map(
            mncs_path=mncs_path,
            program_path=program_path,
            request_path=request_path,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            library_paths=library_paths,
        )
    except NoSourceMap:
        if kind != "operation":
            raise
        # Manifest programs have no map; the runtime filters the opaque id.
        source_map = {}
        opaque = True
    else:
        opaque = False
    if opaque:
        resolution: dict[str, Any] = {"status": "opaque", "operations": [{"identity": value}], "note": "manifest program: operation id passed to selected capture without static resolution"}
    elif kind == "function":
        resolution = resolve_function(source_map, value)
    elif kind == "operation":
        resolution = resolve_operation(source_map, value)
    elif kind == "line":
        try:
            line = int(value)
        except ValueError:
            raise TargetError(f"line must be an integer, got {value!r}") from None
        resolution = resolve_line(source_map, line)
    else:
        raise TargetError(f"unknown target kind: {kind}")
    if resolution.get("status") not in {"resolved", "opaque"}:
        stop_set = build_stop_set(kind=kind, value=value, resolution=resolution, executions=1)
        raise UnresolvedTarget(stop_set)
    operation_ids = [item["identity"] for item in resolution["operations"]]
    witness = build_witness(
        mncs_path=mncs_path,
        program_path=program_path,
        request_path=request_path,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        capture_policy="selected",
        max_events=max_events,
        max_values=max_values,
        max_value_bytes=max_value_bytes,
        selected_operations=operation_ids,
        core_path=core_path,
        library_paths=library_paths,
    )
    matched = matched_events(witness, set(operation_ids))
    stop_set = build_stop_set(
        kind=kind,
        value=value,
        resolution=resolution,
        witness_id=witness.get("witness_id"),
        executions=2,
        capture_policy="selected",
        matched=matched,
    )
    return witness, stop_set


class UnresolvedTarget(TargetError):
    """An unresolvable target that still carries a stop-set document."""

    def __init__(self, stop_set: dict[str, Any]) -> None:
        self.stop_set = stop_set
        resolution = stop_set.get("resolution", {})
        super().__init__(str(resolution.get("note", "target did not resolve")))


def witness_stop_set(witness: dict[str, Any], kind: str, value: str) -> dict[str, Any]:
    """Resolve a target against a retained witness (no execution)."""

    resolution = resolve_witness_target(witness, kind, value)
    operation_ids = {
        str(item.get("identity"))
        for item in resolution.get("operations", [])
        if isinstance(item, dict) and isinstance(item.get("identity"), str)
    }
    matched = matched_events(witness, operation_ids) if operation_ids else []
    return build_stop_set(
        kind=kind,
        value=value,
        resolution=resolution,
        witness_id=witness.get("witness_id"),
        executions=0,
        capture_policy=(witness.get("runtime", {}) or {}).get("effective_capture_policy"),
        matched=matched,
    )


def _observation_values(witness: dict[str, Any]) -> list[dict[str, Any]]:
    runtime = witness.get("runtime") if isinstance(witness.get("runtime"), dict) else {}
    observation = runtime.get("observation") if isinstance(runtime.get("observation"), dict) else {}
    values = observation.get("values") if isinstance(observation.get("values"), list) else []
    return [item for item in values if isinstance(item, dict)]


def watch_binding(witness: dict[str, Any], binding: str) -> dict[str, Any]:
    """Resolve a value binding to observations plus the native origin chain."""

    candidates = [
        item
        for item in _observation_values(witness)
        if item.get("binding") == binding and isinstance(item.get("identity"), str)
    ]
    if len(candidates) == 1:
        return provenance_query(witness, question=f"watch {binding}", value=candidates[0]["identity"])
    if not candidates:
        claims: list[dict[str, Any]] = [
            {
                "kind": "value_observation",
                "status": "unobserved",
                "binding": binding,
                "confidence": "native_runtime_observation_missing",
                "message": f"binding {binding!r} has no value observation in this witness",
            }
        ]
        completeness: dict[str, Any] = {"status": "complete", "exact": [], "missing": ["value observation for binding"]}
    else:
        summaries = [
            {
                "identity": item.get("identity"),
                "frame": item.get("frame"),
                "version": item.get("version"),
                "operation": item.get("operation"),
            }
            for item in candidates
        ]
        summaries.sort(key=lambda item: str(item.get("identity")))
        claims = [
            {
                "kind": "binding_candidates",
                "status": "ambiguous",
                "binding": binding,
                "candidates": summaries,
                "confidence": "native_runtime_observation",
                "message": f"binding {binding!r} has {len(summaries)} observations; refine with --value <identity>",
            }
        ]
        completeness = {"status": "complete", "exact": ["candidate value identities"], "missing": []}
    material = {"witness_id": witness.get("witness_id"), "question": f"watch {binding}", "claims": claims}
    return {
        "schema_version": PROVENANCE_SCHEMA,
        "protocol_version": 1,
        "provenance_id": identity("provenance", material),
        "witness_id": witness.get("witness_id"),
        "execution_identity": witness.get("execution_identity"),
        "question": f"watch {binding}",
        "target": {"binding": binding},
        "claims": claims,
        "completeness": completeness,
        "limitations": witness.get("limitations", []),
    }


def watch_value(witness: dict[str, Any], value_identity: str) -> dict[str, Any]:
    """Answer a watch for one exact native value identity."""

    return provenance_query(witness, question=f"watch {value_identity}", value=value_identity)
