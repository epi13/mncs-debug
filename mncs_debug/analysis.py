"""Query, replay, provenance, and conservative minimization operations."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .protocol import (
    INSPECTION_SCHEMA,
    PROVENANCE_SCHEMA,
    PROTOCOL_VERSION,
    REPLAY_SCHEMA,
    TRACE_SCHEMA,
    WITNESS_SCHEMA,
    failure_signature,
    identity,
    load_json,
    return_digest,
    file_artifact,
    sha256_file,
    validate_witness_integrity,
)
from .runner import RunnerError, build_witness, run_process, resolve_mncs


def load_witness(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict) or value.get("schema_version") != WITNESS_SCHEMA:
        raise ValueError(f"{path} is not {WITNESS_SCHEMA}")
    errors = validate_witness_integrity(value)
    if errors:
        raise ValueError("invalid witness: " + "; ".join(errors))
    return value


def make_session(witness: dict[str, Any]) -> dict[str, Any]:
    session_id = identity("session", {"witness_id": witness["witness_id"], "operation": "open"})
    frames = _frames(witness)
    return {
        "schema_version": "mncs.debug-session/1",
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id,
        "state": "open",
        "witness_id": witness["witness_id"],
        "execution_identity": witness.get("execution_identity"),
        "capabilities": witness.get("capabilities", {}),
        "active_frame": frames[-1] if frames else _frame(witness),
        "transport": {
            "kind": "one_shot_cli",
            "resumable": False,
            "note": "The current runtime has no suspended process; this is an immutable inspection session.",
        },
    }


def _native_observation(witness: dict[str, Any]) -> dict[str, Any] | None:
    runtime = witness.get("runtime") if isinstance(witness.get("runtime"), dict) else {}
    observation = runtime.get("observation")
    if isinstance(observation, dict) and observation.get("schema_version") == "mncs.execution-observation/1":
        return observation
    return None


def _source_function_index(witness: dict[str, Any]) -> dict[str, dict[str, Any]]:
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    source = static.get("source") if isinstance(static.get("source"), dict) else {}
    source_map = source.get("source_map") if isinstance(source.get("source_map"), dict) else {}
    return {
        item["identity"]: item
        for item in source_map.get("functions", [])
        if isinstance(item, dict) and isinstance(item.get("identity"), str)
    }


def _source_operation_index(witness: dict[str, Any]) -> dict[str, dict[str, Any]]:
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    source = static.get("source") if isinstance(static.get("source"), dict) else {}
    source_map = source.get("source_map") if isinstance(source.get("source_map"), dict) else {}
    return {
        item["identity"]: item
        for item in source_map.get("operations", [])
        if isinstance(item, dict) and isinstance(item.get("identity"), str)
    }


def _source_span_for_function(witness: dict[str, Any], function_identity: str | None) -> dict[str, Any] | None:
    if not function_identity:
        return None
    function = _source_function_index(witness).get(function_identity)
    if not function or not isinstance(function.get("declaration_span"), dict):
        return None
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    source = static.get("source") if isinstance(static.get("source"), dict) else {}
    source_map = source.get("source_map") if isinstance(source.get("source_map"), dict) else {}
    return {
        "path": source.get("path"),
        **function["declaration_span"],
        "symbol": function.get("name"),
        "confidence": "compiler_exact",
        "mapping": source_map.get("schema_version", "mncs.execution-source-map/1"),
    }


def _frames(witness: dict[str, Any]) -> list[dict[str, Any]]:
    observation = _native_observation(witness)
    if observation is None:
        return [_frame(witness)]
    request = witness.get("request", {}).get("embedded", {})
    target = request.get("target", {}) if isinstance(request, dict) else {}
    functions = _source_function_index(witness)
    frames: list[dict[str, Any]] = []
    for raw in observation.get("frames", []) if isinstance(observation.get("frames"), list) else []:
        if not isinstance(raw, dict) or not isinstance(raw.get("identity"), str):
            continue
        function_identity = raw.get("function") if isinstance(raw.get("function"), str) else None
        function = functions.get(function_identity, {})
        frames.append(
            {
                "frame_id": raw["identity"],
                "module": target.get("module"),
                "function": function.get("name") or function_identity,
                "function_identity": function_identity,
                "source_location": _source_span_for_function(witness, function_identity),
                "runtime_identity": raw["identity"],
                "parent_frame": raw.get("parent"),
                "call_operation": raw.get("call_operation"),
                "depth": raw.get("depth"),
                "arguments": raw.get("arguments", []),
                "availability": "native_runtime_observed",
                "suspended": False,
            }
        )
    return frames or [_frame(witness)]


def _native_values(witness: dict[str, Any]) -> list[dict[str, Any]]:
    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    return [item for item in trace.get("value_observations", []) if isinstance(item, dict)]


def _native_effects(witness: dict[str, Any]) -> list[dict[str, Any]]:
    observation = _native_observation(witness)
    if observation is not None:
        return [
            item
            for item in observation.get("effects", [])
            if isinstance(item, dict) and isinstance(item.get("identity"), str)
        ]
    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    return [event for event in trace.get("events", []) if isinstance(event, dict) and event.get("kind") == "effect"]


def inspect_witness(witness: dict[str, Any], *, event_id: str | None = None) -> dict[str, Any]:
    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    events = trace.get("events") if isinstance(trace.get("events"), list) else []
    selected_event = None
    if event_id:
        selected_event = next((item for item in events if isinstance(item, dict) and item.get("event_id") == event_id), None)
    outcome = witness.get("outcome") if isinstance(witness.get("outcome"), dict) else {}
    state = {
        "kind": "terminal_snapshot",
        "status": outcome.get("status"),
        "suspended": False,
        "resumable": False,
        "current_event_id": selected_event.get("event_id") if selected_event else (events[-1].get("event_id") if events else None),
        "observation_scope": "request_boundary_and_bounded_trace",
    }
    result = {
        "schema_version": INSPECTION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "inspection_id": identity("inspection", {"witness_id": witness["witness_id"], "event_id": event_id}),
        "witness_id": witness["witness_id"],
        "execution_identity": witness.get("execution_identity"),
        "outcome": outcome,
        "frames": _frames(witness),
        "state": state,
        "values": _native_values(witness),
        "effects": _native_effects(witness),
        "trace": {
            "trace_id": trace.get("trace_id"),
            "event_count": len(events),
            "truncated": trace.get("truncated", False),
            "selected_event": selected_event,
            "observation_identity": trace.get("observation_identity"),
            "completeness": trace.get("completeness", {}),
        },
        "failure": outcome.get("failure"),
        "limitations": witness.get("limitations", []),
    }
    return result


def trace_slice(
    witness: dict[str, Any],
    *,
    kind: str | None = None,
    operation: str | None = None,
    start: int | None = None,
    limit: int = 256,
) -> dict[str, Any]:
    source = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    events = source.get("events") if isinstance(source.get("events"), list) else []
    selected: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if kind and event.get("kind") != kind:
            continue
        runtime = event.get("location", {}).get("runtime", {}) if isinstance(event.get("location"), dict) else {}
        if operation and not (
            runtime.get("operation") == operation
            or event.get("payload", {}).get("operation_identity") == operation
        ):
            continue
        selected.append(event)
    if start is not None:
        selected = [event for event in selected if event.get("sequence", 0) >= start]
    truncated = len(selected) > limit
    selected = selected[:limit]
    material = {
        "source_trace": source.get("trace_id"),
        "execution_identity": witness.get("execution_identity"),
        "events": selected,
        "filters": {"kind": kind, "operation": operation, "start": start, "limit": limit},
    }
    return {
        "schema_version": TRACE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "trace_id": identity("trace-slice", material),
        "slice_of": source.get("trace_id"),
        "execution_identity": witness.get("execution_identity"),
        "events": selected,
        "value_observations": [
            value
            for value in source.get("value_observations", [])
            if not operation
            or value.get("output_identity") == operation
            or value.get("operation") == operation
            or value.get("value_id") in {
                value_id
                for event in selected
                if isinstance(event, dict)
                for value_id in event.get("relationships", {}).get("value_inputs", [])
                if isinstance(value_id, str)
            }
        ],
        "frame_observations": [
            frame
            for frame in source.get("frame_observations", [])
            if not operation
            or frame.get("call_operation") == operation
            or any(
                event.get("location", {}).get("runtime", {}).get("frame") == frame.get("identity")
                for event in selected
                if isinstance(event, dict)
            )
        ],
        "effect_observations": [
            effect
            for effect in source.get("effect_observations", [])
            if not operation
            or effect.get("operation") == operation
            or any(
                event.get("relationships", {}).get("effect") == effect.get("identity")
                for event in selected
                if isinstance(event, dict)
            )
        ],
        "capture_policy": "query_slice",
        "bounded": True,
        "max_events": limit,
        "truncated": truncated or bool(source.get("truncated")),
        "filters": {"kind": kind, "operation": operation, "start": start, "limit": limit},
        "completeness": {
            "ordering": "preserved_from_parent_trace",
            "causality": "preserved event relationships; omitted events may be outside the slice",
        },
    }


def _native_provenance_query(
    witness: dict[str, Any],
    *,
    question: str | None,
    value: str | None,
    operation: str | None,
) -> dict[str, Any]:
    """Answer provenance questions from runtime-emitted references.

    The native path deliberately does not consult the legacy static dataflow
    projection to manufacture a value origin. Static compiler facts are used
    only to attach the already-observed operation to its exact source map
    entry.
    """

    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    events = [event for event in trace.get("events", []) if isinstance(event, dict)]
    values = _native_values(witness)
    value_index = {
        item.get("value_id"): item
        for item in values
        if isinstance(item.get("value_id"), str)
    }
    effects = _native_effects(witness)
    effect_index = {
        item.get("identity"): item
        for item in effects
        if isinstance(item.get("identity"), str)
    }
    operation_index = _source_operation_index(witness)
    operation_events: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        runtime = event.get("location", {}).get("runtime", {}) if isinstance(event.get("location"), dict) else {}
        event_operation = runtime.get("operation")
        if not isinstance(event_operation, str):
            event_operation = event.get("payload", {}).get("operation_identity")
        if isinstance(event_operation, str):
            operation_events.setdefault(event_operation, []).append(event)

    outcome = witness.get("outcome") if isinstance(witness.get("outcome"), dict) else {}
    failure = outcome.get("failure") if isinstance(outcome.get("failure"), dict) else {}
    target_operation = operation
    if target_operation is None and isinstance(failure.get("identity"), str):
        target_operation = failure["identity"]

    target_value = value_index.get(value) if value else None
    if target_operation is None and target_value is not None:
        target_operation = target_value.get("operation")
    if target_operation is None and value:
        target_operation = next(
            (
                event.get("location", {}).get("runtime", {}).get("operation")
                for event in events
                if value in event.get("relationships", {}).get("value_outputs", [])
            ),
            None,
        )

    def value_claim(value_identity: str) -> dict[str, Any]:
        observed = value_index.get(value_identity)
        if observed is None:
            return {
                "identity": value_identity,
                "status": "unobserved",
                "confidence": "native_runtime_observation_missing",
            }
        capture = observed.get("capture") if isinstance(observed.get("capture"), dict) else {}
        return {
            "identity": value_identity,
            "status": "observed",
            "value": observed.get("value") if capture.get("kind") == "full" else None,
            "capture": capture,
            "type_name": observed.get("type_name"),
            "logical_identity": observed.get("logical_identity"),
            "binding": observed.get("binding"),
            "version": observed.get("version"),
            "frame": observed.get("frame"),
            "operation": observed.get("operation"),
            "origin": observed.get("origin"),
            "confidence": "native_runtime_observation",
        }

    claims: list[dict[str, Any]] = []
    if target_value is not None and isinstance(target_value.get("value_id"), str):
        target_value_id = target_value["value_id"]
        claims.append(
            {
                "kind": "value_observation",
                **value_claim(target_value_id),
            }
        )
        origins: list[dict[str, Any]] = []
        current = target_value
        seen: set[str] = set()
        while isinstance(current, dict):
            current_id = current.get("value_id")
            if not isinstance(current_id, str) or current_id in seen:
                break
            seen.add(current_id)
            origin_id = current.get("origin")
            if not isinstance(origin_id, str):
                break
            origins.append(value_claim(origin_id))
            current = value_index.get(origin_id, {})
        if origins:
            claims.append(
                {
                    "kind": "value_origin_chain",
                    "status": "observed",
                    "values": origins,
                    "confidence": "native_runtime_references",
                }
            )

    if target_operation:
        observed_events = operation_events.get(target_operation, [])
        static_operation = operation_index.get(target_operation)
        operation_claim: dict[str, Any] = {
            "identity": target_operation,
            "status": "observed" if observed_events else "unobserved",
            "event_ids": [event.get("event_id") for event in observed_events],
            "confidence": "native_runtime_observation" if observed_events else "native_runtime_identity_missing",
        }
        if static_operation is not None:
            correspondence = dict(static_operation)
            span = correspondence.get("source_span")
            correspondence["confidence"] = "compiler_exact" if isinstance(span, dict) else "compiler_synthetic"
            operation_claim["source_correspondence"] = correspondence
        claims.append({"kind": "operation_identity", "operation": operation_claim})
        if observed_events:
            input_ids: list[str] = []
            output_ids: list[str] = []
            effect_ids: list[str] = []
            for event in observed_events:
                input_ids.extend(
                    item
                    for item in event.get("relationships", {}).get("value_inputs", [])
                    if isinstance(item, str)
                )
                output_ids.extend(
                    item
                    for item in event.get("relationships", {}).get("value_outputs", [])
                    if isinstance(item, str)
                )
                effect = event.get("relationships", {}).get("effect")
                if isinstance(effect, str):
                    effect_ids.append(effect)
            input_ids = list(dict.fromkeys(input_ids))
            output_ids = list(dict.fromkeys(output_ids))
            effect_ids = list(dict.fromkeys(effect_ids))
            claims.append(
                {
                    "kind": "inputs",
                    "status": "observed",
                    "inputs": [value_claim(item) for item in input_ids],
                    "confidence": "native_runtime_value_references",
                }
            )
            claims.append(
                {
                    "kind": "outputs",
                    "status": "observed",
                    "outputs": [value_claim(item) for item in output_ids],
                    "confidence": "native_runtime_value_references",
                }
            )
            frame_ids = list(
                dict.fromkeys(
                    event.get("location", {}).get("runtime", {}).get("frame")
                    for event in observed_events
                    if isinstance(event.get("location"), dict)
                    and isinstance(event.get("location", {}).get("runtime"), dict)
                    and isinstance(event.get("location", {}).get("runtime", {}).get("frame"), str)
                )
            )
            if frame_ids:
                claims.append(
                    {
                        "kind": "frames",
                        "status": "observed",
                        "frames": [frame for frame in _frames(witness) if frame.get("frame_id") in frame_ids],
                        "confidence": "native_runtime_frame_references",
                    }
                )
            for effect_id in effect_ids:
                effect = effect_index.get(effect_id)
                if effect is not None:
                    claims.append(
                        {
                            "kind": "effect_provenance",
                            "status": "observed",
                            "effect": effect,
                            "confidence": "native_runtime_effect_lineage",
                        }
                    )

    selected_event_ids = []
    for event in events:
        runtime = event.get("location", {}).get("runtime", {}) if isinstance(event.get("location"), dict) else {}
        relationships = event.get("relationships", {}) if isinstance(event.get("relationships"), dict) else {}
        if not target_operation and not value:
            selected_event_ids.append(event.get("event_id"))
        elif (
            runtime.get("operation") == target_operation
            or target_operation in relationships.get("value_inputs", [])
            or target_operation in relationships.get("value_outputs", [])
            or value in relationships.get("value_inputs", [])
            or value in relationships.get("value_outputs", [])
        ):
            selected_event_ids.append(event.get("event_id"))
    claims.append(
        {
            "kind": "execution_path",
            "status": "bounded_observation",
            "event_ids": [item for item in selected_event_ids if isinstance(item, str)],
            "confidence": "native_runtime_observation_sequence",
        }
    )
    completeness = _native_observation(witness).get("completeness", {}) if _native_observation(witness) else {}
    complete = completeness.get("status") == "complete"
    material = {
        "witness_id": witness.get("witness_id"),
        "question": question,
        "value": value,
        "operation": operation,
        "claims": claims,
    }
    return {
        "schema_version": PROVENANCE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "provenance_id": identity("provenance", material),
        "witness_id": witness.get("witness_id"),
        "execution_identity": witness.get("execution_identity"),
        "question": question or (f"why {value}" if value else f"why {target_operation}" if target_operation else "execution provenance"),
        "target": {"value": value, "operation": target_operation},
        "claims": claims,
        "completeness": {
            "status": "complete" if complete else "partial",
            "exact": [
                "native value identities and capture status",
                "native operation input/output references",
                "native frame ancestry",
                "compiler-owned source correspondence",
                "native effect invocation/result lineage",
            ],
            "missing": [
                "scheduler/task ancestry",
                "deterministic external-effect replay",
            ],
            "observation": completeness,
        },
        "limitations": witness.get("limitations", []),
    }


def provenance_query(witness: dict[str, Any], *, question: str | None = None, value: str | None = None, operation: str | None = None) -> dict[str, Any]:
    if _native_observation(witness) is not None:
        return _native_provenance_query(witness, question=question, value=value, operation=operation)
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    operations = [item for item in static.get("operations", []) if isinstance(item, dict)]
    target_operation = operation
    outcome = witness.get("outcome") if isinstance(witness.get("outcome"), dict) else {}
    failure = outcome.get("failure") if isinstance(outcome.get("failure"), dict) else {}
    if target_operation is None and isinstance(failure.get("identity"), str):
        target_operation = failure["identity"]
    if target_operation is None and value:
        for item in operations:
            if value in item.get("outputs", []):
                target_operation = item.get("identity")
                break

    claims: list[dict[str, Any]] = []
    if target_operation:
        item = next((candidate for candidate in operations if candidate.get("identity") == target_operation), None)
        if item is not None:
            claims.append(
                {
                    "kind": "operation_identity",
                    "status": "observed" if _operation_observed(witness, target_operation) else "static_only",
                    "operation": item,
                    "confidence": "exact_identity_partial_causality",
                }
            )
            claims.append(
                {
                    "kind": "inputs",
                    "status": "static_dataflow",
                    "inputs": [_value_origin(witness, item_input, operations) for item_input in item.get("inputs", [])],
                    "confidence": "static_dataflow_no_intermediate_runtime_values",
                }
            )
            claims.append(
                {
                    "kind": "outputs",
                    "status": "static_dataflow",
                    "outputs": item.get("outputs", []),
                    "confidence": "static_dataflow",
                }
            )
            claims.append(
                {
                    "kind": "compiler_correspondence",
                    "status": "available" if item.get("ir_identity") or item.get("ssa_identity") else "unavailable",
                    "hir_identity": item.get("ir_identity"),
                    "ssa_identity": item.get("ssa_identity"),
                    "obligations": item.get("obligations", []),
                    "lowering": item.get("lowering"),
                    "confidence": "artifact_identity_exact",
                }
            )
        else:
            claims.append(
                {
                    "kind": "operation_identity",
                    "status": "runtime_only",
                    "operation": target_operation,
                    "confidence": "exact_runtime_identity_static_artifact_missing",
                }
            )
    if not claims:
        claims.append(
            {
                "kind": "question",
                "status": "unresolved",
                "message": "No operation or value identity was supplied or localized by the witness.",
                "confidence": "none",
            }
        )
    trace = witness.get("trace") if isinstance(witness.get("trace"), dict) else {}
    claims.append(
        {
            "kind": "execution_path",
            "status": "bounded_observation",
            "event_ids": [
                event.get("event_id")
                for event in trace.get("events", [])
                if isinstance(event, dict)
                and (
                    not target_operation
                    or event.get("location", {}).get("runtime", {}).get("operation") == target_operation
                    or target_operation in event.get("relationships", {}).get("static_dataflow_inputs", [])
                    or target_operation in event.get("relationships", {}).get("static_dataflow_outputs", [])
                )
            ],
            "confidence": "ordered_trace_only",
        }
    )
    material = {
        "witness_id": witness.get("witness_id"),
        "question": question,
        "value": value,
        "operation": operation,
        "claims": claims,
    }
    return {
        "schema_version": PROVENANCE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "provenance_id": identity("provenance", material),
        "witness_id": witness.get("witness_id"),
        "execution_identity": witness.get("execution_identity"),
        "question": question or (f"why {value}" if value else f"why {target_operation}" if target_operation else "execution provenance"),
        "target": {"value": value, "operation": target_operation},
        "claims": claims,
        "completeness": {
            "status": "partial",
            "exact": ["runtime failure identity when supplied", "static operation identity", "bounded event ordering"],
            "missing": ["intermediate runtime values", "nested frames", "scheduler/task ancestry", "complete effect input lineage"],
        },
        "limitations": witness.get("limitations", []),
    }


def replay_trace(witness: dict[str, Any]) -> dict[str, Any]:
    material = {"witness_id": witness["witness_id"], "trace_id": witness.get("trace", {}).get("trace_id")}
    return {
        "schema_version": REPLAY_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "replay_id": identity("replay", {**material, "mode": "trace_replay"}),
        "witness_id": witness["witness_id"],
        "mode": "trace_replay",
        "guarantee": "inspection of the preserved bounded trace; no program execution occurs",
        "status": "replayed",
        "expected": {"trace_id": witness.get("trace", {}).get("trace_id")},
        "observed": {"trace": witness.get("trace")},
        "differences": [],
        "limitations": ["A trace replay is not deterministic re-execution."],
    }


def replay_execute(witness: dict[str, Any], *, mncs_override: Path | None = None, timeout_seconds: float | None = None, deterministic: bool = False) -> dict[str, Any]:
    if deterministic:
        return _blocked_replay(witness, "deterministic replay is unsupported: scheduler/effect/environment capture is absent")
    integration = witness.get("integration") if isinstance(witness.get("integration"), dict) else {}
    if integration.get("kind") == "mncs-test-result-import":
        return _blocked_replay(
            witness,
            "this witness imports a test-owned verdict; re-execution would run the request only, not the mncs-test assertion/provider",
        )
    replay = witness.get("replay") if isinstance(witness.get("replay"), dict) else {}
    mncs_path = mncs_override or Path(str(replay.get("mncs_path", "")))
    if not mncs_path.exists():
        return _blocked_replay(witness, f"recorded mncs executable is unavailable: {mncs_path}")
    try:
        environment, _ = _replay_environment(witness)
    except RunnerError as exc:
        return _blocked_replay(witness, str(exc))
    try:
        with _replay_inputs(witness) as (program_path, request_path, cwd):
            limit = timeout_seconds or float(replay.get("timeout_seconds", 30.0))
            validation_observation = run_process(
                [os.fspath(mncs_path), "validate", os.fspath(program_path)],
                cwd=cwd,
                timeout_seconds=limit,
                environment=environment,
            )
            validation = validation_observation.json
            if isinstance(validation, dict) and validation.get("valid") is False:
                observation = validation_observation
                execution = None
                observed = _validation_signature(validation)
            else:
                observation = run_process(
                    [os.fspath(mncs_path), "execute", os.fspath(program_path), os.fspath(request_path)],
                    cwd=cwd,
                    timeout_seconds=limit,
                    environment=environment,
                )
                execution = observation.json
                observed = _execution_signature(execution, observation.timed_out)
    except RunnerError as exc:
        return _blocked_replay(witness, str(exc))
    expected = _witness_signature(witness)
    same = observed == expected
    material = {"witness_id": witness["witness_id"], "mode": "reexecute", "expected": expected, "observed": observed}
    return {
        "schema_version": REPLAY_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "replay_id": identity("replay", material),
        "witness_id": witness["witness_id"],
        "mode": "reexecute",
        "guarantee": "bounded re-execution against the selected external executable; deterministic replay is not claimed",
        "status": "reproduced" if same else "mismatch",
        "expected": expected,
        "observed": observed,
        "execution": execution,
        "process": {"returncode": observation.returncode, "timed_out": observation.timed_out},
        "differences": [] if same else _differences(expected, observed),
        "limitations": [
            "The current runtime does not capture scheduler decisions or external effects for replay.",
            "Matching compares bounded status/failure identity/return digest, not universal execution equivalence.",
        ],
    }


def minimize_witness(
    witness: dict[str, Any],
    *,
    max_attempts: int = 32,
    mncs_override: Path | None = None,
    timeout_seconds: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Try only integer request reductions that preserve the exact signature."""

    request = witness.get("request", {}).get("embedded")
    if not isinstance(request, dict):
        return witness, _min_report(witness, "blocked", "request is not embedded in the witness", [], 0)
    args = request.get("arguments")
    if not isinstance(args, list):
        return witness, _min_report(witness, "blocked", "request arguments are unavailable", [], 0)
    replay = witness.get("replay") if isinstance(witness.get("replay"), dict) else {}
    mncs_path = mncs_override or Path(str(replay.get("mncs_path", "")))
    if not mncs_path.exists():
        return witness, _min_report(witness, "blocked", f"mncs executable is unavailable: {mncs_path}", [], 0)
    try:
        environment, library_paths = _replay_environment(witness)
    except RunnerError as exc:
        return witness, _min_report(witness, "blocked", str(exc), [], 0)
    baseline = _witness_signature(witness)
    changes: list[dict[str, Any]] = []
    attempts = 0
    with _replay_inputs(witness) as (program_path, original_request_path, cwd):
        current = copy.deepcopy(request)
        for index, argument in enumerate(list(args)):
            current_value = _integer_value(argument)
            if current_value is None:
                continue
            for candidate_value in _candidates(current_value):
                if attempts >= max_attempts:
                    break
                attempts += 1
                candidate = copy.deepcopy(current)
                candidate["arguments"][index] = _replace_integer(candidate["arguments"][index], candidate_value)
                candidate_fd, candidate_name = tempfile.mkstemp(prefix="mncs-debug-min-")
                os.close(candidate_fd)
                candidate_path = Path(candidate_name)
                try:
                    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                    observation = run_process(
                        [os.fspath(mncs_path), "execute", os.fspath(program_path), os.fspath(candidate_path)],
                        cwd=cwd,
                        timeout_seconds=timeout_seconds or float(replay.get("timeout_seconds", 30.0)),
                        environment=environment,
                    )
                    observed = _execution_signature(observation.json, observation.timed_out)
                except RunnerError:
                    observed = {"status": "infrastructure_failure"}
                finally:
                    try:
                        candidate_path.unlink()
                    except OSError:
                        pass
                if observed == baseline:
                    old_value = current["arguments"][index]
                    current["arguments"][index] = _replace_integer(current["arguments"][index], candidate_value)
                    changes.append({"argument": index, "from": old_value, "to": current["arguments"][index]})
                    break
            if attempts >= max_attempts:
                break
        if not changes:
            return witness, _min_report(witness, "no_reduction", "no integer candidate preserved the exact failure signature", [], attempts)
        final_fd, final_name = tempfile.mkstemp(prefix="mncs-debug-min-final-")
        os.close(final_fd)
        final_path = Path(final_name)
        try:
            final_path.write_text(json.dumps(current), encoding="utf-8")
            integration = witness.get("integration") if isinstance(witness.get("integration"), dict) else {}
            test_result = integration.get("result") if integration.get("kind") == "mncs-test-result-import" and isinstance(integration.get("result"), dict) else None
            reduced = build_witness(
                mncs_path=mncs_path,
                program_path=program_path,
                request_path=final_path,
                cwd=cwd,
                timeout_seconds=timeout_seconds or float(replay.get("timeout_seconds", 30.0)),
                test_result=test_result,
                library_paths=library_paths,
            )
        finally:
            try:
                final_path.unlink()
            except OSError:
                pass
    report = _min_report(reduced, "reduced", "all accepted mutations retained the exact bounded failure signature", changes, attempts)
    report["parent_witness_id"] = witness["witness_id"]
    return reduced, report


def _frame(witness: dict[str, Any]) -> dict[str, Any]:
    request = witness.get("request", {}).get("embedded", {})
    target = request.get("target", {}) if isinstance(request, dict) else {}
    static = witness.get("static", {}) if isinstance(witness.get("static"), dict) else {}
    location = static.get("source", {}).get("function_locations", {}).get(target.get("function"))
    return {
        "frame_id": identity("frame", {"execution_identity": witness.get("execution_identity"), "function": target.get("function")}),
        "module": target.get("module"),
        "function": target.get("function"),
        "function_identity": witness.get("program", {}).get("function_identity"),
        "source_location": location,
        "runtime_identity": witness.get("program", {}).get("function_identity"),
        "availability": "requested_entry_only",
        "suspended": False,
    }


def _operation_observed(witness: dict[str, Any], operation: str) -> bool:
    trace = witness.get("trace", {})
    return any(
        isinstance(event, dict) and event.get("location", {}).get("runtime", {}).get("operation") == operation
        for event in trace.get("events", [])
    )


def _value_origin(witness: dict[str, Any], value_identity: str, operations: list[dict[str, Any]]) -> dict[str, Any]:
    request = witness.get("request", {}).get("embedded", {})
    target = request.get("target", {}) if isinstance(request, dict) else {}
    arguments = request.get("arguments", []) if isinstance(request, dict) else []
    static = witness.get("static") if isinstance(witness.get("static"), dict) else {}
    function_identity = witness.get("program", {}).get("function_identity")
    static_function = next(
        (
            item
            for item in static.get("functions", [])
            if isinstance(item, dict) and item.get("identity") == function_identity
        ),
        None,
    )
    parameter_identities = static_function.get("inputs", []) if isinstance(static_function, dict) else []
    for index, argument in enumerate(arguments):
        if index < len(parameter_identities) and value_identity == parameter_identities[index]:
            return {
                "identity": value_identity,
                "origin": "request_argument",
                "argument_index": index,
                "value": argument,
                "confidence": "exact_static_parameter_identity",
            }
        parameter_prefix = f"mncs:0.2:value:{target.get('module')}::{target.get('function')}::parameter::"
        if value_identity.startswith(parameter_prefix) and value_identity.endswith(str(index)):
            return {
                "identity": value_identity,
                "origin": "request_argument",
                "argument_index": index,
                "value": argument,
                "confidence": "runtime_parameter_identity_suffix",
            }
    producer = next((item for item in operations if value_identity in item.get("outputs", [])), None)
    if producer:
        return {"identity": value_identity, "origin": "operation_output", "producer": producer.get("identity"), "confidence": "static_dataflow"}
    return {"identity": value_identity, "origin": "unresolved", "confidence": "none"}


def _execution_signature(execution: Any, timed_out: bool = False) -> dict[str, Any]:
    if timed_out:
        return {"failure_class": "timeout_or_budget_exhaustion", "status": "budget_exhausted", "failure_identity": None, "test_id": None, "returned_digest": None}
    if not isinstance(execution, dict):
        return {"failure_class": "infrastructure_bootstrap_failure", "status": "infrastructure_failure", "failure_identity": None, "test_id": None, "returned_digest": None}
    failure = execution.get("failure") if isinstance(execution.get("failure"), dict) else {}
    status = execution.get("status")
    failure_class = {
        "returned": "success",
        "runtime_failure": "runtime_failure",
        "unsupported": "unsupported_debug_capability",
        "budget_exhausted": "timeout_or_budget_exhaustion",
        "invalid_request": "invalid_invocation",
    }.get(status, "infrastructure_bootstrap_failure")
    return {
        "failure_class": failure_class,
        "status": status,
        "failure_identity": failure.get("identity"),
        "test_id": None,
        "returned_digest": return_digest(execution.get("returned", [])),
    }


def _witness_signature(witness: dict[str, Any]) -> dict[str, Any]:
    outcome = witness.get("outcome", {}) if isinstance(witness.get("outcome"), dict) else {}
    failure = outcome.get("failure") if isinstance(outcome.get("failure"), dict) else {}
    return {
        "failure_class": outcome.get("failure_class"),
        "status": outcome.get("status"),
        "failure_identity": failure.get("identity"),
        "test_id": outcome.get("test_id"),
        "returned_digest": outcome.get("returned_digest"),
    }


def _differences(expected: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    return [key for key in sorted(set(expected) | set(observed)) if expected.get(key) != observed.get(key)]


def _validation_signature(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "failure_class": "compile_failure",
        "status": "compile_failure",
        "failure_identity": identity("compiler-diagnostic", validation),
        "test_id": None,
        "returned_digest": None,
    }


def _replay_environment(witness: dict[str, Any]) -> tuple[dict[str, str], list[Path]]:
    replay = witness.get("replay") if isinstance(witness.get("replay"), dict) else {}
    raw_libraries = replay.get("libraries") if isinstance(replay.get("libraries"), list) else []
    libraries: list[Path] = []
    for item in raw_libraries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        path = Path(item["path"]).resolve()
        if not path.is_dir():
            raise RunnerError(f"replay library is unavailable: {path}")
        recorded_digest = item.get("sha256")
        observed_digest = file_artifact(path, "replay-library").get("sha256")
        if recorded_digest and recorded_digest != observed_digest:
            raise RunnerError(f"replay library digest changed: {path}")
        libraries.append(path)
    environment = dict(os.environ)
    if libraries:
        environment["MNCS_LIBRARY_PATH"] = os.pathsep.join(os.fspath(path) for path in libraries)
    else:
        environment.pop("MNCS_LIBRARY_PATH", None)
    return environment, libraries


def _blocked_replay(witness: dict[str, Any], message: str) -> dict[str, Any]:
    material = {"witness_id": witness.get("witness_id"), "mode": "reexecute", "status": "blocked", "message": message}
    return {
        "schema_version": REPLAY_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "replay_id": identity("replay", material),
        "witness_id": witness.get("witness_id"),
        "mode": "reexecute",
        "guarantee": "none",
        "status": "blocked",
        "error": message,
        "differences": [],
        "limitations": [message],
    }


def _min_report(witness: dict[str, Any], status: str, message: str, changes: list[dict[str, Any]], attempts: int) -> dict[str, Any]:
    return {
        "schema_version": "mncs.debug-minimization/1",
        "protocol_version": PROTOCOL_VERSION,
        "minimization_id": identity("minimization", {"witness_id": witness.get("witness_id"), "status": status, "changes": changes, "attempts": attempts}),
        "witness_id": witness.get("witness_id"),
        "status": status,
        "message": message,
        "attempts": attempts,
        "changes": changes,
        "equivalence": "exact bounded status/failure identity/test id/return digest signature",
        "conservative": True,
    }


def _integer_value(value: Any) -> int | None:
    if isinstance(value, dict) and isinstance(value.get("integer"), dict) and isinstance(value["integer"].get("value"), int):
        return value["integer"]["value"]
    return None


def _replace_integer(value: Any, integer: int) -> Any:
    replacement = copy.deepcopy(value)
    replacement["integer"]["value"] = integer
    return replacement


def _candidates(value: int) -> list[int]:
    candidates: list[int] = []
    seen: set[int] = set()
    for candidate in (0, -1 if value < 0 else 1, value // 2, value - value // 2):
        if candidate != value and candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


class _ReplayInputs:
    def __init__(self, witness: dict[str, Any]):
        self.witness = witness
        self.directory: tempfile.TemporaryDirectory[str] | None = None
        self.program_path: Path | None = None
        self.request_path: Path | None = None
        self.cwd: Path | None = None

    def __enter__(self) -> tuple[Path, Path, Path]:
        replay = self.witness.get("replay", {}) if isinstance(self.witness.get("replay"), dict) else {}
        program = self.witness.get("program", {}) if isinstance(self.witness.get("program"), dict) else {}
        request = self.witness.get("request", {}) if isinstance(self.witness.get("request"), dict) else {}
        original_program = Path(str(replay.get("program_path", program.get("path", ""))))
        original_request = Path(str(replay.get("request_path", request.get("path", ""))))
        original_cwd = Path(str(replay.get("cwd", ".")))
        program_digest = program.get("sha256")
        request_digest = request.get("sha256")
        use_program = original_program.exists() and (not program_digest or sha256_file(original_program) == program_digest)
        use_request = original_request.exists() and (not request_digest or sha256_file(original_request) == request_digest)
        if use_program and use_request:
            self.program_path = original_program
            self.request_path = original_request
            self.cwd = original_cwd if original_cwd.exists() else original_program.parent
            return self.program_path, self.request_path, self.cwd
        self.directory = tempfile.TemporaryDirectory(prefix="mncs-debug-replay-")
        root = Path(self.directory.name)
        embedded = program.get("embedded") if isinstance(program.get("embedded"), dict) else {}
        if not embedded.get("embedded"):
            raise RunnerError("program path/digest is unavailable and no complete embedded program exists")
        content = embedded.get("content", "")
        if embedded.get("encoding") == "base64":
            import base64

            data = base64.b64decode(content)
        else:
            data = str(content).encode("utf-8")
        suffix = ".mncs" if original_program.suffix == ".mncs" else ".json"
        self.program_path = root / f"program{suffix}"
        self.program_path.write_bytes(data)
        embedded_request = request.get("embedded")
        if not isinstance(embedded_request, dict):
            raise RunnerError("request is not embedded")
        self.request_path = root / "request.json"
        self.request_path.write_text(json.dumps(embedded_request), encoding="utf-8")
        self.cwd = root
        return self.program_path, self.request_path, self.cwd

    def __exit__(self, *_: Any) -> None:
        if self.directory is not None:
            self.directory.cleanup()


def _replay_inputs(witness: dict[str, Any]) -> _ReplayInputs:
    return _ReplayInputs(witness)
