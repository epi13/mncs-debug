"""Normalize the bounded MNCS execution trace into debug-event/1."""

from __future__ import annotations

from typing import Any

from .protocol import EVENT_SCHEMA, PROTOCOL_VERSION, TRACE_SCHEMA, identity, return_digest


def _operation_index(static: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["identity"]: item
        for item in static.get("operations", [])
        if isinstance(item, dict) and isinstance(item.get("identity"), str)
    }


def _source_location(source: dict[str, Any] | None, function: str | None) -> dict[str, Any] | None:
    if not source or not function:
        return None
    locations = source.get("function_locations")
    if isinstance(locations, dict):
        location = locations.get(function)
        if isinstance(location, dict):
            return location
    return None


def _event(
    *,
    execution_identity: str,
    sequence: int,
    kind: str,
    location: dict[str, Any],
    payload: dict[str, Any],
    relationships: dict[str, Any],
    evidence: str,
    completeness: str,
) -> dict[str, Any]:
    material = {
        "execution_identity": execution_identity,
        "sequence": sequence,
        "kind": kind,
        "location": location,
        "payload": payload,
        "relationships": relationships,
    }
    return {
        "schema_version": EVENT_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "event_id": identity("event", material),
        **material,
        "evidence": evidence,
        "completeness": completeness,
    }


def _value_observation(value: Any, *, origin: str, sequence: int, output_identity: str | None = None) -> dict[str, Any]:
    material = {"value": value, "origin": origin, "sequence": sequence, "output_identity": output_identity}
    return {
        "value_id": identity("value", material),
        "kind": _value_kind(value),
        "value": value,
        "origin": origin,
        "output_identity": output_identity,
        "confidence": "exact_runtime_return",
    }


def _value_kind(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("integer", "float", "boolean", "finite", "record", "byte", "sequence", "vector", "mask"):
            if key in value:
                return key
    return "unknown"


def make_trace(
    *,
    execution_identity: str,
    execution: dict[str, Any],
    static: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
    capture_policy: str = "bounded",
    max_events: int = 512,
) -> dict[str, Any]:
    """Create a bounded trace while preserving the runtime's exact events."""

    static = static or {}
    op_index = _operation_index(static)
    target = execution.get("target") if isinstance(execution.get("target"), dict) else {}
    function = target.get("function") if isinstance(target.get("function"), str) else None
    function_identity = execution.get("function_identity")
    program_identity = execution.get("program_identity")
    runtime_entries = execution.get("trace") if isinstance(execution.get("trace"), list) else []
    events: list[dict[str, Any]] = []
    values: list[dict[str, Any]] = []
    previous_id: str | None = None

    function_location = _source_location(source, function)
    entry_location = {
        "program": program_identity,
        "function": function_identity,
        "source": function_location,
        "runtime": {"module": target.get("module"), "function": function},
    }
    entry = _event(
        execution_identity=execution_identity,
        sequence=0,
        kind="function_entry",
        location=entry_location,
        payload={"function": function, "runtime_stack_depth": None},
        relationships={},
        evidence="mncs-debug-derived-boundary",
        completeness="derived_single_entry_frame",
    )
    events.append(entry)
    previous_id = entry["event_id"]

    for raw in runtime_entries:
        if not isinstance(raw, dict):
            continue
        step = raw.get("step")
        if not isinstance(step, int) or step < 0:
            continue
        raw_event = raw.get("event") if isinstance(raw.get("event"), str) else "unknown"
        operation = raw.get("operation") if isinstance(raw.get("operation"), str) else None
        block = raw.get("block") if isinstance(raw.get("block"), str) else None
        static_operation = op_index.get(operation) if operation else None
        kind = {
            "block_enter": "block_enter",
            "operation": "semantic_operation",
            "terminator": "state_transition",
        }.get(raw_event, "runtime_event")
        payload: dict[str, Any] = {
            "runtime_event": raw_event,
            "runtime_step": step,
            "operation_identity": operation,
            "block_identity": block,
        }
        if static_operation is not None:
            payload["static_operation"] = {
                "kind": static_operation.get("kind"),
                "inputs": static_operation.get("inputs", []),
                "outputs": static_operation.get("outputs", []),
                "effects": static_operation.get("effects", []),
                "obligations": static_operation.get("obligations", []),
            }
        location = {
            "program": program_identity,
            "function": function_identity,
            "source": None,
            "runtime": {
                "module": target.get("module"),
                "function": function,
                "block": block,
                "operation": operation,
            },
        }
        relationships: dict[str, Any] = {"observed_after": previous_id} if previous_id else {}
        if operation and static_operation is not None:
            relationships["static_block"] = static_operation.get("block_identity")
            relationships["static_dataflow_inputs"] = static_operation.get("inputs", [])
            relationships["static_dataflow_outputs"] = static_operation.get("outputs", [])
        event = _event(
            execution_identity=execution_identity,
            sequence=step + 1,
            kind=kind,
            location=location,
            payload=payload,
            relationships=relationships,
            evidence="mncs-language.execution-result/0.1",
            completeness="runtime_identity_without_value_snapshot",
        )
        events.append(event)
        previous_id = event["event_id"]

    effects = execution.get("effects") if isinstance(execution.get("effects"), list) else []
    effect_sequence = max((event["sequence"] for event in events), default=0) + 1
    operation_events = {
        event["location"].get("runtime", {}).get("operation"): event["event_id"]
        for event in events
        if isinstance(event.get("location"), dict)
        and isinstance(event["location"].get("runtime"), dict)
        and event["location"]["runtime"].get("operation")
    }
    for effect in effects:
        if not isinstance(effect, dict):
            continue
        operation = effect.get("operation")
        effect_event = _event(
            execution_identity=execution_identity,
            sequence=effect_sequence,
            kind="effect",
            location={
                "program": program_identity,
                "function": function_identity,
                "source": None,
                "runtime": {"operation": operation, "effect": effect.get("kind")},
            },
            payload={
                "kind": effect.get("kind"),
                "target": effect.get("target"),
                "capability": effect.get("capability"),
                "provenance": effect.get("provenance"),
            },
            relationships={
                "caused_by": operation_events.get(operation),
                "causality_confidence": "operation_association_only",
            },
            evidence="mncs-language.execution-effect/0.1",
            completeness="effect_observed_without_input_lineage",
        )
        events.append(effect_event)
        previous_id = effect_event["event_id"]
        effect_sequence += 1

    status = execution.get("status")
    failure = execution.get("failure") if isinstance(execution.get("failure"), dict) else None
    if failure is not None or status not in {"returned", None}:
        failure_sequence = max((event["sequence"] for event in events), default=0) + 1
        failure_event = _event(
            execution_identity=execution_identity,
            sequence=failure_sequence,
            kind="failure",
            location={
                "program": program_identity,
                "function": function_identity,
                "source": None,
                "runtime": {
                    "status": status,
                    "failure_identity": failure.get("identity") if failure else None,
                },
            },
            payload={"status": status, "failure": failure},
            relationships={"observed_after": previous_id} if previous_id else {},
            evidence="mncs-language.execution-result/0.1",
            completeness="exact_failure_identity_when_present",
        )
        events.append(failure_event)
        previous_id = failure_event["event_id"]
    else:
        exit_sequence = max((event["sequence"] for event in events), default=0) + 1
        returned = execution.get("returned") if isinstance(execution.get("returned"), list) else []
        output_identities = _output_identities(static, function)
        for index, value in enumerate(returned):
            values.append(
                _value_observation(
                    value,
                    origin="function_return",
                    sequence=exit_sequence,
                    output_identity=output_identities[index] if index < len(output_identities) else None,
                )
            )
        exit_event = _event(
            execution_identity=execution_identity,
            sequence=exit_sequence,
            kind="function_exit",
            location=entry_location,
            payload={
                "status": status,
                "returned_count": len(returned),
                "returned_digest": return_digest(returned),
                "runtime_stack_depth": None,
            },
            relationships={"observed_after": previous_id} if previous_id else {},
            evidence="mncs-debug-derived-boundary",
            completeness="derived_single_entry_frame",
        )
        events.append(exit_event)

    events.sort(key=lambda event: (event["sequence"], event["event_id"]))
    truncated = len(events) > max_events or bool(execution.get("trace_truncated"))
    if len(events) > max_events:
        events = events[:max_events]
    material = {
        "execution_identity": execution_identity,
        "events": events,
        "values": values,
        "capture_policy": capture_policy,
        "bounded": True,
        "truncated": truncated,
    }
    trace = {
        "schema_version": TRACE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "trace_id": identity("trace", material),
        "execution_identity": execution_identity,
        "events": events,
        "value_observations": values,
        "capture_policy": capture_policy,
        "bounded": True,
        "max_events": max_events,
        "truncated": truncated,
        "runtime_trace_entries": len(runtime_entries),
        "completeness": {
            "ordering": "exact_for_preserved_runtime_events",
            "source_locations": "function_declaration_only_or_unavailable",
            "values": "arguments_and_returns_only",
            "frames": "requested_entry_frame_only",
            "causality": "partial_order_and_static_dataflow_association",
            "tasks": "unavailable",
        },
    }
    return trace


def _output_identities(static: dict[str, Any], function: str | None) -> list[str]:
    for item in static.get("functions", []):
        if not isinstance(item, dict):
            continue
        if item.get("name") == function:
            outputs = item.get("outputs")
            if isinstance(outputs, list):
                return [value for value in outputs if isinstance(value, str)]
    return []
