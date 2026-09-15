"""Small, dependency-free protocol and identity helpers.

The module deliberately does not interpret MNCS program semantics. It
provides canonical JSON, bounded artifact handling, and structural checks for
the documents emitted by the semantic-core/runtime adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SESSION_SCHEMA = "mncs.debug-session/1"
EVENT_SCHEMA = "mncs.debug-event/1"
TRACE_SCHEMA = "mncs.debug-trace/1"
WITNESS_SCHEMA = "mncs.debug-witness/1"
REPLAY_SCHEMA = "mncs.debug-replay/1"
CAPABILITIES_SCHEMA = "mncs.debug-capabilities/1"
INSPECTION_SCHEMA = "mncs.debug-inspection/1"
PROVENANCE_SCHEMA = "mncs.debug-provenance/1"
API_SCHEMA = "mncs.debug-api/1"
VALIDATION_SCHEMA = "mncs.debug-validation/1"
MINIMIZATION_SCHEMA = "mncs.debug-minimization/1"
SUFFICIENCY_SCHEMA = "mncs.debug-sufficiency/1"
DIAGNOSIS_SCHEMA = "mncs.debug-diagnosis/1"
DEMONSTRATIONS_SCHEMA = "mncs.debug-demonstrations/1"
OVERHEAD_SCHEMA = "mncs.debug-overhead/1"
PROTOCOL_VERSION = 1
MAX_CAPTURE_BYTES = 64 * 1024
MAX_EMBEDDED_INPUT_BYTES = 256 * 1024
MAX_TRACE_EVENTS = 512
MAX_STATIC_RECORDS = 2048
LANGUAGE_OBSERVATION_SCHEMA = "mncs.execution-observation/1"
LANGUAGE_SOURCE_MAP_SCHEMA = "mncs.execution-source-map/1"

CAPABILITY_STATES = (
    "supported",
    "partially_supported",
    "unsupported",
    "emulated",
    "bootstrap_host_boundary",
)

FAILURE_CLASSES = (
    "success",
    "compile_failure",
    "runtime_failure",
    "assertion_failure",
    "effect_failure",
    "action_failure",
    "timeout_or_budget_exhaustion",
    "unsupported_debug_capability",
    "invalid_invocation",
    "infrastructure_bootstrap_failure",
    "test_failure",
)


class ProtocolError(ValueError):
    """The input is not a valid document for the requested protocol."""


def canonical_json(value: Any) -> str:
    """Return the stable identity representation used by this repository."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_value(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def identity(namespace: str, value: Any) -> str:
    return f"mncs:debug:{namespace}:{sha256_value(value)}"


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProtocolError(f"unable to read JSON {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_artifact(path: Path, kind: str, *, relative_to: Path | None = None) -> dict[str, Any]:
    """Describe a file without making its path part of a semantic identity."""

    try:
        if path.is_dir():
            digest = hashlib.sha256()
            total_size = 0
            file_count = 0
            for child in sorted(item for item in path.rglob("*") if item.is_file()):
                relative = child.relative_to(path).as_posix().encode("utf-8")
                child_digest = sha256_file(child)
                child_size = child.stat().st_size
                digest.update(relative)
                digest.update(b"\0")
                digest.update(child_digest.encode("ascii"))
                digest.update(b"\0")
                total_size += child_size
                file_count += 1
            shown_path = path.as_posix()
            if relative_to is not None:
                try:
                    shown_path = path.resolve().relative_to(relative_to.resolve()).as_posix()
                except ValueError:
                    pass
            return {
                "kind": kind,
                "path": shown_path,
                "sha256": digest.hexdigest(),
                "size_bytes": total_size,
                "file_count": file_count,
                "available": True,
                "artifact_type": "directory_tree",
            }
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as exc:
        return {
            "kind": kind,
            "path": path.as_posix(),
            "sha256": sha256_bytes(f"unreadable:{path}:{exc}".encode()),
            "size_bytes": 0,
            "available": False,
        }
    shown_path = path.as_posix()
    if relative_to is not None:
        try:
            shown_path = path.resolve().relative_to(relative_to.resolve()).as_posix()
        except ValueError:
            pass
    return {
        "kind": kind,
        "path": shown_path,
        "sha256": digest,
        "size_bytes": size,
        "available": True,
    }


def bounded_text(data: bytes, limit: int = MAX_CAPTURE_BYTES) -> dict[str, Any]:
    """Preserve bounded text and its full-byte digest."""

    clipped = data[:limit]
    return {
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "truncated": len(data) > len(clipped),
        "text": clipped.decode("utf-8", errors="replace"),
    }


def embedded_bytes(data: bytes, limit: int = MAX_EMBEDDED_INPUT_BYTES) -> dict[str, Any]:
    clipped = data[:limit]
    return {
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "embedded": len(data) <= limit,
        "truncated": len(data) > limit,
        "encoding": "utf-8" if _is_utf8(data) else "base64",
        "content": (
            clipped.decode("utf-8", errors="strict")
            if _is_utf8(data)
            else base64.b64encode(clipped).decode("ascii")
        ),
    }


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def host_facts() -> dict[str, str]:
    """Return small reproducibility facts, never the ambient environment."""

    return {
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python": platform.python_version(),
        "byteorder": sys.byteorder,
    }


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{label} must be a non-empty string")
    return value


def _required(document: dict[str, Any], fields: Iterable[str], label: str) -> list[str]:
    return [field for field in fields if field not in document]


def validate_document(value: Any, expected_schema: str | None = None) -> list[str]:
    """Validate the stable structural membrane without third-party packages."""

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["document must be an object"]
    schema = value.get("schema_version")
    if not isinstance(schema, str):
        errors.append("schema_version must be a string")
        return errors
    if expected_schema is not None and schema != expected_schema:
        errors.append(f"schema_version must be {expected_schema!r}, got {schema!r}")
        return errors

    required: dict[str, tuple[str, ...]] = {
        SESSION_SCHEMA: ("schema_version", "protocol_version", "session_id", "state", "witness_id", "capabilities"),
        EVENT_SCHEMA: ("schema_version", "protocol_version", "event_id", "execution_identity", "sequence", "kind", "location", "payload", "relationships"),
        TRACE_SCHEMA: ("schema_version", "protocol_version", "trace_id", "execution_identity", "events", "capture_policy", "bounded"),
        WITNESS_SCHEMA: ("schema_version", "protocol_version", "witness_id", "execution_identity", "program", "request", "outcome", "trace", "replay", "capabilities", "provenance"),
        REPLAY_SCHEMA: ("schema_version", "protocol_version", "replay_id", "witness_id", "mode", "guarantee", "status"),
        CAPABILITIES_SCHEMA: ("schema_version", "protocol_version", "debugger", "capabilities"),
        INSPECTION_SCHEMA: ("schema_version", "protocol_version", "witness_id", "outcome", "frames", "state", "trace"),
        PROVENANCE_SCHEMA: ("schema_version", "protocol_version", "provenance_id", "witness_id", "question", "claims", "completeness"),
        API_SCHEMA: ("schema_version", "protocol_version", "operation"),
        VALIDATION_SCHEMA: ("schema_version", "protocol_version", "valid", "kind", "errors"),
        MINIMIZATION_SCHEMA: ("schema_version", "protocol_version", "minimization_id", "witness_id", "status", "message", "attempts", "changes", "equivalence", "conservative"),
        SUFFICIENCY_SCHEMA: ("schema_version", "protocol_version", "sufficiency_id", "witness_id", "status", "sufficient", "next_operation", "evidence_gap"),
        DIAGNOSIS_SCHEMA: ("schema_version", "protocol_version", "diagnosis_id", "witness_id", "status", "sufficient", "stopping_reason", "budget", "steps", "requested_projections", "projections", "final_sufficiency"),
        DEMONSTRATIONS_SCHEMA: ("schema_version", "captured_at", "baseline_file", "selected_runtime", "demonstrations", "interpretation"),
        OVERHEAD_SCHEMA: ("schema_version", "protocol_version", "measurement_id", "program", "request", "runtime", "iterations", "direct", "record", "median_overhead", "interpretation", "boundedness"),
    }
    fields = required.get(schema)
    if fields is None:
        errors.append(f"unsupported protocol schema {schema!r}")
        return errors
    errors.extend(f"missing required field {field!r}" for field in _required(value, fields, schema))
    if "protocol_version" in value and value.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("protocol_version must be 1")
    if schema == EVENT_SCHEMA:
        if not isinstance(value.get("sequence"), int) or value["sequence"] < 0:
            errors.append("event sequence must be a non-negative integer")
        if not isinstance(value.get("kind"), str) or not value["kind"]:
            errors.append("event kind must be a non-empty string")
    if schema == TRACE_SCHEMA and not isinstance(value.get("events"), list):
        errors.append("trace events must be an array")
    if schema == WITNESS_SCHEMA:
        if not isinstance(value.get("outcome"), dict):
            errors.append("witness outcome must be an object")
        if not isinstance(value.get("trace"), dict):
            errors.append("witness trace must be an object")
    if schema == CAPABILITIES_SCHEMA:
        if not isinstance(value.get("capabilities"), list):
            errors.append("capabilities must be an array")
        else:
            for index, item in enumerate(value["capabilities"]):
                if not isinstance(item, dict):
                    errors.append(f"capabilities[{index}] must be an object")
                elif item.get("state") not in CAPABILITY_STATES:
                    errors.append(f"capabilities[{index}].state is not a capability state")
    if schema == REPLAY_SCHEMA and value.get("status") not in {
        "replayed",
        "reproduced",
        "mismatch",
        "blocked",
        "invalid",
    }:
        errors.append("replay status is invalid")
    if schema == MINIMIZATION_SCHEMA and value.get("status") not in {"reduced", "no_reduction", "blocked"}:
        errors.append("minimization status is invalid")
    if schema == SUFFICIENCY_SCHEMA:
        if value.get("status") not in {"sufficient", "ambiguous", "unsupported"}:
            errors.append("sufficiency status is invalid")
        if not isinstance(value.get("sufficient"), bool):
            errors.append("sufficiency sufficient must be boolean")
    if schema == DIAGNOSIS_SCHEMA:
        if value.get("status") not in {"sufficient", "unknown", "unsupported"}:
            errors.append("diagnosis status is invalid")
        if not isinstance(value.get("sufficient"), bool):
            errors.append("diagnosis sufficient must be boolean")
        if not isinstance(value.get("steps"), list):
            errors.append("diagnosis steps must be an array")
        if not isinstance(value.get("requested_projections"), list):
            errors.append("diagnosis requested_projections must be an array")
        if not isinstance(value.get("projections"), list):
            errors.append("diagnosis projections must be an array")
        if not isinstance(value.get("budget"), dict):
            errors.append("diagnosis budget must be an object")
        if not isinstance(value.get("final_sufficiency"), dict):
            errors.append("diagnosis final_sufficiency must be an object")
    return errors


def validate_witness_integrity(witness: dict[str, Any]) -> list[str]:
    errors = validate_document(witness, WITNESS_SCHEMA)
    if errors:
        return errors
    material = dict(witness)
    recorded = material.pop("witness_id", None)
    material.pop("created_at", None)
    expected = identity("witness", material)
    if recorded != expected:
        errors.append(f"witness_id does not match content: expected {expected}")
    trace = witness.get("trace")
    if isinstance(trace, dict):
        errors.extend(validate_document(trace, TRACE_SCHEMA))
        for index, event in enumerate(trace.get("events", [])):
            event_errors = validate_document(event, EVENT_SCHEMA)
            errors.extend(f"trace.events[{index}]: {error}" for error in event_errors)
    runtime = witness.get("runtime")
    if isinstance(runtime, dict):
        observation = runtime.get("observation")
        if observation is not None:
            errors.extend(validate_language_observation(observation, label="runtime.observation"))
            if isinstance(trace, dict) and isinstance(observation, dict):
                if (
                    trace.get("observation_identity") is not None
                    and trace.get("observation_identity") != observation.get("identity")
                ):
                    errors.append("trace.observation_identity does not match runtime.observation.identity")
                observed_ids = {
                    item.get("identity")
                    for item in observation.get("events", [])
                    if isinstance(item, dict) and isinstance(item.get("identity"), str)
                }
                projected_ids = {
                    item.get("payload", {}).get("native_event", {}).get("identity")
                    for item in trace.get("events", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("payload"), dict)
                    and isinstance(item.get("payload", {}).get("native_event"), dict)
                }
                missing = sorted(item for item in projected_ids - observed_ids if isinstance(item, str))
                if missing:
                    errors.append(f"trace projects unknown native observation events: {missing[:4]}")
        source_map = runtime.get("source_map")
        if source_map is not None:
            errors.extend(validate_language_source_map(source_map, label="runtime.source_map"))
    static = witness.get("static")
    if isinstance(static, dict):
        source = static.get("source")
        if (
            isinstance(source, dict)
            and isinstance(source.get("source_map"), dict)
            and source["source_map"].get("schema_version") is not None
        ):
            errors.extend(validate_language_source_map(source["source_map"], label="static.source.source_map"))
    return errors


def validate_language_observation(value: Any, *, label: str = "observation") -> list[str]:
    """Validate the language-owned observation membrane without owning it."""

    errors: list[str] = []
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    required = ("schema_version", "identity", "execution_identity", "policy", "completeness", "frames", "values", "effects", "events")
    errors.extend(f"{label} missing required field {field!r}" for field in required if field not in value)
    if value.get("schema_version") != LANGUAGE_OBSERVATION_SCHEMA:
        errors.append(f"{label}.schema_version must be {LANGUAGE_OBSERVATION_SCHEMA!r}")
    for field in ("identity", "execution_identity"):
        if not isinstance(value.get(field), str) or not value[field]:
            errors.append(f"{label}.{field} must be a non-empty string")
    policy = value.get("policy")
    if not isinstance(policy, dict):
        errors.append(f"{label}.policy must be an object")
    else:
        if policy.get("schema_version") != "mncs.execution-observation-policy/1":
            errors.append(f"{label}.policy.schema_version is unsupported")
        if policy.get("capture") not in {"none", "failure_only", "selected", "bounded", "diagnostic"}:
            errors.append(f"{label}.policy.capture is unsupported")
        for field, maximum in (("max_events", 4096), ("max_values", 2048), ("max_value_bytes", 65536)):
            bound = policy.get(field)
            if not isinstance(bound, int) or not 0 <= bound <= maximum:
                errors.append(f"{label}.policy.{field} is outside the native bound")
    completeness = value.get("completeness")
    if not isinstance(completeness, dict):
        errors.append(f"{label}.completeness must be an object")
    elif completeness.get("status") not in {"disabled", "not_captured", "complete", "truncated"}:
        errors.append(f"{label}.completeness.status is unsupported")
    for field in ("frames", "values", "effects", "events"):
        if not isinstance(value.get(field), list):
            errors.append(f"{label}.{field} must be an array")
    return errors


def validate_language_source_map(value: Any, *, label: str = "source_map") -> list[str]:
    """Validate source-map shape at the debugger membrane."""

    errors: list[str] = []
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    required = ("schema_version", "identity", "source_identity", "source_profile", "module", "module_identity", "functions", "blocks", "operations")
    errors.extend(f"{label} missing required field {field!r}" for field in required if field not in value)
    if value.get("schema_version") != LANGUAGE_SOURCE_MAP_SCHEMA:
        errors.append(f"{label}.schema_version must be {LANGUAGE_SOURCE_MAP_SCHEMA!r}")
    for field in ("identity", "source_identity", "source_profile", "module", "module_identity"):
        if not isinstance(value.get(field), str) or not value[field]:
            errors.append(f"{label}.{field} must be a non-empty string")
    for field in ("functions", "blocks", "operations"):
        if not isinstance(value.get(field), list):
            errors.append(f"{label}.{field} must be an array")
    return errors


def failure_signature(outcome: dict[str, Any]) -> dict[str, Any]:
    """The conservative equivalence key used by minimization and replay."""

    failure = outcome.get("failure") if isinstance(outcome.get("failure"), dict) else {}
    return {
        "failure_class": outcome.get("failure_class"),
        "status": outcome.get("status"),
        "failure_identity": failure.get("identity"),
        "test_id": outcome.get("test_id"),
    }


def return_digest(values: Any) -> str | None:
    if not isinstance(values, list):
        return None
    return sha256_value(values)


def normalize_status(value: Any) -> str:
    return value if isinstance(value, str) else "unknown"
