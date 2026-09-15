"""Transport adapter around the current `mncs` executable."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capabilities import capability_document
from .native_core import NativeCoreError, decide as native_decide
from .protocol import (
    MAX_STATIC_RECORDS,
    WITNESS_SCHEMA,
    bounded_text,
    embedded_bytes,
    file_artifact,
    host_facts,
    identity,
    load_json,
    return_digest,
    sha256_value,
    sha256_file,
    validate_language_observation,
    validate_language_source_map,
)
from .trace import make_trace


class RunnerError(RuntimeError):
    """The external runtime or an input boundary failed."""


HOST_DEPENDENCIES = [
    {
        "id": "process-supervision",
        "classification": "legitimate platform/bootstrap boundary",
        "files": ["mncs_debug/runner.py"],
        "role": "launch the current external compiler/runtime, enforce an OS timeout, and carry bounded stdout/stderr",
    },
    {
        "id": "artifact-transport",
        "classification": "legitimate platform/bootstrap boundary",
        "files": ["mncs_debug/protocol.py", "mncs_debug/runner.py"],
        "role": "read/write JSON, bounded source/request bytes, directory digests, and canonical SHA-256 identities",
    },
    {
        "id": "compiler-artifact-normalization",
        "classification": "versioned compatibility fallback",
        "files": ["mncs_debug/runner.py", "mncs_debug/trace.py"],
        "role": "normalize legacy JSON manifests that predate mncs.execution-source-map/1 and mncs.execution-observation/1; the native path does not reconstruct compiler facts",
        "pressure_ids": ["MNCS-DEBUG-P-001", "MNCS-DEBUG-P-002", "MNCS-DEBUG-P-003"],
        "native_path": False,
    },
    {
        "id": "debug-query-projection",
        "classification": "canonical debugger semantic consumer",
        "files": ["mncs_debug/analysis.py", "mncs_debug/cli.py"],
        "role": "interpret bounded native execution facts into debugger inspection, backtrace, value-origin, effect-provenance, replay and minimization contracts; unsupported runtime facilities remain explicit",
        "native_path": True,
    },
    {
        "id": "selected-mncs-executable",
        "classification": "independent differential/reference witness",
        "files": ["mncs_debug/runner.py", "mncs_debug/native_core.py"],
        "role": "consume the pinned-campaign reference runtime without modifying sibling repositories",
    },
]


@dataclass
class ProcessObservation:
    command: list[str]
    cwd: Path
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False

    @property
    def json(self) -> Any:
        try:
            return json.loads(self.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None


def resolve_mncs(value: str | None = None) -> Path:
    candidates: list[Path] = []
    if value:
        candidates.append(Path(value))
    env_value = os.environ.get("MNCS")
    if env_value:
        candidates.append(Path(env_value))
    candidates.append(Path(__file__).resolve().parents[2] / "mncs-language/target/debug/mncs")
    which = shutil.which("mncs")
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    raise RunnerError("no executable mncs runtime found; pass --mncs or set MNCS")


def run_process(
    command: list[str],
    cwd: Path,
    timeout_seconds: float,
    environment: dict[str, str] | None = None,
) -> ProcessObservation:
    try:
        completed = subprocess.run(
            command,
            cwd=os.fspath(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcessObservation(
            command=command,
            cwd=cwd,
            returncode=None,
            stdout=exc.stdout or b"",
            stderr=exc.stderr or b"",
            timed_out=True,
        )
    except OSError as exc:
        raise RunnerError(f"unable to start {command[0]!r}: {exc}") from exc
    return ProcessObservation(
        command=command,
        cwd=cwd,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _git_revision(path: Path) -> str | None:
    for candidate in [path, *path.parents]:
        if not (candidate / ".git").exists():
            continue
        try:
            result = subprocess.run(
                ["git", "-C", os.fspath(candidate), "rev-parse", "HEAD"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode == 0:
            return result.stdout.decode("ascii", errors="ignore").strip() or None
    return None


def _language_version(source: bytes) -> str | None:
    match = re.search(rb"\bmncs\s+([0-9]+(?:\.[0-9]+)*)\s*;", source)
    return match.group(1).decode("ascii") if match else None


def _function_locations(source: bytes, names: list[str]) -> dict[str, dict[str, Any]]:
    text = source.decode("utf-8", errors="replace")
    locations: dict[str, dict[str, Any]] = {}
    for name in names:
        match = re.search(rf"\bfn\s+{re.escape(name)}\s*\(", text)
        if not match:
            continue
        line = text.count("\n", 0, match.start()) + 1
        line_start = text.rfind("\n", 0, match.start()) + 1
        locations[name] = {
            "path": None,
            "line": line,
            "column": match.start() - line_start + 1,
            "symbol": name,
            "confidence": "heuristic",
            "mapping": "bounded_function_declaration_scan",
        }
    return locations


def _read_input(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"unable to read {path}: {exc}") from exc


def _runtime_status(execution: Any, validation: Any = None, timed_out: bool = False) -> str:
    """Translate platform execution facts into the native status vocabulary."""

    if timed_out:
        return "BudgetExhausted"
    if isinstance(validation, dict) and validation.get("valid") is False:
        return "CompileFailure"
    if not isinstance(execution, dict):
        return "InfrastructureFailure"
    status = execution.get("status")
    if status == "returned":
        return "Returned"
    if status == "runtime_failure":
        return "RuntimeFailure"
    if status == "unsupported":
        return "Unsupported"
    if status == "budget_exhausted":
        return "BudgetExhausted"
    if status == "invalid_request":
        return "InvalidRequest"
    return "InfrastructureFailure"


def classify_with_native_core(
    *,
    mncs_path: Path,
    execution: Any,
    test_result: dict[str, Any] | None = None,
    validation: Any = None,
    timed_out: bool = False,
    core_path: Path | None = None,
) -> dict[str, Any]:
    """Use native semantics to classify the boundary outcome."""

    runtime_status = _runtime_status(execution, validation, timed_out)
    failure = execution.get("failure") if isinstance(execution, dict) else None
    effect_failed = bool(isinstance(failure, dict) and "effect" in str(failure.get("reason", "")).lower())
    assertion_failed = False
    if test_result:
        assertion_failed = test_result.get("classification") in {"test_failure"} or test_result.get("failure_class") in {
            "assertion",
            "expectation_mismatch",
            "diagnostic_mismatch",
        }
        effect_failed = effect_failed or test_result.get("classification") == "effect_failure"
    try:
        decision = native_decide(
            mncs_path=mncs_path,
            runtime_status=runtime_status,
            assertion_failed=assertion_failed,
            effect_failed=effect_failed,
            core_path=core_path,
        )
    except NativeCoreError as exc:
        return {
            "available": False,
            "error": str(exc),
            "runtime_status": runtime_status,
            "input_assertion_failed": assertion_failed,
            "input_effect_failed": effect_failed,
        }
    return {"available": True, **decision, "runtime_status": runtime_status}


def build_static_index(
    *,
    trace: Any,
    ir: Any,
    ssa: Any,
    study: Any,
    source: dict[str, Any] | None,
    function: str | None,
    validation: Any = None,
) -> dict[str, Any]:
    """Retain a bounded, queryable projection of compiler correspondence."""

    trace = _bounded_trace_document(trace if isinstance(trace, dict) else {})
    ir = ir if isinstance(ir, dict) else {}
    ssa = ssa if isinstance(ssa, dict) else {}
    study = study if isinstance(study, dict) else {}
    ssa_ops: dict[str, dict[str, Any]] = {}
    ssa_functions: dict[str, dict[str, Any]] = {}
    for ssa_function in ssa.get("functions", []) if isinstance(ssa.get("functions"), list) else []:
        if not isinstance(ssa_function, dict):
            continue
        semantic_function = ssa_function.get("semantic_identity")
        if isinstance(semantic_function, str):
            ssa_functions[semantic_function] = ssa_function
        for block in ssa_function.get("blocks", []) if isinstance(ssa_function.get("blocks"), list) else []:
            if not isinstance(block, dict):
                continue
            for instruction in block.get("instructions", []) if isinstance(block.get("instructions"), list) else []:
                if isinstance(instruction, dict) and isinstance(instruction.get("semantic_identity"), str):
                    ssa_ops[instruction["semantic_identity"]] = instruction

    functions: list[dict[str, Any]] = []
    operations: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    for ir_function in ir.get("functions", []) if isinstance(ir.get("functions"), list) else []:
        if not isinstance(ir_function, dict):
            continue
        function_identity = ir_function.get("semantic_identity") or ir_function.get("identity")
        derived_name = function_identity.split("::")[-1] if isinstance(function_identity, str) else function
        function_item = {
            "name": derived_name,
            "identity": function_identity,
            "ir_identity": ir_function.get("identity"),
            "inputs": [item.get("semantic_identity") or item.get("identity") for item in ir_function.get("inputs", []) if isinstance(item, dict)],
            "outputs": [item.get("semantic_identity") or item.get("identity") for item in ir_function.get("outputs", []) if isinstance(item, dict)],
            "failure": ir_function.get("failure"),
        }
        if isinstance(function_identity, str):
            match = ssa_functions.get(function_identity)
            if match:
                function_item["ssa_identity"] = match.get("identity")
        functions.append(function_item)
        for block in ir_function.get("blocks", []) if isinstance(ir_function.get("blocks"), list) else []:
            if not isinstance(block, dict):
                continue
            block_identity = block.get("semantic_identity") or block.get("identity")
            block_item = {
                "identity": block_identity,
                "ir_identity": block.get("identity"),
                "function_identity": function_identity,
                "path": block.get("path"),
            }
            blocks.append(block_item)
            for operation in block.get("operations", []) if isinstance(block.get("operations"), list) else []:
                if not isinstance(operation, dict):
                    continue
                operation_identity = operation.get("semantic_identity") or operation.get("identity")
                if not isinstance(operation_identity, str):
                    continue
                ssa_operation = ssa_ops.get(operation_identity, {})
                operations.append(
                    {
                        "identity": operation_identity,
                        "ir_identity": operation.get("identity"),
                        "ssa_identity": ssa_operation.get("identity"),
                        "function_identity": function_identity,
                        "block_identity": block_identity,
                        "kind": operation.get("kind"),
                        "inputs": [item.get("semantic_identity") or item.get("identity") for item in operation.get("inputs", []) if isinstance(item, dict)],
                        "outputs": [item.get("semantic_identity") or item.get("identity") for item in operation.get("outputs", []) if isinstance(item, dict)],
                        "effects": operation.get("effects", []),
                        "capability_uses": operation.get("capability_uses", []),
                        "obligations": operation.get("obligations", []),
                        "machine_intent": operation.get("machine_intent"),
                        "lowering": operation.get("lowering"),
                        "ssa_failure": ssa_operation.get("failure"),
                    }
                )
    functions = functions[:MAX_STATIC_RECORDS]
    operations = operations[:MAX_STATIC_RECORDS]
    blocks = blocks[:MAX_STATIC_RECORDS]
    return {
        "schema_version": "mncs.debug-static-index/1",
        "program_trace_map": trace,
        "functions": functions,
        "blocks": blocks,
        "operations": operations,
        "compiler_study": {
            key: _bounded_list(study.get(key))
            for key in (
                "identity",
                "compiler_identity",
                "pipeline_identity",
                "compilation_status",
                "stage_fingerprints",
                "pass_executions",
                "semantic_fingerprint",
                "hir_fingerprint",
                "ssa_fingerprint",
                "unresolved_obligations",
                "unresolved_assumptions",
                "name_resolutions",
            )
            if key in study
        },
        "validation": {
            key: validation.get(key)
            for key in ("valid", "errors", "warnings", "summary")
            if isinstance(validation, dict) and key in validation
        },
        "source": source or {},
        "bounded": True,
        "truncated": len(operations) >= MAX_STATIC_RECORDS,
    }


def collect_static(
    *,
    mncs_path: Path,
    program_path: Path,
    cwd: Path,
    target_function: str | None,
    timeout_seconds: float,
    environment: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    documents: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []
    for name in ("validate", "trace", "ir", "ssa"):
        observation = run_process(
            [os.fspath(mncs_path), name, os.fspath(program_path)],
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
        document = observation.json
        if document is None:
            errors.append({"operation": name, "returncode": observation.returncode, "stderr": bounded_text(observation.stderr)})
        else:
            documents[name] = document
    source_bytes = _read_input(program_path)
    source: dict[str, Any] = {
        "path": program_path.as_posix(),
        "sha256": sha256_file(program_path),
        "language_version": _language_version(source_bytes),
        "function_locations": _function_locations(source_bytes, [target_function] if target_function else []),
    }
    if target_function in source["function_locations"]:
        source["function_locations"][target_function]["path"] = program_path.as_posix()
    if program_path.suffix == ".mncs":
        observation = run_process(
            [os.fspath(mncs_path), "source-study", os.fspath(program_path), "--node-id", "mncs-debug"],
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
        study = observation.json
        if study is None:
            errors.append({"operation": "source-study", "returncode": observation.returncode, "stderr": bounded_text(observation.stderr)})
        else:
            documents["study"] = study
    static = build_static_index(
        trace=documents.get("trace"),
        ir=documents.get("ir"),
        ssa=documents.get("ssa"),
        study=documents.get("study"),
        source=source,
        function=target_function,
        validation=documents.get("validate"),
    )
    static["collection_errors"] = errors
    return static, documents


def _bounded_list(value: Any) -> Any:
    if isinstance(value, list):
        return value[:MAX_STATIC_RECORDS]
    return value


def _bounded_trace_document(trace: dict[str, Any]) -> dict[str, Any]:
    bounded = dict(trace)
    for key in ("entries", "events", "operations", "blocks", "functions"):
        value = bounded.get(key)
        if isinstance(value, list) and len(value) > MAX_STATIC_RECORDS:
            bounded[key] = value[:MAX_STATIC_RECORDS]
            bounded[f"{key}_truncated"] = True
    bounded["bounded"] = True
    return bounded


def _compiler_ref(mncs_path: Path) -> dict[str, Any]:
    return {
        "kind": "external-mncs-reference-runtime",
        "binary_path": mncs_path.as_posix(),
        "binary_sha256": sha256_file(mncs_path),
        "observed_checkout_revision": _git_revision(mncs_path),
        "baseline_revision": "1da244a58d656b3058de05d0fc0f799a5e2f0106",
        "baseline_note": "The observability campaign baseline is the verified mncs-language origin/main revision; the selected local binary is an observed executable and is never assumed to be identical without its digest/revision.",
    }


def _program_ref(program_path: Path, execution: Any) -> dict[str, Any]:
    reference = file_artifact(program_path, "program-source-or-manifest")
    if isinstance(execution, dict):
        reference.update(
            {
                "semantic_identity": execution.get("program_identity"),
                "semantic_fingerprint": execution.get("program_fingerprint"),
                "function_identity": execution.get("function_identity"),
            }
        )
    reference["embedded"] = embedded_bytes(_read_input(program_path))
    return reference


def execute_request(
    *,
    mncs_path: Path,
    program_path: Path,
    request_path: Path,
    cwd: Path,
    timeout_seconds: float,
    environment: dict[str, str] | None = None,
) -> tuple[ProcessObservation, Any]:
    request = load_json(request_path)
    observation = run_process(
        [os.fspath(mncs_path), "execute", os.fspath(program_path), os.fspath(request_path)],
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        environment=environment,
    )
    return observation, request


def observe_request(
    *,
    mncs_path: Path,
    program_path: Path,
    request_path: Path,
    cwd: Path,
    timeout_seconds: float,
    capture_policy: str,
    max_events: int,
    max_values: int,
    max_value_bytes: int,
    selected_operations: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> tuple[ProcessObservation, dict[str, Any]]:
    """Run the language-owned observation boundary once.

    The command returns a semantic execution result and a separate bounded
    observation stream. A missing wrapper is an explicit compatibility or
    compile boundary; callers may then use the legacy static fallback.
    """

    request = load_json(request_path)
    command = [
        os.fspath(mncs_path),
        "observe",
        os.fspath(program_path),
        os.fspath(request_path),
        "--capture",
        "bounded" if capture_policy == "events" else capture_policy,
        "--max-events",
        str(max_events),
        "--max-values",
        str(max_values),
        "--max-value-bytes",
        str(max_value_bytes),
    ]
    for operation in selected_operations or []:
        command.extend(("--operation", operation))
    observation = run_process(
        command,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        environment=environment,
    )
    return observation, request


def _native_static_index(
    *,
    document: dict[str, Any],
    program_path: Path,
    target_function: str | None,
) -> dict[str, Any]:
    """Project compiler-owned map facts without re-deriving them."""

    source_map = document.get("source_map")
    source_map = source_map if isinstance(source_map, dict) and source_map.get("schema_version") else None
    functions: list[dict[str, Any]] = []
    function_names: dict[str, str] = {}
    raw_functions = source_map.get("functions") if source_map is not None else None
    for item in raw_functions if isinstance(raw_functions, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("identity"), str):
            continue
        name = item.get("name") if isinstance(item.get("name"), str) else item["identity"]
        function_names[item["identity"]] = name
        functions.append(
            {
                "name": name,
                "identity": item["identity"],
                "semantic_identity": item["identity"],
                "declaration_span": item.get("declaration_span"),
                "test_declaration_identity": item.get("test_declaration_identity"),
                "outputs": [],
            }
        )
    operations: list[dict[str, Any]] = []
    raw_operations = source_map.get("operations") if source_map is not None else None
    for item in raw_operations if isinstance(raw_operations, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("identity"), str):
            continue
        operations.append(
            {
                "identity": item["identity"],
                "semantic_identity": item["identity"],
                "function_identity": item.get("function_identity"),
                "block_identity": item.get("block_identity"),
                "source_span": item.get("source_span"),
                "synthetic": item.get("synthetic", True),
                "correspondence": item.get("correspondence"),
            }
        )
    raw_blocks = source_map.get("blocks") if source_map is not None else None
    blocks = [
        item
        for item in raw_blocks
        if isinstance(item, dict) and isinstance(item.get("identity"), str)
    ] if isinstance(raw_blocks, list) else []
    source_bytes = _read_input(program_path)
    function_locations: dict[str, dict[str, Any]] = {}
    for item in raw_functions if isinstance(raw_functions, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        span = item.get("declaration_span")
        if isinstance(span, dict):
            function_locations[item["name"]] = {
                "path": program_path.as_posix(),
                "line": span.get("line"),
                "column": span.get("column"),
                "start": span.get("start"),
                "end": span.get("end"),
                "symbol": item["name"],
                "confidence": "compiler_exact",
                "mapping": "mncs.execution-source-map/1",
            }
    source = {
        "path": program_path.as_posix(),
        "sha256": sha256_file(program_path),
        "language_version": _language_version(source_bytes),
        "function_locations": function_locations,
        "source_map_identity": source_map.get("identity") if source_map is not None else None,
        "source_map_schema": source_map.get("schema_version") if source_map is not None else None,
        "source_map": source_map,
    }
    return {
        "schema_version": "mncs.debug-static-index/1",
        "program_trace_map": {},
        "functions": functions[:MAX_STATIC_RECORDS],
        "blocks": blocks[:MAX_STATIC_RECORDS],
        "operations": operations[:MAX_STATIC_RECORDS],
        "compiler_study": {},
        "validation": document.get("validation") if isinstance(document.get("validation"), dict) else {"valid": True, "authority": "mncs-observe-front-end"},
        "source": source,
        "source_map": source_map,
        "bounded": True,
        "truncated": len(operations) > MAX_STATIC_RECORDS,
        "collection_errors": [],
        "native_function_names": function_names,
        "target_function": target_function,
        "native_observation": True,
    }


def build_witness(
    *,
    mncs_path: Path,
    program_path: Path,
    request_path: Path,
    cwd: Path,
    timeout_seconds: float = 30.0,
    capture_policy: str = "bounded",
    max_events: int = 512,
    max_values: int | None = None,
    max_value_bytes: int = 4096,
    selected_operations: list[str] | None = None,
    test_result: dict[str, Any] | None = None,
    core_path: Path | None = None,
    library_paths: list[Path] | None = None,
) -> dict[str, Any]:
    program_path = program_path.resolve()
    request_path = request_path.resolve()
    cwd = cwd.resolve()
    mncs_path = mncs_path.resolve()
    libraries = [path.resolve() for path in (library_paths or [])]
    if not libraries and isinstance(test_result, dict):
        provenance = test_result.get("provenance") if isinstance(test_result.get("provenance"), dict) else {}
        raw_libraries = provenance.get("libraries") if isinstance(provenance.get("libraries"), list) else []
        libraries = [
            Path(item["path"]).resolve()
            for item in raw_libraries
            if isinstance(item, dict) and isinstance(item.get("path"), str) and Path(item["path"]).is_dir()
        ]
    environment = dict(os.environ)
    if libraries:
        environment["MNCS_LIBRARY_PATH"] = os.pathsep.join(os.fspath(path) for path in libraries)
    else:
        environment.pop("MNCS_LIBRARY_PATH", None)
    # A first-class test assertion is represented by mncs-test as a returned
    # TestResult, not necessarily as a runtime exception.  `failure-only`
    # therefore needs a debugger-owned effective policy for an imported FAIL;
    # the requested policy remains preserved in the witness so semantic
    # execution identity and capture intent are not conflated.
    requested_capture_policy = capture_policy
    effective_capture_policy = capture_policy
    if (
        capture_policy == "failure-only"
        and isinstance(test_result, dict)
        and test_result.get("verdict") == "FAIL"
    ):
        effective_capture_policy = "bounded"
    observation, request = observe_request(
        mncs_path=mncs_path,
        program_path=program_path,
        request_path=request_path,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        capture_policy=effective_capture_policy,
        max_events=max_events,
        max_values=max_values if max_values is not None else min(max_events * 2, 2048),
        max_value_bytes=max_value_bytes,
        selected_operations=selected_operations,
        environment=environment,
    )
    observed_document = observation.json
    native_candidate = (
        observed_document
        if isinstance(observed_document, dict)
        and isinstance(observed_document.get("execution"), dict)
        and isinstance(observed_document.get("observation"), dict)
        else None
    )
    if native_candidate is not None:
        observation_errors = validate_language_observation(native_candidate["observation"])
        source_map = native_candidate.get("source_map")
        if source_map is not None:
            observation_errors.extend(validate_language_source_map(source_map))
        if observation_errors:
            raise RunnerError("mncs observe emitted an invalid native contract: " + "; ".join(observation_errors))
    native_observation = native_candidate
    if native_observation is not None:
        execution = native_observation["execution"]
    else:
        observation, request = execute_request(
            mncs_path=mncs_path,
            program_path=program_path,
            request_path=request_path,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
        execution = observation.json
    target = request.get("target") if isinstance(request, dict) and isinstance(request.get("target"), dict) else {}
    target_function = target.get("function") if isinstance(target.get("function"), str) else None
    if native_observation is not None:
        static = _native_static_index(
            document=native_observation,
            program_path=program_path,
            target_function=target_function,
        )
        documents = {"observe": native_observation, "validate": static["validation"]}
    else:
        static, documents = collect_static(
            mncs_path=mncs_path,
            program_path=program_path,
            cwd=cwd,
            target_function=target_function,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
    validation = documents.get("validate")
    native_decision = classify_with_native_core(
        mncs_path=mncs_path,
        execution=execution,
        test_result=test_result,
        validation=validation,
        timed_out=observation.timed_out,
        core_path=core_path,
    )
    outcome = _outcome(
        observation=observation,
        execution=execution,
        native_decision=native_decision,
        test_result=test_result,
        validation=validation,
    )
    native_execution_identity = (
        native_observation.get("observation", {}).get("execution_identity")
        if native_observation is not None
        else None
    )
    execution_identity = native_execution_identity if isinstance(native_execution_identity, str) else identity(
        "execution",
        {
            "program_identity": execution.get("program_identity") if isinstance(execution, dict) else None,
            "program_fingerprint": execution.get("program_fingerprint") if isinstance(execution, dict) else None,
            "target": target,
            "request": request,
            "runtime": {"sha256": sha256_file(mncs_path), "revision": _git_revision(mncs_path)},
        },
    )
    source = static.get("source") if isinstance(static.get("source"), dict) else None
    trace_execution = execution if isinstance(execution, dict) else {}
    if isinstance(validation, dict) and validation.get("valid") is False:
        trace_execution = dict(trace_execution)
        trace_execution["status"] = "compile_failure"
        trace_execution["failure"] = outcome.get("failure")
    trace = make_trace(
        execution_identity=execution_identity,
        execution=trace_execution,
        static=static,
        source=source,
        capture_policy=capture_policy,
        max_events=max_events,
        observation=(
            native_observation.get("observation")
            if native_observation
            and isinstance(validation, dict)
            and validation.get("valid") is True
            and isinstance(native_observation.get("observation"), dict)
            and native_observation["observation"].get("events")
            else None
        ),
    )
    process_artifacts = {
        "stdout": bounded_text(observation.stdout),
        "stderr": bounded_text(observation.stderr),
    }
    compiler = _compiler_ref(mncs_path)
    program = _program_ref(program_path, execution)
    request_bytes = _read_input(request_path)
    request_embedding = embedded_bytes(request_bytes)
    request_ref = {
        "path": request_path.as_posix(),
        "sha256": sha256_file(request_path),
        "embedded": request if request_embedding["embedded"] else None,
        "embedding": request_embedding,
    }
    runtime = {
        "kind": "mncs-reference-executor",
        "result_schema": execution.get("schema_version") if isinstance(execution, dict) else None,
        "result_status": execution.get("status") if isinstance(execution, dict) else None,
        "binary_sha256": compiler["binary_sha256"],
        "observed_revision": compiler["observed_checkout_revision"],
        "observation_schema": (
            native_observation.get("observation", {}).get("schema_version")
            if native_observation
            else None
        ),
        "observation_identity": (
            native_observation.get("observation", {}).get("identity")
            if native_observation
            else None
        ),
        # Keep the bounded language-owned stream available to debugger
        # queries. The artifact digest remains the transport identity; this
        # inline copy is the bounded artifact itself.
        "observation": (
            native_observation.get("observation")
            if native_observation
            else None
        ),
        "capture_policy": requested_capture_policy,
        "effective_capture_policy": effective_capture_policy,
    }
    artifacts = [
        {"kind": "program", "sha256": program["sha256"], "path": program["path"]},
        {"kind": "execution-request", "sha256": request_ref["sha256"], "path": request_ref["path"]},
    ]
    if native_observation is not None:
        artifacts.append(
            {
                "kind": "mncs-execution-observation",
                "schema": native_observation.get("observation", {}).get("schema_version"),
                "sha256": sha256_value(native_observation.get("observation")),
                "inline": True,
            }
        )
        if isinstance(native_observation.get("source_map"), dict):
            artifacts.append(
                {
                    "kind": "mncs-execution-source-map",
                    "schema": native_observation["source_map"].get("schema_version"),
                    "sha256": sha256_value(native_observation["source_map"]),
                    "inline": True,
                }
            )
    for name in ("validate", "trace", "ir", "ssa", "study", "observe"):
        document = documents.get(name)
        if document is not None:
            artifacts.append({"kind": f"language-{name}", "sha256": sha256_value(document), "inline": True})
    session_id = identity("session", {"execution_identity": execution_identity, "mode": "record"})
    replay = {
        "kind": "bounded_reexecution",
        "guarantee": "same request is resubmitted to the recorded external executable; deterministic scheduling and effect replay are not guaranteed",
        "program_path": program_path.as_posix(),
        "request_path": request_path.as_posix(),
        "mncs_path": mncs_path.as_posix(),
        "cwd": cwd.as_posix(),
        "timeout_seconds": timeout_seconds,
        "embedded_program": program["embedded"],
        "embedded_request": request_ref["embedded"],
        "libraries": [file_artifact(path, "mncs-library") for path in libraries],
    }
    integration: dict[str, Any] = {}
    if test_result is not None:
        selected_test = test_result.get("selected_test")
        selected_test = selected_test if isinstance(selected_test, dict) else {}
        lineage = selected_test.get("execution_lineage")
        lineage = lineage if isinstance(lineage, dict) else {}
        test_result_artifact = test_result.get("test_result_artifact")
        if not isinstance(test_result_artifact, dict):
            test_result_artifact = {
                "kind": "mncs-test-result",
                "sha256": identity("test-result", test_result),
                "available": False,
                "path": None,
            }
        test_execution = {"test_id": test_result.get("test_id")}
        test_execution.update({
            key: lineage.get(key)
            for key in (
                "test_case_identity",
                "declaration_identity",
                "function_identity",
                "module",
                "subject_identity",
                "execution_identity",
                "observation_identity",
                "oracle_evaluation_identity",
            )
            if lineage.get(key) is not None
        })
        integration = {
            "kind": "mncs-test-result-import",
            "schema_version": test_result.get("schema_version"),
            "provider": test_result.get("provider"),
            "run_id": test_result.get("run_id"),
            "test_id": test_result.get("test_id"),
            "classification": test_result.get("classification"),
            "verdict": test_result.get("verdict"),
            "test_result_reference": test_result_artifact,
            "test_execution": test_execution,
            "request": request_ref,
            "sha256": identity("test-result-import", {
                "reference": test_result_artifact,
                "run_id": test_result.get("run_id"),
                "test_id": test_result.get("test_id"),
                "test_execution": lineage,
            }),
            "result": test_result,
        }
    witness = {
        "schema_version": WITNESS_SCHEMA,
        "protocol_version": 1,
        "witness_id": None,
        "execution_identity": execution_identity,
        "session": {"session_id": session_id, "state": "closed", "mode": "record"},
        "program": program,
        "request": request_ref,
        "compiler": compiler,
        "runtime": runtime,
        "outcome": outcome,
        "trace": trace,
        "static": static,
        "artifacts": artifacts,
        "process": process_artifacts,
        "replay": replay,
        "capabilities": capability_document(
            runtime_path=mncs_path.as_posix(), runtime_digest=compiler["binary_sha256"]
        ),
        "provenance": {
            "host": host_facts(),
            "cwd": cwd.as_posix(),
            "source_revision": _git_revision(program_path),
            "baseline_file": "docs/baseline/revisions.json",
            "transport": "mncs-debug Python launcher",
            "libraries": [file_artifact(path, "mncs-library") for path in libraries],
            "host_dependencies": HOST_DEPENDENCIES,
        },
        "integration": integration,
        "limitations": _limitations(execution, static, observation, native_decision),
    }
    material = dict(witness)
    material.pop("witness_id", None)
    witness["witness_id"] = identity("witness", material)
    return witness


def _outcome(
    *,
    observation: ProcessObservation,
    execution: Any,
    native_decision: dict[str, Any],
    test_result: dict[str, Any] | None,
    validation: Any = None,
) -> dict[str, Any]:
    status = execution.get("status") if isinstance(execution, dict) else None
    failure = execution.get("failure") if isinstance(execution, dict) and isinstance(execution.get("failure"), dict) else None
    if isinstance(validation, dict) and validation.get("valid") is False:
        status = "compile_failure"
        failure = {
            "identity": identity("compiler-diagnostic", validation),
            "reason": "program validation failed",
            "diagnostics": validation.get("errors", []),
        }
    if observation.timed_out:
        status = "budget_exhausted"
    if observation.timed_out:
        failure_class = "timeout_or_budget_exhaustion"
    elif test_result is not None and test_result.get("verdict") == "FAIL":
        failure_class = "test_failure"
    elif native_decision.get("available"):
        failure_class = native_decision.get("outcome")
    elif execution is None:
        failure_class = "infrastructure_bootstrap_failure"
    else:
        failure_class = "infrastructure_bootstrap_failure"
    compile_invalid = isinstance(validation, dict) and validation.get("valid") is False
    returned = [] if compile_invalid else (
        execution.get("returned", []) if isinstance(execution, dict) else []
    )
    outcome = {
        "status": status or "infrastructure_failure",
        "failure_class": failure_class,
        "failure": failure,
        "returned": returned,
        "returned_digest": None if compile_invalid else return_digest(returned),
        "steps": execution.get("steps", 0) if isinstance(execution, dict) else 0,
        "process_exit_code": observation.returncode,
        "timed_out": observation.timed_out,
        "native_decision": native_decision,
    }
    if test_result is not None:
        outcome["test_id"] = test_result.get("test_id")
        outcome["test_failure"] = {
            "classification": test_result.get("classification"),
            "failure_class": test_result.get("failure_class"),
            "verdict": test_result.get("verdict"),
            "failure": test_result.get("failure"),
        }
    return outcome


def _limitations(execution: Any, static: dict[str, Any], observation: ProcessObservation, native_decision: dict[str, Any]) -> list[str]:
    # The native source path is identified by the compiler-owned source map;
    # legacy manifests without source still use the observation stream but
    # cannot resolve operation spans.
    if isinstance(execution, dict) and static.get("native_observation") is True:
        limitations = [
            "Native observation is bounded; omitted values/events are represented by completeness and truncation metadata.",
            "The stream establishes effect lineage, not deterministic replay of scheduler decisions or external state.",
        ]
    else:
        limitations = [
            "The compatibility path does not expose intermediate values, a resumable session, or nested runtime frames.",
            "Operation source locations are unavailable without a compiler-owned source map.",
            "Causal relationships are limited to execution order, operation identity, and static dataflow association.",
        ]
    if observation.timed_out:
        limitations.append("The operating-system timeout interrupted the external process; no deterministic replay claim is made.")
    if static.get("collection_errors"):
        limitations.append("One or more static correspondence commands did not emit structured artifacts.")
    if not native_decision.get("available"):
        limitations.append("The MNCS semantic decision core was unavailable; outcome classification is not semantically established.")
    if isinstance(execution, dict) and execution.get("trace_truncated"):
        limitations.append("The language runtime truncated its bounded execution trace.")
    return limitations
