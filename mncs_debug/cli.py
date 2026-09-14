"""JSON-first command line interface for mncs-debug."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from .analysis import (
    inspect_witness,
    load_witness,
    make_session,
    minimize_witness,
    provenance_query,
    replay_execute,
    replay_trace,
    trace_slice,
)
from .capabilities import capability_document
from .protocol import (
    API_SCHEMA,
    CAPABILITIES_SCHEMA,
    PROTOCOL_VERSION,
    VALIDATION_SCHEMA,
    WITNESS_SCHEMA,
    bounded_text,
    file_artifact,
    load_json,
    sha256_file,
    validate_document,
    validate_witness_integrity,
    write_json,
)
from .runner import RunnerError, build_witness, resolve_mncs, run_process


EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_INVALID_INVOCATION = 2
EXIT_INFRASTRUCTURE = 3


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _write(value: Any, output: str | None, *, text: str | None = None) -> None:
    if output:
        write_json(_path(output), value)
        if text:
            print(text)
        return
    if text:
        print(text)
        return
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _runtime(args: argparse.Namespace) -> Path:
    return resolve_mncs(getattr(args, "mncs", None))


def _add_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mncs", help="explicit executable path for the MNCS runtime")
    parser.add_argument("--cwd", help="explicit process working directory")
    parser.add_argument("--timeout", type=float, default=30.0, help="bounded runtime timeout in seconds")
    parser.add_argument("--core", help="override the MNCS semantic debug core")
    parser.add_argument("--library", action="append", default=[], help="MNCS library root; may be repeated")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mncs-debug",
        description="Canonical MNCS structured debugging, tracing, replay, and failure analysis.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    capabilities = sub.add_parser("capabilities", help="report truthful runtime/debugger capabilities")
    capabilities.add_argument("--mncs")
    capabilities.add_argument("--output")
    capabilities.add_argument("--format", choices=("json", "text"), default="json")

    for name in ("record", "run"):
        command = sub.add_parser(name, help="execute one MNCS request and preserve a debug witness")
        command.add_argument("program", help="MNCS source or semantic program manifest")
        command.add_argument("request", help="execution request JSON")
        _add_runtime_options(command)
        command.add_argument("--capture", choices=("failure-only", "bounded", "events"), default="bounded")
        command.add_argument("--max-events", type=int, default=512)
        command.add_argument("--test-result", help="optional pinned mncs.test-result/1 document")
        command.add_argument("--output", help="write witness JSON to this path")
        command.add_argument("--format", choices=("json", "text"), default="json")

    inspect = sub.add_parser("inspect", help="inspect a witness as structured state")
    inspect.add_argument("witness")
    inspect.add_argument("--event")
    inspect.add_argument("--output")
    inspect.add_argument("--format", choices=("json", "text"), default="json")

    trace = sub.add_parser("trace", help="return a bounded trace or trace slice")
    trace.add_argument("witness")
    trace.add_argument("--kind")
    trace.add_argument("--operation")
    trace.add_argument("--from", dest="start", type=int)
    trace.add_argument("--limit", type=int, default=256)
    trace.add_argument("--output")
    trace.add_argument("--format", choices=("json", "text"), default="json")

    why = sub.add_parser("why", help="query partial causal/provenance evidence")
    why.add_argument("witness")
    why.add_argument("--operation")
    why.add_argument("--value")
    why.add_argument("--question")
    why.add_argument("--output")
    why.add_argument("--format", choices=("json", "text"), default="json")

    open_command = sub.add_parser("open", help="open an immutable inspection session")
    open_command.add_argument("witness")
    open_command.add_argument("--output")
    open_command.add_argument("--format", choices=("json", "text"), default="json")

    replay = sub.add_parser("replay", help="inspect a trace or boundedly re-execute a witness")
    replay.add_argument("witness")
    replay.add_argument("--mode", choices=("trace", "reexecute"), default="trace")
    replay.add_argument("--mncs")
    replay.add_argument("--timeout", type=float)
    replay.add_argument("--deterministic", action="store_true")
    replay.add_argument("--output")
    replay.add_argument("--format", choices=("json", "text"), default="json")

    minimize = sub.add_parser("minimize", help="conservatively reduce integer request inputs")
    minimize.add_argument("witness")
    minimize.add_argument("--max-attempts", type=int, default=32)
    minimize.add_argument("--mncs")
    minimize.add_argument("--timeout", type=float)
    minimize.add_argument("--output", help="write the reduced witness")
    minimize.add_argument("--report", help="write the minimization report")
    minimize.add_argument("--format", choices=("json", "text"), default="json")

    validate = sub.add_parser("validate", help="validate a debug artifact or an MNCS program")
    validate.add_argument("artifact")
    validate.add_argument("--mncs")
    validate.add_argument("--output")
    validate.add_argument("--format", choices=("json", "text"), default="json")

    import_test = sub.add_parser("import-test", help="turn one mncs-test result into a debug witness")
    import_test.add_argument("result", help="mncs.test-result/1 JSON")
    import_test.add_argument("--test-id")
    _add_runtime_options(import_test)
    import_test.add_argument("--capture", choices=("failure-only", "bounded", "events"), default="bounded")
    import_test.add_argument("--max-events", type=int, default=512)
    import_test.add_argument("--output")
    import_test.add_argument("--format", choices=("json", "text"), default="json")

    export = sub.add_parser("export", help="export a witness projection for another consumer")
    export.add_argument("witness")
    export.add_argument("--kind", choices=("witness", "trace", "inspection", "provenance"), default="witness")
    export.add_argument("--operation")
    export.add_argument("--value")
    export.add_argument("--output")

    for name in ("api", "provider"):
        api = sub.add_parser(name, help="serve the Forge-ready mncs.debug-api/1 interface")
        api.add_argument("--request", help="one API request JSON")
        api.add_argument("--stdio", action="store_true", help="read newline-delimited API requests from stdin")

    return parser


def _text_summary(document: dict[str, Any]) -> str:
    schema = document.get("schema_version", "document")
    if schema == WITNESS_SCHEMA:
        outcome = document.get("outcome", {})
        return f"{document.get('witness_id')}: {outcome.get('failure_class')} ({outcome.get('status')})"
    if schema == CAPABILITIES_SCHEMA:
        counts: dict[str, int] = {}
        for item in document.get("capabilities", []):
            state = item.get("state", "unknown") if isinstance(item, dict) else "unknown"
            counts[state] = counts.get(state, 0) + 1
        return "mncs-debug capabilities: " + ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
    if schema == VALIDATION_SCHEMA:
        return f"validation: {'valid' if document.get('valid') else 'invalid'} ({document.get('kind')})"
    if schema == "mncs.debug-replay/1":
        return f"replay: {document.get('status')} ({document.get('guarantee')})"
    return schema


def _cmd_capabilities(args: argparse.Namespace) -> int:
    runtime_path = None
    runtime_digest = None
    try:
        runtime = resolve_mncs(args.mncs)
        runtime_path = runtime.as_posix()
        runtime_digest = sha256_file(runtime)
    except RunnerError:
        pass
    document = capability_document(runtime_path=runtime_path, runtime_digest=runtime_digest)
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS


def _cmd_record(args: argparse.Namespace) -> int:
    program = _path(args.program)
    request = _path(args.request)
    runtime = _runtime(args)
    cwd = _path(args.cwd) if args.cwd else program.parent
    test_result = load_json(_path(args.test_result)) if args.test_result else None
    if args.max_events < 1 or args.max_events > 512:
        raise ValueError("--max-events must be between 1 and 512")
    witness = build_witness(
        mncs_path=runtime,
        program_path=program,
        request_path=request,
        cwd=cwd,
        timeout_seconds=args.timeout,
        capture_policy=args.capture,
        max_events=args.max_events,
        test_result=test_result,
        core_path=_path(args.core) if args.core else None,
        library_paths=[_path(path) for path in args.library],
    )
    _write(witness, args.output, text=_text_summary(witness) if args.format == "text" else None)
    return EXIT_SUCCESS if witness.get("outcome", {}).get("failure_class") in {"success", "test_failure"} else EXIT_FAILURE


def _cmd_inspect(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    document = inspect_witness(witness, event_id=args.event)
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS


def _cmd_trace(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    if args.limit < 1 or args.limit > 512:
        raise ValueError("--limit must be between 1 and 512")
    document = trace_slice(
        witness,
        kind=args.kind,
        operation=args.operation,
        start=args.start,
        limit=args.limit,
    )
    _write(document, args.output, text=f"{len(document.get('events', []))} events from {document.get('slice_of')}" if args.format == "text" else None)
    return EXIT_SUCCESS


def _cmd_why(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    document = provenance_query(witness, question=args.question, value=args.value, operation=args.operation)
    _write(document, args.output, text=f"{len(document.get('claims', []))} provenance claims; completeness={document.get('completeness', {}).get('status')}" if args.format == "text" else None)
    return EXIT_SUCCESS


def _cmd_open(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    document = make_session(witness)
    _write(document, args.output, text=f"opened {document['session_id']}" if args.format == "text" else None)
    return EXIT_SUCCESS


def _cmd_replay(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    if args.mode == "trace":
        document = replay_trace(witness)
    else:
        override = _path(args.mncs) if args.mncs else None
        document = replay_execute(
            witness,
            mncs_override=override,
            timeout_seconds=args.timeout,
            deterministic=args.deterministic,
        )
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS if document.get("status") in {"replayed", "reproduced"} else EXIT_FAILURE


def _cmd_minimize(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    if args.max_attempts < 1 or args.max_attempts > 256:
        raise ValueError("--max-attempts must be between 1 and 256")
    reduced, report = minimize_witness(
        witness,
        max_attempts=args.max_attempts,
        mncs_override=_path(args.mncs) if args.mncs else None,
        timeout_seconds=args.timeout,
    )
    if args.output:
        write_json(_path(args.output), reduced)
    if args.report:
        write_json(_path(args.report), report)
    if not args.output and not args.report:
        print(json.dumps({"witness": reduced, "report": report}, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.format == "text":
        print(f"minimize: {report.get('status')} after {report.get('attempts')} attempts")
    return EXIT_SUCCESS if report.get("status") in {"reduced", "no_reduction"} else EXIT_FAILURE


def _external_validate(path: Path, runtime: Path) -> dict[str, Any]:
    observation = run_process([os.fspath(runtime), "validate", os.fspath(path)], cwd=path.parent, timeout_seconds=30.0)
    decoded = observation.json
    valid = bool(isinstance(decoded, dict) and decoded.get("valid") is True)
    return {
        "schema_version": VALIDATION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "validation_id": f"mncs:debug:validation:{sha256_file(path)}",
        "valid": valid,
        "kind": "mncs-program-or-manifest",
        "errors": [] if valid else ["mncs validation did not establish valid=true"],
        "external": decoded,
        "process": {"returncode": observation.returncode, "timed_out": observation.timed_out, "stderr": bounded_text(observation.stderr)},
    }


def _cmd_validate(args: argparse.Namespace) -> int:
    path = _path(args.artifact)
    value = None
    if path.suffix != ".mncs":
        value = load_json(path)
    is_program_manifest = isinstance(value, dict) and value.get("schema_version") == "0.1" and isinstance(value.get("functions"), list)
    if path.suffix == ".mncs" or is_program_manifest:
        document = _external_validate(path, _runtime(args))
    else:
        schema = value.get("schema_version") if isinstance(value, dict) else None
        if schema == WITNESS_SCHEMA:
            errors = validate_witness_integrity(value)
            kind = "witness"
        else:
            errors = validate_document(value)
            kind = "debug-protocol" if isinstance(schema, str) and schema.startswith("mncs.debug-") else "json"
        document = {
            "schema_version": VALIDATION_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "validation_id": f"mncs:debug:validation:{sha256_file(path)}",
            "valid": not errors,
            "kind": kind,
            "errors": errors,
            "artifact": file_artifact(path, "validated-input"),
        }
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS if document["valid"] else EXIT_FAILURE


def _validate_test_result(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("test result must be an object")
    required = ("schema_version", "provider", "verdict", "classification", "tests", "provenance", "artifacts", "reproduction")
    missing = [field for field in required if field not in value]
    if value.get("schema_version") != "mncs.test-result/1" or missing:
        raise ValueError(f"input is not a valid enough mncs.test-result/1 document; missing={missing}")


def _validate_execution_request(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("selected test request must be an object")
    target = value.get("target")
    if (
        value.get("schema_version") != "0.1"
        or not isinstance(target, dict)
        or not isinstance(target.get("module"), str)
        or not isinstance(target.get("function"), str)
        or not isinstance(value.get("arguments"), list)
        or not isinstance(value.get("step_budget"), int)
        or value["step_budget"] < 1
    ):
        raise ValueError("selected test request is not a canonical 0.1 execution request")


def _cmd_import_test(args: argparse.Namespace) -> int:
    result_path = _path(args.result)
    result = load_json(result_path)
    _validate_test_result(result)
    tests = result.get("tests") if isinstance(result.get("tests"), list) else []
    selected = None
    if args.test_id:
        selected = next((item for item in tests if isinstance(item, dict) and item.get("id") == args.test_id), None)
    else:
        selected = next((item for item in tests if isinstance(item, dict) and item.get("verdict") == "FAIL"), None)
        selected = selected or next((item for item in tests if isinstance(item, dict)), None)
    if not isinstance(selected, dict):
        raise ValueError("test result contains no selectable test")
    source = selected.get("source")
    request_value = selected.get("request")
    if not isinstance(source, str) or not source:
        raise ValueError("selected test has no source path")
    program = _path(source) if Path(source).is_absolute() else (result_path.parent / source).resolve()
    if not isinstance(request_value, dict):
        raise ValueError("selected test has no embedded execution request; future mncs-test must supply one")
    _validate_execution_request(request_value)
    with tempfile.TemporaryDirectory(prefix="mncs-debug-test-import-") as directory:
        request_path = Path(directory) / "request.json"
        request_path.write_text(json.dumps(request_value), encoding="utf-8")
        selected_result = dict(result)
        selected_result["test_id"] = selected.get("id")
        selected_result["selected_test"] = selected
        selected_result["test_result_artifact"] = file_artifact(
            result_path, "mncs-test-result", relative_to=result_path.parent
        )
        witness = build_witness(
            mncs_path=_runtime(args),
            program_path=program,
            request_path=request_path,
            cwd=_path(args.cwd) if args.cwd else program.parent,
            timeout_seconds=args.timeout,
            capture_policy=args.capture,
            max_events=args.max_events,
            test_result=selected_result,
            core_path=_path(args.core) if args.core else None,
            library_paths=[_path(path) for path in args.library],
        )
    _write(witness, args.output, text=_text_summary(witness) if args.format == "text" else None)
    return EXIT_SUCCESS if witness.get("outcome", {}).get("failure_class") in {"success", "test_failure"} else EXIT_FAILURE


def _cmd_export(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    if args.kind == "witness":
        value = witness
    elif args.kind == "trace":
        value = trace_slice(witness, operation=args.operation)
    elif args.kind == "inspection":
        value = inspect_witness(witness)
    else:
        value = provenance_query(witness, value=args.value, operation=args.operation)
    _write(value, args.output)
    return EXIT_SUCCESS


def _load_api_witness(request: dict[str, Any]) -> dict[str, Any]:
    value = request.get("witness")
    if isinstance(value, str):
        return load_witness(_path(value))
    if isinstance(value, dict):
        errors = validate_witness_integrity(value)
        if errors:
            raise ValueError("invalid inline witness: " + "; ".join(errors))
        return value
    raise ValueError("API operation requires witness as a path or inline object")


def _api_one(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema_version") not in {None, API_SCHEMA}:
        raise ValueError(f"API schema must be {API_SCHEMA}")
    operation = request.get("operation")
    if operation == "capabilities":
        return capability_document()
    witness = _load_api_witness(request)
    if operation == "open":
        return make_session(witness)
    if operation == "inspect":
        return inspect_witness(witness, event_id=request.get("event_id"))
    if operation == "trace":
        limit = int(request.get("limit", 256))
        if not 1 <= limit <= 512:
            raise ValueError("API trace limit must be between 1 and 512")
        return trace_slice(
            witness,
            kind=request.get("kind"),
            operation=request.get("operation_identity"),
            start=request.get("start"),
            limit=limit,
        )
    if operation == "why":
        return provenance_query(witness, question=request.get("question"), value=request.get("value"), operation=request.get("operation_identity"))
    if operation == "replay":
        if request.get("mode", "trace") == "trace":
            return replay_trace(witness)
        return replay_execute(witness, deterministic=bool(request.get("deterministic")))
    if operation == "minimize":
        max_attempts = int(request.get("max_attempts", 32))
        if not 1 <= max_attempts <= 256:
            raise ValueError("API max_attempts must be between 1 and 256")
        _, report = minimize_witness(witness, max_attempts=max_attempts)
        return report
    raise ValueError(f"unsupported debug API operation: {operation!r}")


def _cmd_api(args: argparse.Namespace) -> int:
    if args.stdio:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
                response = _api_one(request)
            except (ValueError, json.JSONDecodeError) as exc:
                response = {"schema_version": API_SCHEMA, "protocol_version": PROTOCOL_VERSION, "error": str(exc)}
            print(json.dumps(response, sort_keys=True, ensure_ascii=False), flush=True)
        return EXIT_SUCCESS
    if not args.request:
        raise ValueError("api requires --request or --stdio")
    request = load_json(_path(args.request))
    if not isinstance(request, dict):
        raise ValueError("API request must be an object")
    print(json.dumps(_api_one(request), indent=2, sort_keys=True, ensure_ascii=False))
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        handlers: dict[str, Callable[[argparse.Namespace], int]] = {
            "capabilities": _cmd_capabilities,
            "record": _cmd_record,
            "run": _cmd_record,
            "inspect": _cmd_inspect,
            "trace": _cmd_trace,
            "why": _cmd_why,
            "open": _cmd_open,
            "replay": _cmd_replay,
            "minimize": _cmd_minimize,
            "validate": _cmd_validate,
            "import-test": _cmd_import_test,
            "export": _cmd_export,
            "api": _cmd_api,
            "provider": _cmd_api,
        }
        return handlers[args.command](args)
    except (RunnerError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"mncs-debug: {exc}", file=sys.stderr)
        return EXIT_INVALID_INVOCATION if isinstance(exc, ValueError) else EXIT_INFRASTRUCTURE


if __name__ == "__main__":
    raise SystemExit(main())
