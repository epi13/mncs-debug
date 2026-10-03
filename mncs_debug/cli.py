"""JSON-first command line interface for mncs-debug."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .analysis import (
    compiler_phases,
    diagnostic_loop,
    inspect_witness,
    diagnostic_sufficiency,
    load_witness,
    make_session,
    minimize_witness,
    provenance_query,
    replay_execute,
    replay_trace,
    trace_slice,
)
from .capabilities import capability_document
from .native_core import actions_failure_lineage
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
    sha256_file_memoized,
    validate_document,
    validate_witness_integrity,
    write_json,
)
from .runner import RunnerError, build_witness, resolve_mncs, run_process
from .session import SessionError, attach_session, close_session, open_session, query_session
from .live import (
    LiveError,
    attach_session as live_attach,
    bind_stop as live_bind_stop,
    clear_stop as live_clear_stop,
    close_session as live_close,
    continue_session as live_continue,
    default_sessions_root,
    inspect_session as live_inspect,
    resolve_mncs_vm,
    resume_session as live_resume,
    run_pipe as live_run_pipe,
    start_session as live_start,
    step_session as live_step,
    terminate_session as live_terminate,
)
from .remediate import crash_envelope, remediate
from .retain import RetentionError, StoreUnavailable, fetch_live_evidence, fetch_witness, retain_live_evidence, retain_witness
from .targets import TargetError, UnresolvedTarget, record_stop_set, watch_binding, watch_value, witness_stop_set


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
        command.add_argument(
            "--capture",
            choices=("failure-only", "selected", "bounded", "diagnostic", "events"),
            default="bounded",
        )
        command.add_argument("--max-events", type=int, default=512)
        command.add_argument("--max-values", type=int, default=1024)
        command.add_argument("--max-value-bytes", type=int, default=4096)
        command.add_argument(
            "--operation",
            action="append",
            default=[],
            help="semantic operation identity for selected capture; may be repeated",
        )
        command.add_argument("--test-result", help="optional pinned mncs.test-result/1 document")
        command.add_argument("--output", help="write witness JSON to this path")
        command.add_argument("--format", choices=("json", "text"), default="json")

    inspect = sub.add_parser("inspect", help="inspect a witness as structured state")
    inspect.add_argument("witness")
    inspect.add_argument("--event")
    inspect.add_argument("--output")
    inspect.add_argument("--format", choices=("json", "text"), default="json")

    sufficiency = sub.add_parser("sufficiency", help="decide whether current diagnostic evidence is sufficient")
    sufficiency.add_argument("witness")
    sufficiency.add_argument("--inspection")
    sufficiency.add_argument("--mncs")
    sufficiency.add_argument("--core")
    sufficiency.add_argument("--evidence-artifact", action="append", default=[], help="typed projection artifact JSON; may be repeated")
    sufficiency.add_argument("--evidence-operation", choices=("trace", "provenance", "replay", "minimization"))
    sufficiency.add_argument("--output")
    sufficiency.add_argument("--format", choices=("json", "text"), default="json")

    diagnose = sub.add_parser("diagnose", help="run the bounded native evidence-sufficiency loop")
    diagnose.add_argument("witness")
    diagnose.add_argument("--mncs")
    diagnose.add_argument("--core")
    diagnose.add_argument("--max-steps", type=int, default=4)
    diagnose.add_argument("--inspection", help="reuse a previously produced inspection artifact")
    diagnose.add_argument("--evidence-artifact", action="append", default=[], help="reuse a typed projection artifact; may be repeated")
    diagnose.add_argument("--output")
    diagnose.add_argument("--format", choices=("json", "text"), default="json")

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

    session = sub.add_parser("session", help="durable resident inspection sessions with warm queries")
    session_sub = session.add_subparsers(dest="session_command", required=True)

    session_open = session_sub.add_parser("open", help="bind a witness copy to a resident session directory")
    session_open.add_argument("witness")
    session_open.add_argument("--root", required=True, help="session directory; created when missing")
    session_open.add_argument("--force", action="store_true", help="reopen over an existing session")
    session_open.add_argument("--output")
    session_open.add_argument("--format", choices=("json", "text"), default="json")

    session_attach = session_sub.add_parser("attach", help="validate a session and report status plus orientation")
    session_attach.add_argument("--root", required=True)
    session_attach.add_argument("--output")
    session_attach.add_argument("--format", choices=("json", "text"), default="json")

    session_query = session_sub.add_parser("query", help="answer one memoized query against a session")
    session_query.add_argument("--root", required=True)
    session_query.add_argument("--op", required=True, choices=("inspect", "trace", "why", "replay", "sufficiency", "diagnose", "phases"))
    session_query.add_argument("--event", help="inspect: selected event identity")
    session_query.add_argument("--kind", help="trace: event kind filter; phases: one of all, summary, passes, resolutions")
    session_query.add_argument("--operation", help="trace/why: semantic operation identity")
    session_query.add_argument("--value", help="why: native value identity")
    session_query.add_argument("--question", help="why: provenance question")
    session_query.add_argument("--from", dest="start", type=int, help="trace: first sequence")
    session_query.add_argument("--limit", type=int, help="trace: maximum events (1-512)")
    session_query.add_argument("--inspection", help="sufficiency/diagnose: reuse an inspection artifact")
    session_query.add_argument("--evidence-artifact", action="append", default=[], help="sufficiency/diagnose: typed artifact JSON; may be repeated")
    session_query.add_argument("--max-steps", type=int, help="diagnose: bounded loop steps")
    session_query.add_argument("--mncs", help="explicit executable path for native sufficiency/diagnosis")
    session_query.add_argument("--core", help="override the MNCS semantic debug core")
    session_query.add_argument("--output")
    session_query.add_argument("--format", choices=("json", "text"), default="json")

    session_close = session_sub.add_parser("close", help="close a session, optionally removing its directory")
    session_close.add_argument("--root", required=True)
    session_close.add_argument("--wipe", action="store_true", help="remove the session directory after closing")
    session_close.add_argument("--output")
    session_close.add_argument("--format", choices=("json", "text"), default="json")

    live = sub.add_parser("live", help="live VM debug sessions: stop, inspect, step, resume")
    live_sub = live.add_subparsers(dest="live_command", required=True)

    live_start = live_sub.add_parser("start", help="spawn a debug daemon and start one live execution")
    live_start.add_argument("--root", help="session directory; defaults to a fresh directory under the live root")
    live_start.add_argument("--compile", help="self-contained .mncs source to compile in the daemon")
    live_start.add_argument("--artifact", help="frozen mncs.vm.artifact/1 JSON file")
    live_start.add_argument("--callable", help="MODULE::NAME entry point")
    live_start.add_argument("--function", help="function identity entry point")
    live_start.add_argument("--args", help="JSON file with an array of wire execution values")
    live_start.add_argument("--args-json", help="inline JSON array of wire execution values")
    live_start.add_argument("--envelope", help="JSON resource envelope file")
    live_start.add_argument("--providers", help="JSON const-provider map file")
    live_start.add_argument("--capture", choices=("none", "bounded", "selected", "failure-only", "diagnostic"), default="none")
    live_start.add_argument("--max-events", type=int, default=256)
    live_start.add_argument("--max-values", type=int, default=128)
    live_start.add_argument("--max-value-bytes", type=int, default=4096)
    live_start.add_argument("--selected", action="append", default=[], help="selected operation identity; may be repeated")
    live_start.add_argument("--stop-op", action="append", default=[], help="stop before an SSA instruction identity; may be repeated")
    live_start.add_argument("--stop-function", action="append", default=[], help="stop at function entry; may be repeated")
    live_start.add_argument("--stop-effect", choices=("before", "after", "both"), help="stop around provider dispatch")
    live_start.add_argument("--stop-failure", action=argparse.BooleanOptionalAction, default=True, help="suspend before finalizing abnormal outcomes")
    live_start.add_argument("--mncs-vm", help="explicit mncs-vm driver binary")
    live_start.add_argument("--timeout", type=float, default=120.0)
    live_start.add_argument("--output")
    live_start.add_argument("--format", choices=("json", "text"), default="json")

    for name, help_text in (
        ("resume", "resume until the next stop or finish"),
        ("continue", "run until another stop, failure, completion, or bound"),
        ("step-in", "advance to the next observable transition (into calls)"),
        ("step-over", "advance beyond the current operation (over calls)"),
        ("step-out", "advance until the current frame returns"),
        ("terminate", "terminate the execution and finalize terminal evidence"),
    ):
        drive = live_sub.add_parser(name, help=help_text)
        drive.add_argument("--root", required=True)
        drive.add_argument("--timeout", type=float, default=120.0)
        drive.add_argument("--output")
        drive.add_argument("--format", choices=("json", "text"), default="json")

    live_inspect = live_sub.add_parser("inspect", help="read-only inspection of a live or finished session")
    live_inspect.add_argument("--root", required=True)
    live_inspect.add_argument("--view", choices=("stack", "observation", "effects", "stops"), default="stack")
    live_inspect.add_argument("--max-frames", type=int, default=16)
    live_inspect.add_argument("--max-values", type=int, default=64)
    live_inspect.add_argument("--max-value-bytes", type=int, default=4096)
    live_inspect.add_argument("--output")
    live_inspect.add_argument("--format", choices=("json", "text"), default="json")

    live_bind = live_sub.add_parser("bind-stop", help="bind a stop condition on the live execution")
    live_bind.add_argument("--root", required=True)
    live_bind.add_argument("--id", help="stop identity; minted when omitted")
    live_bind.add_argument("--op", help="stop before an SSA instruction identity")
    live_bind.add_argument("--function", help="stop at function entry")
    live_bind.add_argument("--effect", choices=("before", "after", "both"), help="stop around provider dispatch")
    live_bind.add_argument("--failure", action="store_true", help="stop at abnormal terminal boundaries")
    live_bind.add_argument("--output")
    live_bind.add_argument("--format", choices=("json", "text"), default="json")

    live_clear = live_sub.add_parser("clear-stop", help="clear one bound stop condition by id")
    live_clear.add_argument("--root", required=True)
    live_clear.add_argument("--id", required=True)
    live_clear.add_argument("--output")
    live_clear.add_argument("--format", choices=("json", "text"), default="json")

    live_attach = live_sub.add_parser("attach", help="validate a live session and report status plus orientation")
    live_attach.add_argument("--root", required=True)
    live_attach.add_argument("--output")
    live_attach.add_argument("--format", choices=("json", "text"), default="json")

    live_close = live_sub.add_parser("close", help="terminate, shut the daemon down, optionally remove the directory")
    live_close.add_argument("--root", required=True)
    live_close.add_argument("--remove", action="store_true", help="remove the session directory after closing")
    live_close.add_argument("--output")
    live_close.add_argument("--format", choices=("json", "text"), default="json")

    live_retain = live_sub.add_parser("retain", help="retain finished live evidence as a Store object")
    live_retain.add_argument("--root", required=True)
    live_retain.add_argument("--store", required=True)
    live_retain.add_argument("--output")
    live_retain.add_argument("--format", choices=("json", "text"), default="json")

    live_fetch = live_sub.add_parser("fetch", help="fetch retained live evidence by execution identity")
    live_fetch.add_argument("--store", required=True)
    live_fetch.add_argument("--evidence-id", required=True)
    live_fetch.add_argument("--output", required=True)
    live_fetch.add_argument("--format", choices=("json", "text"), default="json")

    live_pipe = live_sub.add_parser(
        "pipe",
        help="serve JSONL session ops on stdin/stdout in one process (no per-query startup)",
    )
    live_pipe.add_argument("--root", required=True)
    live_pipe.add_argument("--timeout", type=float, default=120.0)

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
    import_test.add_argument(
        "--capture",
        choices=("failure-only", "selected", "bounded", "diagnostic", "events"),
        default="bounded",
    )
    import_test.add_argument("--max-events", type=int, default=512)
    import_test.add_argument("--max-values", type=int, default=1024)
    import_test.add_argument("--max-value-bytes", type=int, default=4096)
    import_test.add_argument(
        "--operation",
        action="append",
        default=[],
        help="semantic operation identity for selected capture; may be repeated",
    )
    import_test.add_argument("--output")
    import_test.add_argument("--format", choices=("json", "text"), default="json")

    import_actions = sub.add_parser(
        "import-actions",
        help="ingest canonical Actions artifacts through native Debug",
    )
    import_actions.add_argument("provider_result")
    import_actions.add_argument("provider_check")
    import_actions.add_argument("execution_receipt")
    import_actions.add_argument("evidence_manifest")
    import_actions.add_argument("selected_proof")
    import_actions.add_argument("--mncs")
    import_actions.add_argument("--timeout", type=float, default=120.0)
    import_actions.add_argument("--output")
    import_actions.add_argument("--format", choices=("json", "text"), default="json")

    break_command = sub.add_parser("break", help="resolve a semantic target to a targeted stop set")
    break_command.add_argument("--program", help="MNCS source or manifest (record mode)")
    break_command.add_argument("--request", help="execution request JSON (record mode)")
    break_command.add_argument("--witness", help="resolve against a retained witness without executing")
    target_group = break_command.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--function", help="function name or identity")
    target_group.add_argument("--operation", help="exact semantic operation identity")
    target_group.add_argument("--line", help="1-based source line (source programs only)")
    break_command.add_argument("--mncs", help="explicit executable path for the MNCS runtime")
    break_command.add_argument("--cwd", help="explicit process working directory")
    break_command.add_argument("--timeout", type=float, default=30.0)
    break_command.add_argument("--core", help="override the MNCS semantic debug core")
    break_command.add_argument("--library", action="append", default=[], help="MNCS library root; may be repeated")
    break_command.add_argument("--max-events", type=int, default=512)
    break_command.add_argument("--max-values", type=int, default=1024)
    break_command.add_argument("--max-value-bytes", type=int, default=4096)
    break_command.add_argument("--output", help="write the stop-set JSON to this path")
    break_command.add_argument("--witness-out", help="record mode: write the recorded witness here")
    break_command.add_argument("--format", choices=("json", "text"), default="json")

    phases = sub.add_parser("phases", help="project the compiler pipeline behind a recorded program")
    phases.add_argument("witness")
    phases.add_argument("--kind", choices=("all", "summary", "passes", "resolutions"), default="all")
    phases.add_argument("--mncs")
    phases.add_argument("--timeout", type=float)
    phases.add_argument("--output")
    phases.add_argument("--format", choices=("json", "text"), default="json")

    watch = sub.add_parser("watch", help="resolve a value binding to observations plus origin chain")
    watch.add_argument("witness")
    watch_group = watch.add_mutually_exclusive_group(required=True)
    watch_group.add_argument("--binding", help="runtime value binding name")
    watch_group.add_argument("--value", help="exact native value identity")
    watch.add_argument("--output")
    watch.add_argument("--format", choices=("json", "text"), default="json")

    retain = sub.add_parser("retain", help="retain one witness as a Store object")
    retain.add_argument("witness")
    retain.add_argument("--store", required=True, help="Store root directory")
    retain.add_argument("--output")
    retain.add_argument("--format", choices=("json", "text"), default="json")

    fetch = sub.add_parser("fetch", help="fetch one retained witness by identity")
    fetch.add_argument("--store", required=True, help="Store root directory")
    fetch.add_argument("--witness-id", required=True)
    fetch.add_argument("--output", required=True, help="write the fetched witness here")
    fetch.add_argument("--format", choices=("json", "text"), default="json")

    remediate_command = sub.add_parser("remediate", help="remediate debugger infrastructure (mncs.remediation/1)")
    remediate_command.add_argument("--target", required=True, help="checkout root (repository domain)")
    remediate_command.add_argument("--json", action="store_true", help="print exactly one envelope on stdout")
    remediate_command.add_argument("--dry-run", action="store_true")
    remediate_command.add_argument("--changed-path", action="append", default=[], help="scope-relative hint; may be repeated")
    remediate_command.add_argument("--budget", type=int, default=256)
    remediate_command.add_argument("--mncs", help="explicit executable path for toolchain observations")

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
    if schema == "mncs.debug-sufficiency/1":
        return f"diagnosis: {document.get('status')} (next={document.get('next_operation') or 'stop'})"
    if schema == "mncs.debug.failure-lineage/1":
        return f"failure lineage: {document.get('outcome')} (next={document.get('next_operation') or 'stop'})"
    return schema


def _cmd_capabilities(args: argparse.Namespace) -> int:
    runtime_path = None
    runtime_digest = None
    try:
        runtime = resolve_mncs(args.mncs)
        runtime_path = runtime.as_posix()
        runtime_digest = sha256_file_memoized(runtime)
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
    if args.max_values < 0 or args.max_values > 2048:
        raise ValueError("--max-values must be between 0 and 2048")
    if args.max_value_bytes < 0 or args.max_value_bytes > 65536:
        raise ValueError("--max-value-bytes must be between 0 and 65536")
    if args.capture == "selected" and not args.operation:
        raise ValueError("--capture selected requires at least one --operation")
    witness = build_witness(
        mncs_path=runtime,
        program_path=program,
        request_path=request,
        cwd=cwd,
        timeout_seconds=args.timeout,
        capture_policy=args.capture,
        max_events=args.max_events,
        max_values=args.max_values,
        max_value_bytes=args.max_value_bytes,
        selected_operations=args.operation,
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


def _cmd_sufficiency(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    inspection = load_json(_path(args.inspection)) if args.inspection else inspect_witness(witness)
    if not isinstance(inspection, dict):
        raise ValueError("inspection must be a JSON object")
    artifacts = [load_json(_path(path)) for path in args.evidence_artifact]
    if not all(isinstance(artifact, dict) for artifact in artifacts):
        raise ValueError("evidence artifacts must be JSON objects")
    document = diagnostic_sufficiency(
        witness,
        inspection,
        mncs_path=_runtime(args),
        core_path=_path(args.core) if args.core else None,
        evidence_artifacts=artifacts,
        supplemental_operation=args.evidence_operation,
    )
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS if document.get("status") == "sufficient" else EXIT_FAILURE


def _cmd_diagnose(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    inspection = load_json(_path(args.inspection)) if args.inspection else None
    artifacts = [load_json(_path(path)) for path in args.evidence_artifact]
    if inspection is not None and not isinstance(inspection, dict):
        raise ValueError("inspection must be a JSON object")
    if not all(isinstance(artifact, dict) for artifact in artifacts):
        raise ValueError("evidence artifacts must be JSON objects")
    document = diagnostic_loop(
        witness,
        mncs_path=_runtime(args),
        core_path=_path(args.core) if args.core else None,
        max_steps=args.max_steps,
        initial_inspection=inspection,
        initial_evidence_artifacts=artifacts,
    )
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS if document.get("status") == "sufficient" else EXIT_FAILURE


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


def _cmd_session(args: argparse.Namespace) -> int:
    root = _path(args.root)
    if args.session_command == "open":
        document = open_session(witness_path=_path(args.witness), root=root, force=args.force)
        _write(
            document,
            args.output,
            text=f"session {document['session_id']} open at {root} ({document['failure_class']})"
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS
    if args.session_command == "attach":
        document = attach_session(root)
        memo = document.get("memo", {})
        _write(
            document,
            args.output,
            text=f"session {document['session_id']} {document['state']} "
            f"(queries={document.get('queries', 0)} memo_hits={memo.get('hits', 0)} "
            f"memo_misses={memo.get('misses', 0)} rebuilt={document.get('indexes_rebuilt', False)})"
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS if document.get("state") == "open" else EXIT_FAILURE
    if args.session_command == "query":
        if args.limit is not None and not 1 <= args.limit <= 512:
            raise ValueError("--limit must be between 1 and 512")
        params: dict[str, Any] = {}
        if args.event is not None:
            params["event_id"] = args.event
        for key in ("kind", "operation", "value", "question", "start", "limit", "max_steps"):
            value = getattr(args, key, None)
            if value is not None:
                params[key] = value
        if args.inspection:
            params["inspection"] = load_json(_path(args.inspection))
        if args.evidence_artifact:
            params["evidence_artifacts"] = [load_json(_path(path)) for path in args.evidence_artifact]
        mncs_path = _path(args.mncs) if args.mncs else None
        if mncs_path is None and args.op in {"sufficiency", "diagnose", "phases"}:
            mncs_path = resolve_mncs(None)
        envelope = query_session(
            root,
            args.op,
            params,
            mncs_path=mncs_path,
            core_path=_path(args.core) if args.core else None,
        )
        _write(
            envelope,
            args.output,
            text=f"query {args.op} memo_hit={envelope['memo_hit']} ({_text_summary(envelope['result'])})"
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS
    if args.session_command == "close":
        document = close_session(root, wipe=args.wipe)
        _write(
            document,
            args.output,
            text=f"session {document['session_id']} closed (wiped={document['wiped']})"
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS
    raise ValueError(f"unknown session command: {args.session_command}")


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
    if args.max_events < 1 or args.max_events > 512:
        raise ValueError("--max-events must be between 1 and 512")
    if args.max_values < 0 or args.max_values > 2048:
        raise ValueError("--max-values must be between 0 and 2048")
    if args.max_value_bytes < 0 or args.max_value_bytes > 65536:
        raise ValueError("--max-value-bytes must be between 0 and 65536")
    if args.capture == "selected" and not args.operation:
        raise ValueError("--capture selected requires at least one --operation")
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
            max_values=args.max_values,
            max_value_bytes=args.max_value_bytes,
            selected_operations=args.operation,
            test_result=selected_result,
            core_path=_path(args.core) if args.core else None,
            library_paths=[_path(path) for path in args.library],
        )
    _write(witness, args.output, text=_text_summary(witness) if args.format == "text" else None)
    return EXIT_SUCCESS if witness.get("outcome", {}).get("failure_class") in {"success", "test_failure"} else EXIT_FAILURE


def _cmd_import_actions(args: argparse.Namespace) -> int:
    document = actions_failure_lineage(
        mncs_path=_runtime(args),
        provider_result=_path(args.provider_result),
        provider_check=_path(args.provider_check),
        receipt=_path(args.execution_receipt),
        evidence_manifest=_path(args.evidence_manifest),
        selected_proof=_path(args.selected_proof),
        timeout_seconds=args.timeout,
    )
    _write(document, args.output, text=_text_summary(document) if args.format == "text" else None)
    return EXIT_SUCCESS


def _cmd_break(args: argparse.Namespace) -> int:
    if args.function is not None:
        kind, value = "function", args.function
    elif args.operation is not None:
        kind, value = "operation", args.operation
    else:
        kind, value = "line", args.line
    if args.witness:
        if args.program or args.request:
            raise ValueError("break takes either --witness or --program/--request, not both")
        witness = load_witness(_path(args.witness))
        stop_set = witness_stop_set(witness, kind, value)
    else:
        if not args.program or not args.request:
            raise ValueError("break record mode requires --program and --request")
        if args.max_events < 1 or args.max_events > 512:
            raise ValueError("--max-events must be between 1 and 512")
        if args.max_values < 0 or args.max_values > 2048:
            raise ValueError("--max-values must be between 0 and 2048")
        if args.max_value_bytes < 0 or args.max_value_bytes > 65536:
            raise ValueError("--max-value-bytes must be between 0 and 65536")
        program = _path(args.program)
        try:
            witness, stop_set = record_stop_set(
                mncs_path=_runtime(args),
                program_path=program,
                request_path=_path(args.request),
                cwd=_path(args.cwd) if args.cwd else program.parent,
                kind=kind,
                value=value,
                timeout_seconds=args.timeout,
                max_events=args.max_events,
                max_values=args.max_values,
                max_value_bytes=args.max_value_bytes,
                core_path=_path(args.core) if args.core else None,
                library_paths=[_path(path) for path in args.library],
            )
        except UnresolvedTarget as exc:
            stop_set = exc.stop_set
            witness = None
        if witness is not None:
            witness_out = args.witness_out
            if witness_out is None and args.output:
                derived = _path(args.output)
                witness_out = str(derived.parent / (derived.stem + ".witness.json"))
            if witness_out is None:
                raise ValueError("break record mode requires --witness-out (or --output to derive it)")
            write_json(_path(witness_out), witness)
    resolution = stop_set.get("resolution", {})
    operations = resolution.get("operations", [])
    _write(
        stop_set,
        args.output,
        text=f"stop {kind}={value}: {resolution.get('status')} "
        f"({len(operations)} operations, {stop_set.get('matched_event_count', 0)} matched events, "
        f"{stop_set.get('executions', 0)} executions)"
        if args.format == "text"
        else None,
    )
    return EXIT_SUCCESS if resolution.get("status") in {"resolved", "observed_only", "opaque"} else EXIT_FAILURE


def _cmd_phases(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    document = compiler_phases(
        witness,
        mncs_path=_runtime(args),
        timeout_seconds=args.timeout,
        kind=args.kind,
    )
    _write(
        document,
        args.output,
        text=f"phases: {document.get('pass_count', 0)} passes ({document.get('compilation', {}).get('compilation_status', document.get('status'))})"
        if args.format == "text"
        else None,
    )
    return EXIT_SUCCESS if document.get("status") == "complete" else EXIT_FAILURE


def _cmd_watch(args: argparse.Namespace) -> int:
    witness = load_witness(_path(args.witness))
    if args.binding is not None:
        document = watch_binding(witness, args.binding)
    else:
        document = watch_value(witness, args.value)
    _write(
        document,
        args.output,
        text=f"{len(document.get('claims', []))} provenance claims; completeness={document.get('completeness', {}).get('status')}"
        if args.format == "text"
        else None,
    )
    return EXIT_SUCCESS


def _cmd_retain(args: argparse.Namespace) -> int:
    document = retain_witness(witness_path=_path(args.witness), store_path=_path(args.store))
    _write(
        document,
        args.output,
        text=f"retained {document['witness_id']} at generation {document['store']['generation']} ({document['bytes']} bytes)"
        if args.format == "text"
        else None,
    )
    return EXIT_SUCCESS


def _cmd_fetch(args: argparse.Namespace) -> int:
    output = _path(args.output)
    document = fetch_witness(store_path=_path(args.store), witness_id=args.witness_id, output_path=output)
    _write(
        document,
        None,
        text=f"fetched {document['witness_id']} ({document['bytes']} bytes, integrity={document['integrity']})"
        if args.format == "text"
        else None,
    )
    return EXIT_SUCCESS


def _cmd_remediate(args: argparse.Namespace) -> int:
    try:
        envelope = remediate(
            target=_path(args.target),
            dry_run=args.dry_run,
            changed_paths=args.changed_path,
            budget=args.budget,
            mncs_path=args.mncs,
        )
    except Exception as exc:  # noqa: BLE001 - envelope over exit codes
        envelope = crash_envelope(args.target, args.dry_run, f"{type(exc).__name__}: {exc}")
    if args.json:
        print(json.dumps(envelope, sort_keys=True, ensure_ascii=False))
        return EXIT_SUCCESS
    summary = envelope.get("summary", {})
    print(
        f"remediation: repaired={summary.get('repaired', 0)} reconciled={summary.get('reconciled', 0)} "
        f"degraded={summary.get('degraded', 0)} blockers={summary.get('blockers', 0)} "
        f"dry_run={envelope.get('dry_run', False)}"
    )
    for item in envelope.get("escalations", [])[:8]:
        print(f"  escalation {item.get('severity')}: {item.get('id')}: {item.get('action')}")
    return EXIT_SUCCESS


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
    if operation in {"frames", "backtrace"}:
        document = inspect_witness(witness, event_id=request.get("event_id"))
        document["projection"] = "backtrace"
        return document
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
    if operation in {"inspect-value", "value-origin"}:
        value = request.get("value")
        if not isinstance(value, str) or not value:
            raise ValueError(f"{operation} requires a value identity")
        document = provenance_query(witness, question=request.get("question"), value=value)
        document["projection"] = "value-origin"
        return document
    if operation == "effect-provenance":
        effect = request.get("effect_identity")
        if not isinstance(effect, str) or not effect:
            raise ValueError("effect-provenance requires an effect identity")
        observation = witness.get("runtime", {}).get("observation", {}) if isinstance(witness.get("runtime"), dict) else {}
        effect_item = next(
            (
                item
                for item in observation.get("effects", [])
                if isinstance(item, dict) and item.get("identity") == effect
            ),
            None,
        ) if isinstance(observation, dict) else None
        if effect_item is None:
            raise ValueError(f"effect identity is not present in the witness: {effect}")
        document = provenance_query(
            witness,
            question=request.get("question") or f"effect {effect}",
            operation=effect_item.get("operation"),
        )
        document["projection"] = "effect-provenance"
        document["target"]["effect"] = effect
        return document
    if operation == "break":
        kinds = [("function", request.get("function")), ("operation", request.get("operation_identity")), ("line", request.get("line"))]
        supplied = [(key, value) for key, value in kinds if value is not None and value != ""]
        if len(supplied) != 1:
            raise ValueError("break requires exactly one of function, operation_identity, or line")
        kind, value = supplied[0]
        if kind in {"function", "operation"} and not isinstance(value, str):
            raise ValueError(f"break {kind} must be a string")
        return witness_stop_set(witness, kind, value if isinstance(value, str) else str(value))
    if operation == "watch":
        binding = request.get("binding")
        value = request.get("value")
        if bool(isinstance(binding, str) and binding) == bool(isinstance(value, str) and value):
            raise ValueError("watch requires exactly one of binding or value")
        if isinstance(binding, str) and binding:
            return watch_binding(witness, binding)
        return watch_value(witness, value)
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


def _live_event_text(event: dict[str, Any]) -> str:
    if event.get("event") == "stopped":
        stop = event.get("stop", {})
        point = stop.get("safe_point", {})
        reasons = ",".join(
            reason.get("kind", "?") for reason in stop.get("reasons", []) if isinstance(reason, dict)
        )
        return (
            f"stopped #{stop.get('stop_sequence')} at {point.get('kind')} "
            f"{(point.get('instruction') or point.get('block'))} "
            f"(depth={point.get('depth')} reasons={reasons})"
        )
    outcome = event.get("outcome", {})
    return f"finished: {outcome.get('kind')}"


def _cmd_live(args: argparse.Namespace) -> int:
    command = args.live_command
    if command == "start":
        if bool(args.callable) == bool(args.function):
            raise ValueError("live start needs exactly one of --callable or --function")
        if args.callable:
            if "::" not in args.callable:
                raise ValueError("live start --callable needs MODULE::NAME")
            module, name = args.callable.split("::", 1)
            target: dict[str, Any] = {"module": module, "name": name}
        else:
            target = {"function": args.function}
        if args.args and args.args_json:
            raise ValueError("live start takes at most one of --args or --args-json")
        arguments: list[Any] = []
        if args.args:
            loaded = load_json(_path(args.args))
            if not isinstance(loaded, list):
                raise ValueError("live start --args must hold a JSON array")
            arguments = loaded
        elif args.args_json:
            loaded = json.loads(args.args_json)
            if not isinstance(loaded, list):
                raise ValueError("live start --args-json must hold a JSON array")
            arguments = loaded
        envelope = load_json(_path(args.envelope)) if args.envelope else None
        providers = load_json(_path(args.providers)) if args.providers else None
        stops: list[dict[str, Any]] = []
        for index, instruction in enumerate(args.stop_op):
            stops.append({"id": f"op:{index}", "target": {"kind": "operation", "instruction": instruction}})
        for index, function in enumerate(args.stop_function):
            stops.append({"id": f"function:{index}", "target": {"kind": "function", "function": function}})
        if args.stop_effect:
            stops.append({"id": "effect", "target": {"kind": "effect_boundary", "phase": args.stop_effect}})
        capture = "failure_only" if args.capture == "failure-only" else args.capture
        root = _path(args.root) if args.root else default_sessions_root() / f"live-{os.getpid()}-{int(time.time())}"
        document = live_start(
            root=root,
            vm_path=resolve_mncs_vm(args.mncs_vm),
            target=target,
            arguments=arguments,
            envelope=envelope,
            providers=providers,
            artifact_path=_path(args.artifact) if args.artifact else None,
            compile_path=_path(args.compile) if args.compile else None,
            capture=capture,
            max_events=args.max_events,
            max_values=args.max_values,
            max_value_bytes=args.max_value_bytes,
            selected_operations=args.selected,
            stops=stops,
            stop_on_abnormal_terminal=args.stop_failure,
            timeout_seconds=args.timeout,
        )
        _write(
            document,
            args.output,
            text=f"live session {document['session']['session_id']} at {root}: {_live_event_text(document['event'])}"
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS
    root = _path(args.root)
    if command == "pipe":
        return live_run_pipe(root, sys.stdin, sys.stdout, timeout_seconds=args.timeout)
    if command in ("resume", "continue"):
        document = live_resume(root, args.timeout) if command == "resume" else live_continue(root, args.timeout)
        _write(document, args.output, text=_live_event_text(document["event"]) if args.format == "text" else None)
        return EXIT_SUCCESS
    if command in ("step-in", "step-over", "step-out"):
        mode = {"step-in": "in", "step-over": "over", "step-out": "out"}[command]
        document = live_step(root, mode, args.timeout)
        _write(document, args.output, text=_live_event_text(document["event"]) if args.format == "text" else None)
        return EXIT_SUCCESS
    if command == "terminate":
        document = live_terminate(root, args.timeout)
        _write(document, args.output, text=_live_event_text(document["event"]) if args.format == "text" else None)
        return EXIT_SUCCESS
    if command == "inspect":
        document = live_inspect(
            root,
            args.view,
            max_frames=args.max_frames,
            max_values=args.max_values,
            max_value_bytes=args.max_value_bytes,
        )
        if args.format == "text":
            if args.view == "stack":
                frames = document.get("stack", {}).get("frames", [])
                text = f"{len(frames)} frames; current={frames[0].get('function') if frames else None}"
            elif args.view == "stops":
                text = f"{len(document.get('stops', []))} stops"
            elif args.view == "effects":
                text = f"{len(document.get('effects', []))} effects"
            else:
                observation = document.get("observation", {}) or {}
                text = f"{len(observation.get('events', []))} events, {len(observation.get('values', []))} values"
        else:
            text = None
        _write(document, args.output, text=text)
        return EXIT_SUCCESS
    if command == "bind-stop":
        chosen = [args.op is not None, args.function is not None, args.effect is not None, args.failure]
        if sum(chosen) != 1:
            raise ValueError("live bind-stop needs exactly one of --op, --function, --effect, --failure")
        if args.op is not None:
            target = {"kind": "operation", "instruction": args.op}
        elif args.function is not None:
            target = {"kind": "function", "function": args.function}
        elif args.effect is not None:
            target = {"kind": "effect_boundary", "phase": args.effect}
        else:
            target = {"kind": "failure_or_trap"}
        document = live_bind_stop(root, target, args.id)
        _write(
            document,
            args.output,
            text=f"bound {document['condition']['id']}" if args.format == "text" else None,
        )
        return EXIT_SUCCESS
    if command == "clear-stop":
        document = live_clear_stop(root, args.id)
        _write(
            document,
            args.output,
            text=f"cleared={document['cleared']}" if args.format == "text" else None,
        )
        return EXIT_SUCCESS
    if command == "attach":
        document = live_attach(root)
        _write(
            document,
            args.output,
            text=(
                f"live session {document.get('session_id')} {document.get('state')} "
                f"(stale={document.get('stale')} stops={document.get('stop_count')})"
                + (f" reason={document.get('stale_reason')}" if document.get("stale") else "")
            )
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS if not document.get("stale") else EXIT_FAILURE
    if command == "close":
        document = live_close(root, remove=args.remove)
        _write(
            document,
            args.output,
            text=f"closed (terminated={document['terminated']} removed={document['removed']})"
            if args.format == "text"
            else None,
        )
        return EXIT_SUCCESS
    if command == "retain":
        finish_path = root / "finish.json"
        if not finish_path.exists():
            raise ValueError(f"session at {root} has no finish.json; only finished sessions retain evidence")
        document = retain_live_evidence(evidence_path=finish_path, store_path=_path(args.store))
        _write(
            document,
            args.output,
            text=f"retained {document['retention_id']} ({document['bytes']} bytes)" if args.format == "text" else None,
        )
        return EXIT_SUCCESS
    if command == "fetch":
        document = fetch_live_evidence(
            store_path=_path(args.store), evidence_id=args.evidence_id, output_path=_path(args.output)
        )
        _write(
            document,
            None,
            text=f"fetched {document['bytes']} bytes to {args.output}" if args.format == "text" else None,
        )
        return EXIT_SUCCESS
    raise ValueError(f"unknown live command {command!r}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        handlers: dict[str, Callable[[argparse.Namespace], int]] = {
            "capabilities": _cmd_capabilities,
            "record": _cmd_record,
            "run": _cmd_record,
            "inspect": _cmd_inspect,
            "sufficiency": _cmd_sufficiency,
            "diagnose": _cmd_diagnose,
            "trace": _cmd_trace,
            "why": _cmd_why,
            "open": _cmd_open,
            "session": _cmd_session,
            "live": _cmd_live,
            "break": _cmd_break,
            "watch": _cmd_watch,
            "phases": _cmd_phases,
            "retain": _cmd_retain,
            "fetch": _cmd_fetch,
            "remediate": _cmd_remediate,
            "replay": _cmd_replay,
            "minimize": _cmd_minimize,
            "validate": _cmd_validate,
            "import-test": _cmd_import_test,
            "import-actions": _cmd_import_actions,
            "export": _cmd_export,
            "api": _cmd_api,
            "provider": _cmd_api,
        }
        return handlers[args.command](args)
    except (RunnerError, SessionError, LiveError, TargetError, RetentionError, StoreUnavailable, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"mncs-debug: {exc}", file=sys.stderr)
        return EXIT_INVALID_INVOCATION if isinstance(exc, (SessionError, TargetError, ValueError)) else EXIT_INFRASTRUCTURE


if __name__ == "__main__":
    raise SystemExit(main())
