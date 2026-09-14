#!/usr/bin/env python3
"""Measure execution, native observation, and debugger bootstrap separately.

The old benchmark compared one direct invocation with a multi-process
debugger path and therefore measured bootstrap/static collection as if it were
runtime tracing. This probe keeps those measurements separate. Every mode
still invokes the real executable/provider and every capture remains bounded.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mncs_debug.protocol import identity, sha256_file, write_json  # noqa: E402
from mncs_debug.runner import resolve_mncs  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--mncs")
    parser.add_argument("--iterations", type=int, default=9)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output", type=Path)
    return parser


def _run(command: list[str], cwd: Path, timeout: float) -> int | None:
    try:
        completed = subprocess.run(
            command,
            cwd=os.fspath(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    return completed.returncode


def _timed(command: list[str], cwd: Path, timeout: float) -> tuple[float, int | None]:
    started = time.perf_counter()
    code = _run(command, cwd, timeout)
    return (time.perf_counter() - started) * 1000.0, code


def _timed_many(commands: Iterable[list[str]], cwd: Path, timeout: float) -> tuple[float, int | None]:
    """Time a legacy multi-process bundle as one mode."""

    started = time.perf_counter()
    code: int | None = 0
    for command in commands:
        remaining = max(timeout - (time.perf_counter() - started), 0.001)
        code = _run(command, cwd, remaining)
        if code is None or code != 0:
            break
    return (time.perf_counter() - started) * 1000.0, code


def _percentile(samples: list[float], percentile: float) -> float:
    ordered = sorted(samples)
    if not ordered:
        return math.nan
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def _mode_document(samples: list[float], codes: list[int | None]) -> dict[str, object]:
    return {
        "milliseconds": samples,
        "median": statistics.median(samples),
        "p95": _percentile(samples, 0.95),
        "minimum": min(samples),
        "maximum": max(samples),
        "returncodes": codes,
    }


def main() -> int:
    args = _parser().parse_args()
    if not 3 <= args.iterations <= 50:
        raise SystemExit("--iterations must be between 3 and 50")
    program = args.program.expanduser().resolve()
    request = args.request.expanduser().resolve()
    runtime = resolve_mncs(args.mncs)
    launcher = ROOT / "bin" / "mncs-debug"
    native_core = ROOT / "native/mncs/debug/v1.mncs"

    direct_command = [os.fspath(runtime), "execute", os.fspath(program), os.fspath(request)]
    observe_prefix = [os.fspath(runtime), "observe", os.fspath(program), os.fspath(request)]
    observe_common = ["--max-events", "512", "--max-value-bytes", "4096"]
    modes = {
        "direct_execution": lambda: direct_command,
        "native_observation_disabled": lambda: observe_prefix
        + ["--capture", "none", "--max-values", "0", *observe_common],
        "native_observation_values": lambda: observe_prefix
        + ["--capture", "bounded", "--no-frames", "--no-effects", "--max-values", "1024", *observe_common],
        "native_observation_frames": lambda: observe_prefix
        + ["--capture", "bounded", "--max-values", "0", "--no-effects", *observe_common],
        "native_observation_effects": lambda: observe_prefix
        + ["--capture", "bounded", "--max-values", "0", "--no-frames", *observe_common],
        "native_observation_bounded": lambda: observe_prefix
        + ["--capture", "bounded", "--max-values", "1024", *observe_common],
        "native_observation_diagnostic": lambda: observe_prefix
        + ["--capture", "diagnostic", "--max-values", "1024", *observe_common],
        "native_semantic_core": lambda: [
            os.fspath(runtime),
            "execute",
            os.fspath(native_core),
            "{native_core_request}",
        ],
        "debug_record": lambda: [
            sys.executable,
            os.fspath(launcher),
            "record",
            os.fspath(program),
            os.fspath(request),
            "--mncs",
            os.fspath(runtime),
            "--capture",
            "bounded",
            "--max-events",
            "512",
            "--max-values",
            "1024",
            "--max-value-bytes",
            "4096",
        ],
    }

    mode_samples: dict[str, list[float]] = {name: [] for name in modes}
    mode_codes: dict[str, list[int | None]] = {name: [] for name in modes}
    with tempfile.TemporaryDirectory(prefix="mncs-debug-overhead-") as directory:
        output = Path(directory) / "witness.json"
        native_core_request = Path(directory) / "native-core-request.json"
        native_core_request.write_text(
            json.dumps(
                {
                    "schema_version": "0.1",
                    "target": {"module": "mncs.debug.v1", "function": "decide"},
                    "arguments": [
                        {"integer": {"value": 0, "type": {"bits": 32, "signed": True}}},
                        {"boolean": {"value": False}},
                        {"boolean": {"value": False}},
                    ],
                    "step_budget": 128,
                }
            ),
            encoding="utf-8",
        )
        for _ in range(args.iterations):
            for name, command_factory in modes.items():
                command = [
                    item.replace("{native_core_request}", os.fspath(native_core_request))
                    for item in command_factory()
                ]
                if name == "debug_record":
                    command.extend(["--output", os.fspath(output)])
                elapsed, code = _timed(command, program.parent, args.timeout)
                mode_samples[name].append(elapsed)
                mode_codes[name].append(code)

        legacy_commands = [
            [os.fspath(runtime), "execute", os.fspath(program), os.fspath(request)],
            [os.fspath(runtime), "validate", os.fspath(program)],
            [os.fspath(runtime), "trace", os.fspath(program)],
            [os.fspath(runtime), "ir", os.fspath(program)],
            [os.fspath(runtime), "ssa", os.fspath(program)],
        ]
        if program.suffix.lower() == ".mncs":
            legacy_commands.append([os.fspath(runtime), "source-study", os.fspath(program)])
        legacy_samples: list[float] = []
        legacy_codes: list[int | None] = []
        for _ in range(args.iterations):
            elapsed, code = _timed_many(legacy_commands, program.parent, args.timeout)
            legacy_samples.append(elapsed)
            legacy_codes.append(code)

    modes_document = {
        name: _mode_document(samples, mode_codes[name])
        for name, samples in mode_samples.items()
    }
    modes_document["legacy_static_bundle"] = _mode_document(legacy_samples, legacy_codes)
    direct_median = modes_document["direct_execution"]["median"]
    record_median = modes_document["debug_record"]["median"]
    material = {
        "program_sha256": sha256_file(program),
        "request_sha256": sha256_file(request),
        "runtime_sha256": sha256_file(runtime),
        "iterations": args.iterations,
        "modes": modes_document,
    }
    document = {
        "schema_version": "mncs.debug-overhead/1",
        "protocol_version": 1,
        "measurement_id": identity("overhead", material),
        "program": {"path": program.as_posix(), "sha256": material["program_sha256"]},
        "request": {"path": request.as_posix(), "sha256": material["request_sha256"]},
        "runtime": {"path": runtime.as_posix(), "sha256": material["runtime_sha256"]},
        "iterations": args.iterations,
        # Keep the original fields for consumers of the first benchmark.
        "direct": modes_document["direct_execution"],
        "record": modes_document["debug_record"],
        "median_overhead": {
            "milliseconds": record_median - direct_median,
            "ratio": (record_median / direct_median) if direct_median else None,
        },
        "p95": {
            "direct_execution": modes_document["direct_execution"]["p95"],
            "debug_record": modes_document["debug_record"]["p95"],
            "legacy_static_bundle": modes_document["legacy_static_bundle"]["p95"],
        },
        "modes": modes_document,
        "measurement_model": {
            "native_observation": "one mncs observe process; capture policy and bounds vary by mode",
            "native_semantic_core": "one native mncs execute process for the MNCS-owned debug decision core",
            "debug_record": "one mncs-debug process, one native observe process, one native semantic-core invocation",
            "legacy_static_bundle": "execute plus validate/trace/ir/ssa and source-study when the fixture is source text",
            "interpretation": "process/bootstrap and protocol costs are separate from runtime observation policy cost",
        },
        "interpretation": "Native observation cost is reported separately from legacy static/bootstrap collection; no deterministic replay or unbounded capture is implied.",
        "boundedness": {
            "observation_events": 4096,
            "observation_values": 2048,
            "observation_value_bytes": 65536,
            "debug_trace_events": 512,
            "static_records": 2048,
            "captured_stream_bytes": 65536,
            "embedded_input_bytes": 262144,
        },
    }
    if args.output:
        write_json(args.output.expanduser().resolve(), document)
    else:
        print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
