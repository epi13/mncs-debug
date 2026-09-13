#!/usr/bin/env python3
"""Measure the bounded bootstrap collector against direct MNCS execution."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mncs_debug.protocol import identity, sha256_file, write_json  # noqa: E402
from mncs_debug.runner import resolve_mncs  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--mncs")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output", type=Path)
    return parser


def _timed(command: list[str], cwd: Path, timeout: float) -> tuple[float, int | None]:
    started = time.perf_counter()
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
        return (time.perf_counter() - started) * 1000.0, None
    return (time.perf_counter() - started) * 1000.0, completed.returncode


def main() -> int:
    args = _parser().parse_args()
    if not 1 <= args.iterations <= 50:
        raise SystemExit("--iterations must be between 1 and 50")
    program = args.program.expanduser().resolve()
    request = args.request.expanduser().resolve()
    runtime = resolve_mncs(args.mncs)
    direct: list[float] = []
    recorded: list[float] = []
    direct_codes: list[int | None] = []
    recorded_codes: list[int | None] = []
    launcher = ROOT / "bin" / "mncs-debug"
    with tempfile.TemporaryDirectory(prefix="mncs-debug-overhead-") as directory:
        output = Path(directory) / "witness.json"
        for _ in range(args.iterations):
            elapsed, code = _timed(
                [os.fspath(runtime), "execute", os.fspath(program), os.fspath(request)],
                program.parent,
                args.timeout,
            )
            direct.append(elapsed)
            direct_codes.append(code)
            elapsed, code = _timed(
                [
                    sys.executable,
                    os.fspath(launcher),
                    "record",
                    os.fspath(program),
                    os.fspath(request),
                    "--mncs",
                    os.fspath(runtime),
                    "--output",
                    os.fspath(output),
                ],
                program.parent,
                args.timeout,
            )
            recorded.append(elapsed)
            recorded_codes.append(code)

    direct_median = statistics.median(direct)
    recorded_median = statistics.median(recorded)
    material = {
        "program_sha256": sha256_file(program),
        "request_sha256": sha256_file(request),
        "runtime_sha256": sha256_file(runtime),
        "iterations": args.iterations,
        "direct_milliseconds": direct,
        "record_milliseconds": recorded,
    }
    document = {
        "schema_version": "mncs.debug-overhead/1",
        "protocol_version": 1,
        "measurement_id": identity("overhead", material),
        "program": {"path": program.as_posix(), "sha256": material["program_sha256"]},
        "request": {"path": request.as_posix(), "sha256": material["request_sha256"]},
        "runtime": {"path": runtime.as_posix(), "sha256": material["runtime_sha256"]},
        "iterations": args.iterations,
        "direct": {"milliseconds": direct, "median": direct_median, "returncodes": direct_codes},
        "record": {"milliseconds": recorded, "median": recorded_median, "returncodes": recorded_codes},
        "median_overhead": {
            "milliseconds": recorded_median - direct_median,
            "ratio": (recorded_median / direct_median) if direct_median else None,
        },
        "interpretation": "bootstrap process/static-evidence collection overhead; not a native in-runtime tracing benchmark",
        "boundedness": {
            "trace_events": 512,
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
