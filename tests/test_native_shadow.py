"""Focused canary for the native bounded Debug planning slice."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _run_native_call(binary: str) -> tuple[dict, dict]:
    """Use the generic MNCS application boundary for the Debug shadow call."""

    command = [
        binary,
        "call",
        str(ROOT / "native/mncs/debug/v1.mncs"),
        "--library",
        str(ROOT.parent / "mncs-language" / "library"),
        "--library",
        str(ROOT.parent / "MNCS-Commons" / "src" / "mncs_commons" / "mesh" / "mncs"),
        "--library",
        str(ROOT.parent / "mncs-test"),
        "--library",
        str(ROOT.parent / "mncs-test" / "native"),
        "--module",
        "mncs.debug.v1",
        "--function",
        "materialize_witness",
        "--args",
        str(ROOT / "tests/fixtures/native-witness-materialization.args.json"),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=305,
    )
    assert completed.returncode == 0, completed.stderr
    call_document = json.loads(completed.stdout)
    return call_document, {
        "schema_version": call_document["schema_version"],
        "subprocess_count": 1,
        "transport": "generic-mncs-call",
    }


def test_native_witness_materialization_and_replay_plan() -> None:
    binary = os.environ.get("MNCS_BINARY", "mncs")
    try:
        document, process_document = _run_native_call(binary)
    except (OSError, subprocess.SubprocessError) as error:
        pytest.skip(f"native MNCS launcher unavailable: {error}")
    assert process_document["subprocess_count"] == 1
    fields = dict(document["call"]["returned"][0]["record"]["fields"])
    assert fields["status"]["finite"]["variant_identity"].endswith("::Ready")
    assert fields["replay_requested"]["boolean"]["value"] is True
    assert fields["retained_bytes"]["integer"]["value"] == 128


def test_native_debug_process_effect_returns_typed_status_and_output() -> None:
    from mncs_debug.native_core import run_process

    binary = Path(os.environ.get("MNCS_BINARY", "mncs"))
    if not binary.is_file():
        pytest.skip("native MNCS launcher unavailable")
    result = run_process(
        mncs_path=binary,
        program="/bin/printf",
        argv=["debug-process"],
        cwd=ROOT,
        environment={},
        stdout_limit=64,
        stderr_limit=64,
        deadline_ms=5_000,
    )
    assert result["success"] is True
    assert result["stdout"] == b"debug-process"
    assert result["timed_out"] is False
    assert result["subprocess_count"] == 1
