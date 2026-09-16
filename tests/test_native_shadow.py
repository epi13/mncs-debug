"""Focused canary for the native bounded Debug planning slice."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _run_native_call_through_process(binary: str) -> tuple[dict, dict]:
    """Use the generic bounded process effect for the Debug shadow call."""

    command = [
        binary,
        "process",
        binary,
        "--arg",
        "call",
        "--arg",
        str(ROOT / "native/mncs/debug/v1.mncs"),
        "--arg",
        "--module",
        "--arg",
        "mncs.debug.v1",
        "--arg",
        "--function",
        "--arg",
        "materialize_witness",
        "--arg",
        "--args",
        "--arg",
        str(ROOT / "tests/fixtures/native-witness-materialization.args.json"),
        "--deadline-ms",
        "300000",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=305,
    )
    if completed.returncode != 0 and (
        "unknown command \"process\"" in completed.stderr
        or "invalid choice: 'process'" in completed.stderr
    ):
        pytest.skip("native MNCS launcher predates the generic process capability")
    assert completed.returncode == 0, completed.stderr
    process_document = json.loads(completed.stdout)
    assert process_document["schema_version"] == "mncs.process-result/1"
    assert process_document["success"] is True
    assert process_document["timed_out"] is False
    call_document = json.loads(process_document["stdout"])
    return call_document, process_document


def test_native_witness_materialization_and_replay_plan() -> None:
    binary = os.environ.get("MNCS_BINARY", "mncs")
    try:
        document, process_document = _run_native_call_through_process(binary)
    except (OSError, subprocess.SubprocessError) as error:
        pytest.skip(f"native MNCS launcher unavailable: {error}")
    assert process_document["stdout_truncated"] is False
    fields = dict(document["call"]["returned"][0]["record"]["fields"])
    assert fields["status"]["finite"]["variant_identity"].endswith("::Ready")
    assert fields["replay_requested"]["boolean"]["value"] is True
    assert fields["retained_bytes"]["integer"]["value"] == 128
