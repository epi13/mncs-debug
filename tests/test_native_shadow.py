"""Focused canary for the native bounded Debug planning slice."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_native_witness_materialization_and_replay_plan() -> None:
    binary = os.environ.get("MNCS_BINARY", "mncs")
    try:
        completed = subprocess.run(
            [
                binary,
                "call",
                str(ROOT / "native/mncs/debug/v1.mncs"),
                "--module",
                "mncs.debug.v1",
                "--function",
                "materialize_witness",
                "--args",
                str(ROOT / "tests/fixtures/native-witness-materialization.args.json"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        pytest.skip(f"native MNCS launcher unavailable: {error}")
    if completed.returncode != 0 and (
        "unknown command \"call\"" in completed.stderr
        or "invalid choice: 'call'" in completed.stderr
    ):
        pytest.skip("native MNCS launcher predates the generic call entrypoint")
    assert completed.returncode == 0, completed.stderr
    document = json.loads(completed.stdout)
    fields = dict(document["call"]["returned"][0]["record"]["fields"])
    assert fields["status"]["finite"]["variant_identity"].endswith("::Ready")
    assert fields["replay_requested"]["boolean"]["value"] is True
    assert fields["retained_bytes"]["integer"]["value"] == 128
