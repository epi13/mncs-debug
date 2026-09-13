"""Invoke the MNCS-owned debug semantic decision core.

The host adapter converts an external runtime status into a small transport
code. The MNCS source decides the semantic outcome and stop policy. This
module is intentionally boring process transport.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


OUTCOME_NAMES = {
    0: "success",
    1: "compile_failure",
    2: "runtime_failure",
    3: "assertion_failure",
    4: "effect_failure",
    5: "timeout_or_budget_exhaustion",
    6: "unsupported_debug_capability",
    7: "invalid_invocation",
    8: "infrastructure_bootstrap_failure",
    9: "test_failure",
}


class NativeCoreError(RuntimeError):
    pass


def default_core_path() -> Path:
    return Path(__file__).resolve().parents[1] / "native/mncs/debug/v1.mncs"


def _integer(value: Any) -> int | None:
    if isinstance(value, dict):
        item = value.get("integer")
        if isinstance(item, dict) and isinstance(item.get("value"), int):
            return item["value"]
    return None


def _boolean(value: Any) -> bool | None:
    if isinstance(value, dict):
        item = value.get("boolean")
        if isinstance(item, dict) and isinstance(item.get("value"), bool):
            return item["value"]
    return None


def decide(
    *,
    mncs_path: Path,
    status_code: int,
    assertion_failed: bool = False,
    effect_failed: bool = False,
    core_path: Path | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Ask the native core for one decision and return its typed record."""

    core = core_path or default_core_path()
    if not core.exists():
        raise NativeCoreError(f"native debug core is missing: {core}")
    request = {
        "schema_version": "0.1",
        "target": {"module": "mncs.debug.v1", "function": "decide"},
        "arguments": [
            {"integer": {"value": status_code, "type": {"bits": 32, "signed": True}}},
            {"boolean": {"value": assertion_failed}},
            {"boolean": {"value": effect_failed}},
        ],
        "step_budget": 128,
    }
    with tempfile.TemporaryDirectory(prefix="mncs-debug-core-") as directory:
        request_path = Path(directory) / "request.json"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        try:
            completed = subprocess.run(
                [os.fspath(mncs_path), "execute", os.fspath(core), os.fspath(request_path)],
                cwd=os.fspath(core.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NativeCoreError(f"native debug core invocation failed: {exc}") from exc
    try:
        document = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeCoreError(
            f"native debug core did not emit JSON (exit {completed.returncode}): "
            f"{completed.stderr.decode('utf-8', errors='replace')[:400]}"
        ) from exc
    if not isinstance(document, dict) or document.get("status") != "returned":
        raise NativeCoreError(f"native debug core returned non-success execution: {document!r}")
    returned = document.get("returned")
    if not isinstance(returned, list) or len(returned) != 1:
        raise NativeCoreError("native debug core returned an unexpected value shape")
    record = returned[0].get("record") if isinstance(returned[0], dict) else None
    fields = record.get("fields") if isinstance(record, dict) else None
    if not isinstance(fields, list):
        raise NativeCoreError("native debug core returned a non-record decision")
    values: dict[str, Any] = {}
    for pair in fields:
        if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str):
            values[pair[0]] = pair[1]
    outcome_code = _integer(values.get("outcome_code"))
    should_stop = _boolean(values.get("should_stop"))
    if outcome_code is None or should_stop is None or outcome_code not in OUTCOME_NAMES:
        raise NativeCoreError(f"native debug core returned invalid decision fields: {values!r}")
    return {
        "outcome_code": outcome_code,
        "outcome": OUTCOME_NAMES[outcome_code],
        "should_stop": should_stop,
        "native_execution": document,
    }
