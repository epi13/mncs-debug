"""Native diagnostic-coherence policy tests through the shipped adapter."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "bin" / "mncs-debug-coherence"
LANGUAGE_ROOT = ROOT.parent / "mncs-language"
MNCS = os.environ.get("MNCS_BINARY", str(LANGUAGE_ROOT / "target/release/mncs"))

EVIDENCE_EMPTY = {
    "failure_key": "",
    "subject_sha": "",
    "request_digest": "",
    "toolchain_identity": "",
    "depth": "minimal",
    "witness_ref": "",
    "capture_complete": False,
}


def failure(key: str, **overrides) -> dict:
    item: dict = {
        "failure_key": key,
        "failure_class": "test_failure",
        "subject_sha": "sha-1",
        "request_digest": "req-1",
        "toolchain_identity": "tc-1",
        "has_source": True,
        "has_request": True,
        "has_source_binding": True,
        "provider_available": True,
        "requested_depth": "minimal",
        "evidence_present": False,
        "evidence": dict(EVIDENCE_EMPTY),
    }
    item.update(overrides)
    return item


def evidence_for(item: dict, depth: str = "minimal", ref: str = "wit-1") -> dict:
    return {
        "failure_key": item["failure_key"],
        "subject_sha": item["subject_sha"],
        "request_digest": item["request_digest"],
        "toolchain_identity": item["toolchain_identity"],
        "depth": depth,
        "witness_ref": ref,
        "capture_complete": True,
    }


def evaluate(failures: list[dict], max_captures: int = 8, tmp: Path | None = None) -> dict:
    workdir = Path(tmp or os.environ.get("TMPDIR", "/tmp")) / "mncs-debug-coherence-test"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "request.json").write_text(
        json.dumps(
            {
                "schema_version": "mncs.debug-diagnostic-coherence-request/1",
                "max_captures": max_captures,
                "failures": failures,
            }
        ),
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["MNCS_NATIVE_APPLICATION_CACHE_DIR"] = str(workdir / "cache")
    completed = subprocess.run(
        [str(ADAPTER), "request.json", "result.json"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=300,
        env={**environment, "MNCS": MNCS},
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads((workdir / "result.json").read_text(encoding="utf-8"))
    assert result["schema_version"] == "mncs.debug-diagnostic-coherence/1"
    return result


def test_fresh_failure_queues_witness_capture(tmp_path) -> None:
    result = evaluate([failure("fresh")], tmp=tmp_path)
    verdict = result["diagnostics"][0]
    assert verdict["status"] == "capture_required"
    assert verdict["reason"] == "no_evidence"
    assert verdict["operation"] == "witness"
    assert result["capture_queue"] == ["fresh"]


def test_matching_evidence_is_current_without_queue(tmp_path) -> None:
    item = failure("cur")
    result = evaluate(
        [failure("cur", evidence_present=True, evidence=evidence_for(item))],
        tmp=tmp_path,
    )
    verdict = result["diagnostics"][0]
    assert verdict["status"] == "current"
    assert verdict["reason"] == "evidence_current"
    assert verdict["operation"] == "none"
    assert result["capture_queue"] == []
    assert result["summary"]["current"] == 1


def test_changed_input_invalidates_evidence(tmp_path) -> None:
    item = failure("stale")
    changed = failure("stale", subject_sha="sha-2",
                      evidence_present=True, evidence=evidence_for(item))
    result = evaluate([changed], tmp=tmp_path)
    verdict = result["diagnostics"][0]
    assert verdict["status"] == "capture_required"
    assert verdict["reason"] == "input_changed"
    assert result["capture_queue"] == ["stale"]


def test_incomplete_capture_is_recaptured(tmp_path) -> None:
    item = failure("partial")
    recorded = evidence_for(item)
    recorded["capture_complete"] = False
    result = evaluate(
        [failure("partial", evidence_present=True, evidence=recorded)],
        tmp=tmp_path,
    )
    assert result["diagnostics"][0]["status"] == "capture_required"
    assert result["diagnostics"][0]["reason"] == "input_changed"


def test_depth_extension_admits_one_deeper_step(tmp_path) -> None:
    item = failure("ext")
    recorded = evidence_for(item)
    standard = failure("ext", requested_depth="standard",
                       evidence_present=True, evidence=recorded)
    deep = failure("ext", requested_depth="deep",
                   evidence_present=True, evidence=recorded)
    result = evaluate([standard], tmp=tmp_path)
    assert result["diagnostics"][0]["status"] == "extend_required"
    assert result["diagnostics"][0]["reason"] == "depth_exceeded"
    assert result["diagnostics"][0]["operation"] == "trace"
    result = evaluate([deep], tmp=tmp_path)
    assert result["diagnostics"][0]["operation"] == "replay"


def test_sufficient_depth_is_current(tmp_path) -> None:
    item = failure("deep-cur", requested_depth="standard")
    recorded = evidence_for(item, depth="deep")
    result = evaluate(
        [failure("deep-cur", requested_depth="standard",
                 evidence_present=True, evidence=recorded)],
        tmp=tmp_path,
    )
    assert result["diagnostics"][0]["status"] == "current"


def test_undebuggable_matrix_never_queues(tmp_path) -> None:
    result = evaluate(
        [
            failure("infra", failure_class="infrastructure_failure"),
            failure("compile", failure_class="compile_failure"),
            failure("timeout", failure_class="timeout"),
            failure("noprov", provider_available=False),
        ],
        tmp=tmp_path,
    )
    got = {item["failure_key"]: (item["status"], item["reason"])
           for item in result["diagnostics"]}
    assert got["infra"] == ("unsupported", "failure_not_debuggable")
    assert got["compile"] == ("unsupported", "failure_not_debuggable")
    assert got["timeout"] == ("unsupported", "failure_not_debuggable")
    assert got["noprov"] == ("unsupported", "provider_unavailable")
    assert result["capture_queue"] == []
    assert result["summary"]["unsupported"] == 4


def test_missing_evidence_escalates_without_capture(tmp_path) -> None:
    result = evaluate(
        [
            failure("nosrc", has_source=False),
            failure("noreq", has_request=False),
            failure("notc", toolchain_identity=""),
        ],
        tmp=tmp_path,
    )
    got = {item["failure_key"]: (item["status"], item["reason"])
           for item in result["diagnostics"]}
    assert got["nosrc"] == ("escalate", "evidence_missing")
    assert got["noreq"] == ("escalate", "evidence_missing")
    assert got["notc"] == ("escalate", "toolchain_unbound")
    assert result["capture_queue"] == []
    assert result["summary"]["escalated"] == 3


def test_capture_budget_defers_overflow(tmp_path) -> None:
    result = evaluate([failure(f"f-{index}") for index in range(3)],
                      max_captures=2, tmp=tmp_path)
    assert result["capture_queue"] == ["f-0", "f-1"]
    assert result["summary"]["queued"] == 2
    assert result["summary"]["deferred"] == 1
    assert [item["deferred"] for item in result["diagnostics"]] == [False, False, True]


def test_runtime_failure_is_debuggable(tmp_path) -> None:
    result = evaluate([failure("rt", failure_class="runtime_failure")],
                      tmp=tmp_path)
    assert result["diagnostics"][0]["status"] == "capture_required"
