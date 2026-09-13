from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mncs_debug.protocol import validate_witness_integrity


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "mncs-debug"
PROGRAM = ROOT / "tests/fixtures/checked-add.mncs.json"
SUCCESS_REQUEST = ROOT / "tests/fixtures/checked-add-success-request.json"
OVERFLOW_REQUEST = ROOT / "tests/fixtures/checked-add-overflow-request.json"
BUDGET_REQUEST = ROOT / "tests/fixtures/checked-add-budget-request.json"
INVALID_PROGRAM = ROOT / "tests/fixtures/invalid-undeclared-effect.mncs.json"
RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))
RUNTIME_AVAILABLE = RUNTIME.is_file() and os.access(RUNTIME, os.X_OK)


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@unittest.skipUnless(RUNTIME_AVAILABLE, "MNCS runtime not available")
class RuntimeCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["MNCS"] = str(RUNTIME)
        return subprocess.run(
            [sys.executable, str(BIN), *arguments],
            cwd=ROOT,
            env=environment,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_success_failure_queries_and_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-test-") as directory:
            root = Path(directory)
            success_path = root / "success.json"
            failure_path = root / "failure.json"
            self.assertEqual(
                self.run_cli("record", str(PROGRAM), str(SUCCESS_REQUEST), "--output", str(success_path)).returncode,
                0,
            )
            failure_run = self.run_cli("record", str(PROGRAM), str(OVERFLOW_REQUEST), "--output", str(failure_path))
            self.assertEqual(failure_run.returncode, 1, failure_run.stderr)
            success = _json(success_path)
            failure = _json(failure_path)
            self.assertEqual(success["outcome"]["failure_class"], "success")
            self.assertEqual(failure["outcome"]["failure_class"], "runtime_failure")
            self.assertEqual(validate_witness_integrity(failure), [])
            self.assertEqual(
                {event["kind"] for event in success["trace"]["events"]},
                {"function_entry", "block_enter", "semantic_operation", "state_transition", "function_exit"},
            )
            self.assertTrue(failure["outcome"]["native_decision"]["should_stop"])
            self.assertEqual(self.run_cli("validate", str(failure_path)).returncode, 0)

            inspection = json.loads(self.run_cli("inspect", str(failure_path)).stdout)
            self.assertEqual(inspection["schema_version"], "mncs.debug-inspection/1")
            trace = json.loads(self.run_cli("trace", str(failure_path), "--kind", "failure").stdout)
            self.assertEqual([event["kind"] for event in trace["events"]], ["failure"])
            why = json.loads(self.run_cli("why", str(failure_path)).stdout)
            self.assertEqual(why["completeness"]["status"], "partial")
            self.assertTrue(any(claim["kind"] == "operation_identity" for claim in why["claims"]))

            trace_replay = json.loads(self.run_cli("replay", str(failure_path), "--mode", "trace").stdout)
            self.assertEqual(trace_replay["status"], "replayed")
            reexecution = json.loads(
                self.run_cli("replay", str(failure_path), "--mode", "reexecute", "--mncs", str(RUNTIME)).stdout
            )
            self.assertEqual(reexecution["status"], "reproduced")
            deterministic = self.run_cli("replay", str(failure_path), "--mode", "reexecute", "--deterministic")
            self.assertEqual(deterministic.returncode, 1)
            self.assertEqual(json.loads(deterministic.stdout)["status"], "blocked")

    def test_nested_static_correspondence_and_minimization(self) -> None:
        nested_program = ROOT / "examples/nested.mncs"
        nested_request = ROOT / "examples/nested-request.json"
        with tempfile.TemporaryDirectory(prefix="mncs-debug-nested-test-") as directory:
            root = Path(directory)
            witness_path = root / "nested.json"
            result = self.run_cli("record", str(nested_program), str(nested_request), "--output", str(witness_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            witness = _json(witness_path)
            self.assertEqual({item["name"] for item in witness["static"]["functions"]}, {"wrapper", "increment"})
            self.assertEqual(witness["static"]["source"]["function_locations"]["wrapper"]["confidence"], "heuristic")
            self.assertTrue(
                any(
                    "increment" in (event.get("location", {}).get("runtime", {}).get("operation") or "")
                    for event in witness["trace"]["events"]
                )
            )

            report_path = root / "min-report.json"
            reduced_path = root / "reduced.json"
            overflow = root / "overflow.json"
            self.assertEqual(self.run_cli("record", str(PROGRAM), str(OVERFLOW_REQUEST), "--output", str(overflow)).returncode, 1)
            minimize = self.run_cli(
                "minimize",
                str(overflow),
                "--max-attempts",
                "2",
                "--output",
                str(reduced_path),
                "--report",
                str(report_path),
            )
            self.assertEqual(minimize.returncode, 0, minimize.stderr)
            self.assertIn(_json(report_path)["status"], {"no_reduction", "reduced"})
            self.assertEqual(validate_witness_integrity(_json(reduced_path)), [])

    def test_compile_failure_is_structured_and_replayable_as_compile_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-compile-test-") as directory:
            witness_path = Path(directory) / "compile.json"
            result = self.run_cli("record", str(INVALID_PROGRAM), str(SUCCESS_REQUEST), "--output", str(witness_path))
            self.assertEqual(result.returncode, 1, result.stderr)
            witness = _json(witness_path)
            self.assertEqual(witness["outcome"]["failure_class"], "compile_failure")
            self.assertEqual(witness["static"]["validation"]["valid"], False)
            self.assertEqual(witness["static"]["validation"]["errors"][0]["code"], "MNCS010")
            self.assertEqual(witness["trace"]["events"][-1]["kind"], "failure")
            replay = self.run_cli("replay", str(witness_path), "--mode", "reexecute")
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(json.loads(replay.stdout)["status"], "reproduced")

    def test_budget_exhaustion_is_a_native_stop_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-budget-test-") as directory:
            witness_path = Path(directory) / "budget.json"
            result = self.run_cli("record", str(PROGRAM), str(BUDGET_REQUEST), "--output", str(witness_path))
            self.assertEqual(result.returncode, 1, result.stderr)
            witness = _json(witness_path)
            self.assertEqual(witness["outcome"]["status"], "budget_exhausted")
            self.assertEqual(witness["outcome"]["failure_class"], "timeout_or_budget_exhaustion")
            self.assertEqual(witness["outcome"]["native_decision"]["outcome"], "timeout_or_budget_exhaustion")
            self.assertTrue(witness["outcome"]["native_decision"]["should_stop"])

    def test_import_test_result_preserves_test_ownership(self) -> None:
        result = {
            "schema_version": "mncs.test-result/1",
            "protocol_version": 1,
            "id": "mncs-test",
            "provider": "mncs-test",
            "verdict": "FAIL",
            "classification": "test_failure",
            "failure_class": "assertion",
            "exit_code": 1,
            "run_id": "a" * 64,
            "scope": {"kind": "fixture"},
            "summary": {"total": 1, "passed": 0, "failed": 1, "skipped": 0, "unsupported": 0, "authority": "native_suite"},
            "tests": [
                {
                    "id": "checked-add-assertion",
                    "entry": "checked_add",
                    "kind": "unit",
                    "source": str(PROGRAM),
                    "verdict": "FAIL",
                    "status": "failed",
                    "request": _json(SUCCESS_REQUEST),
                    "failure": {"class": "assertion", "expected": 43, "actual": 42},
                }
            ],
            "provenance": {"libraries": []},
            "artifacts": [],
            "reproduction": {"command": "mncs-test run --manifest fixture", "run_id": "a" * 64},
        }
        with tempfile.TemporaryDirectory(prefix="mncs-debug-import-test-") as directory:
            root = Path(directory)
            result_path = root / "test-result.json"
            witness_path = root / "witness.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            imported = self.run_cli("import-test", str(result_path), "--output", str(witness_path))
            self.assertEqual(imported.returncode, 0, imported.stderr)
            witness = _json(witness_path)
            self.assertEqual(witness["outcome"]["failure_class"], "test_failure")
            self.assertEqual(witness["outcome"]["native_decision"]["outcome"], "assertion_failure")
            self.assertEqual(witness["integration"]["test_id"], "checked-add-assertion")
            replay = self.run_cli("replay", str(witness_path), "--mode", "reexecute")
            self.assertEqual(replay.returncode, 1)
            self.assertEqual(json.loads(replay.stdout)["status"], "blocked")

    def test_api_and_corrupt_witness_rejection(self) -> None:
        response = self.run_cli(
            "api",
            "--stdio",
            input_text=json.dumps({"schema_version": "mncs.debug-api/1", "protocol_version": 1, "operation": "capabilities"}) + "\n",
        )
        self.assertEqual(response.returncode, 0)
        self.assertEqual(json.loads(response.stdout)["schema_version"], "mncs.debug-capabilities/1")
        with tempfile.TemporaryDirectory(prefix="mncs-debug-invalid-test-") as directory:
            root = Path(directory)
            witness_path = root / "witness.json"
            self.assertEqual(self.run_cli("record", str(PROGRAM), str(SUCCESS_REQUEST), "--output", str(witness_path)).returncode, 0)
            corrupt = _json(witness_path)
            corrupt["witness_id"] = "mncs:debug:witness:corrupt"
            corrupt_path = root / "corrupt.json"
            corrupt_path.write_text(json.dumps(corrupt), encoding="utf-8")
            rejected = self.run_cli("validate", str(corrupt_path))
            self.assertEqual(rejected.returncode, 1)
            self.assertIn("witness_id does not match content", rejected.stdout)


if __name__ == "__main__":
    unittest.main()
