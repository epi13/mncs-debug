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
                {
                    "execution_entry",
                    "function_entry",
                    "block_enter",
                    "semantic_operation",
                    "operation_result",
                    "return",
                    "function_exit",
                    "execution_exit",
                },
            )
            self.assertEqual(
                [event["kind"] for event in failure["trace"]["events"]].count("failure"),
                1,
            )
            self.assertTrue(
                all(
                    event.get("payload", {}).get("native_event", {}).get("status") != "invalid_request"
                    for event in success["trace"]["events"]
                    if event["kind"] == "operation_result"
                )
            )
            self.assertTrue(failure["outcome"]["native_decision"]["should_stop"])
            self.assertEqual(self.run_cli("validate", str(failure_path)).returncode, 0)

            inspection = json.loads(self.run_cli("inspect", str(failure_path)).stdout)
            self.assertEqual(inspection["schema_version"], "mncs.debug-inspection/1")
            trace = json.loads(self.run_cli("trace", str(failure_path), "--kind", "failure").stdout)
            self.assertEqual([event["kind"] for event in trace["events"]], ["failure"])
            why = json.loads(self.run_cli("why", str(failure_path)).stdout)
            self.assertEqual(why["completeness"]["status"], "complete")
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
            self.assertEqual(witness["static"]["source"]["function_locations"]["wrapper"]["confidence"], "compiler_exact")
            self.assertEqual(witness["static"]["source"]["source_map_schema"], "mncs.execution-source-map/1")
            self.assertEqual(witness["trace"]["completeness"]["source_locations"], "compiler_execution_source_map")
            self.assertEqual(len(witness["trace"]["frame_observations"]), 2)
            child = next(frame for frame in witness["trace"]["frame_observations"] if frame.get("parent"))
            self.assertTrue(child["call_operation"])
            self.assertTrue(any(value.get("origin") for value in witness["trace"]["value_observations"]))
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

    def test_native_backtrace_value_origin_and_source_operation_api(self) -> None:
        nested_program = ROOT / "examples/nested.mncs"
        nested_request = ROOT / "examples/nested-request.json"
        with tempfile.TemporaryDirectory(prefix="mncs-debug-native-api-" ) as directory:
            witness_path = Path(directory) / "nested.json"
            result = self.run_cli("record", str(nested_program), str(nested_request), "--output", str(witness_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            witness = _json(witness_path)
            value = next(item["value_id"] for item in witness["trace"]["value_observations"] if item.get("origin"))
            operation = next(
                event["location"]["runtime"]["operation"]
                for event in witness["trace"]["events"]
                if event["kind"] == "operation_result" and event["location"]["runtime"].get("operation")
            )

            def api(request: dict) -> dict:
                response = self.run_cli("api", "--stdio", input_text=json.dumps(request) + "\n")
                self.assertEqual(response.returncode, 0, response.stderr)
                return json.loads(response.stdout)

            backtrace = api(
                {
                    "schema_version": "mncs.debug-api/1",
                    "protocol_version": 1,
                    "operation": "backtrace",
                    "witness": str(witness_path),
                }
            )
            self.assertEqual(backtrace["projection"], "backtrace")
            self.assertEqual(len(backtrace["frames"]), 2)
            self.assertTrue(backtrace["frames"][1]["parent_frame"])

            origin = api(
                {
                    "schema_version": "mncs.debug-api/1",
                    "protocol_version": 1,
                    "operation": "value-origin",
                    "witness": str(witness_path),
                    "value": value,
                }
            )
            self.assertEqual(origin["projection"], "value-origin")
            self.assertTrue(any(claim["kind"] == "value_origin_chain" for claim in origin["claims"]))
            self.assertEqual(origin["completeness"]["status"], "complete")

            source_operation = api(
                {
                    "schema_version": "mncs.debug-api/1",
                    "protocol_version": 1,
                    "operation": "why",
                    "witness": str(witness_path),
                    "operation_identity": operation,
                }
            )
            operation_claim = next(
                claim for claim in source_operation["claims"] if claim["kind"] == "operation_identity"
            )
            self.assertEqual(operation_claim["operation"]["source_correspondence"]["confidence"], "compiler_exact")

            selected_path = Path(directory) / "selected.json"
            selected = self.run_cli(
                "record",
                str(nested_program),
                str(nested_request),
                "--capture",
                "selected",
                "--operation",
                operation,
                "--max-value-bytes",
                "1",
                "--output",
                str(selected_path),
            )
            self.assertEqual(selected.returncode, 0, selected.stderr)
            selected_witness = _json(selected_path)
            self.assertEqual(
                selected_witness["runtime"]["observation"]["policy"]["capture"],
                "selected",
            )
            self.assertTrue(
                all(
                    event["operation"] == operation
                    or event["kind"] in {"operation_result", "semantic_operation"}
                    for event in selected_witness["runtime"]["observation"]["events"]
                )
            )
            self.assertTrue(
                any(
                    value["capture"]["kind"] != "full"
                    for value in selected_witness["runtime"]["observation"]["values"]
                )
            )

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
            imported = self.run_cli(
                "import-test",
                str(result_path),
                "--capture",
                "failure-only",
                "--output",
                str(witness_path),
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            witness = _json(witness_path)
            self.assertEqual(witness["outcome"]["failure_class"], "test_failure")
            self.assertEqual(witness["outcome"]["native_decision"]["outcome"], "assertion_failure")
            self.assertEqual(witness["integration"]["test_id"], "checked-add-assertion")
            self.assertNotIn("test_case_identity", witness["integration"]["test_execution"])
            self.assertEqual(
                witness["integration"]["request"]["embedding"]["sha256"],
                witness["request"]["sha256"],
            )
            self.assertEqual(witness["integration"]["test_result_reference"]["kind"], "mncs-test-result")
            if RUNTIME_AVAILABLE:
                self.assertEqual(witness["runtime"]["capture_policy"], "failure-only")
                self.assertEqual(witness["runtime"]["effective_capture_policy"], "bounded")
                self.assertEqual(
                    witness["runtime"]["observation"]["completeness"]["status"],
                    "complete",
                )
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

class ForgeExecutorCliTests(unittest.TestCase):
    """Forge-submitted observation plumbing without a native toolchain.

    A stub Forge binary stands in for ``mncs-forge mncs observe``; the
    witness it serves is integrity-valid but carries no native facts.
    """

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(BIN), *arguments],
            cwd=ROOT,
            env=dict(os.environ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_forge_executor_requires_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-forge-executor-") as directory:
            root = Path(directory)
            missing = self.run_cli(
                "record",
                str(PROGRAM),
                str(SUCCESS_REQUEST),
                "--mncs",
                sys.executable,
                "--output",
                str(root / "witness.json"),
                "--executor",
                "forge",
            )
            self.assertEqual(missing.returncode, 2)
            self.assertIn("--forge-config", missing.stderr)

    def test_forge_executor_returns_validated_observe_witness(self) -> None:
        from mncs_debug.protocol import identity

        material = {
            "schema_version": "mncs.debug-witness/1",
            "protocol_version": 1,
            "execution_identity": "execution-stub",
            "session": {},
            "program": {},
            "request": {},
            "compiler": {},
            "runtime": {},
            "outcome": {"failure_class": "success"},
            "trace": {
                "schema_version": "mncs.debug-trace/1",
                "protocol_version": 1,
                "trace_id": "trace-stub",
                "execution_identity": "execution-stub",
                "events": [],
                "capture_policy": "bounded",
                "bounded": True,
            },
            "static": {},
            "artifacts": [],
            "process": {},
            "replay": {},
            "capabilities": {
                "schema_version": "mncs.debug-capabilities/1",
                "protocol_version": 1,
                "debugger": "mncs-debug",
                "debugger_version": "stub",
                "capabilities_id": "stub",
                "capabilities": [],
                "protocols": [],
            },
            "provenance": {},
            "limitations": [],
        }
        witness = {**material, "witness_id": identity("witness", material)}
        with tempfile.TemporaryDirectory(prefix="mncs-debug-forge-executor-") as directory:
            root = Path(directory)
            (root / "stub-witness.json").write_text(json.dumps(witness), encoding="utf-8")
            stub = root / "stub-forge"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "from pathlib import Path\n"
                "here = Path(sys.argv[0]).parent\n"
                "witness = json.loads((here / 'stub-witness.json').read_text(encoding='utf-8'))\n"
                "(here / 'seen.json').write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n"
                "assert 'observe' in sys.argv[1:], sys.argv\n"
                "assert '--executor' not in sys.argv[1:], sys.argv\n"
                "print(json.dumps({'schema_version': 'mncs.forge-observation/1', 'witness_document': witness}))\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            forged_path = root / "forged.json"
            forged = self.run_cli(
                "record",
                str(PROGRAM),
                str(SUCCESS_REQUEST),
                "--mncs",
                sys.executable,
                "--output",
                str(forged_path),
                "--capture",
                "failure-only",
                "--executor",
                "forge",
                "--forge-binary",
                str(stub),
                "--forge-config",
                str(root / "forge.toml"),
            )
            self.assertEqual(forged.returncode, 0, forged.stderr)
            self.assertEqual(_json(forged_path), witness)
            seen = json.loads((root / "seen.json").read_text(encoding="utf-8"))
            self.assertIn(str(PROGRAM.resolve()), seen)
            self.assertIn(str(SUCCESS_REQUEST.resolve()), seen)
            self.assertEqual(seen[seen.index("--capture-policy") + 1], "failure-only")

    def test_forge_executor_rejects_invalid_observe_response(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-forge-executor-") as directory:
            root = Path(directory)
            stub = root / "stub-forge"
            stub.write_text(
                "#!/usr/bin/env python3\nprint('{\"ok\": false}')\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            rejected = self.run_cli(
                "record",
                str(PROGRAM),
                str(SUCCESS_REQUEST),
                "--mncs",
                sys.executable,
                "--output",
                str(root / "witness.json"),
                "--executor",
                "forge",
                "--forge-binary",
                str(stub),
                "--forge-config",
                str(root / "forge.toml"),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("forge observe failed", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
