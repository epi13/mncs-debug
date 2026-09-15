from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from mncs_debug.analysis import diagnostic_loop, inspect_witness
from mncs_debug.runner import build_witness

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))
PROGRAM = ROOT / "tests/fixtures/checked-add.mncs.json"
OVERFLOW_REQUEST = ROOT / "tests/fixtures/checked-add-overflow-request.json"


@unittest.skipUnless(RUNTIME.is_file() and os.access(RUNTIME, os.X_OK), "MNCS runtime not available")
class DiagnosticLoopTests(unittest.TestCase):
    def test_inspection_sufficient_does_not_request_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-analysis-") as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(OVERFLOW_REQUEST.read_text(encoding="utf-8"), encoding="utf-8")
            witness = build_witness(
                mncs_path=RUNTIME,
                program_path=PROGRAM,
                request_path=request_path,
                cwd=PROGRAM.parent,
            )
            inspection = inspect_witness(witness)
            for frame in inspection["frames"]:
                frame["source_location"] = {"confidence": "compiler_exact"}
            result = diagnostic_loop(
                witness,
                mncs_path=RUNTIME,
                initial_inspection=inspection,
            )
            self.assertEqual(result["status"], "sufficient")
            self.assertEqual(result["projections"], [])
            self.assertEqual(result["budget"]["used"], 0)

    def test_loop_can_take_trace_only_when_provenance_is_already_observed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-analysis-") as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(OVERFLOW_REQUEST.read_text(encoding="utf-8"), encoding="utf-8")
            witness = build_witness(
                mncs_path=RUNTIME,
                program_path=PROGRAM,
                request_path=request_path,
                cwd=PROGRAM.parent,
            )
            degraded = copy.deepcopy(witness)
            degraded["runtime"]["observation"]["completeness"]["status"] = "truncated"
            degraded["trace"]["completeness"]["stream"] = copy.deepcopy(
                degraded["trace"]["completeness"].get("stream", {})
            )
            degraded["trace"]["completeness"]["stream"]["status"] = "complete"
            inspection = inspect_witness(degraded)
            inspection["trace"]["completeness"] = {"status": "partial"}
            for frame in inspection["frames"]:
                frame["source_location"] = {"confidence": "compiler_exact"}
            result = diagnostic_loop(
                degraded,
                mncs_path=RUNTIME,
                max_steps=4,
                initial_inspection=inspection,
            )
            operations = [
                step.get("projection", {}).get("operation")
                for step in result["steps"]
                if isinstance(step.get("projection"), dict)
            ]
            self.assertEqual(operations, ["trace"])
            self.assertEqual(
                [item["operation"] for item in result["requested_projections"]],
                ["trace"],
            )
            self.assertEqual(result["status"], "sufficient")

    def test_operation_hint_cannot_create_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-analysis-") as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(OVERFLOW_REQUEST.read_text(encoding="utf-8"), encoding="utf-8")
            witness = build_witness(
                mncs_path=RUNTIME,
                program_path=PROGRAM,
                request_path=request_path,
                cwd=PROGRAM.parent,
            )
            inspection = inspect_witness(witness)
            from mncs_debug.analysis import diagnostic_sufficiency

            decision = diagnostic_sufficiency(
                witness,
                inspection,
                mncs_path=RUNTIME,
                supplemental_operation="provenance",
            )
            self.assertFalse(decision["inputs"]["provenance_binding_present"])
            self.assertEqual(decision["status"], "ambiguous")

    def test_loop_can_take_trace_then_provenance_without_rerunning_test(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-analysis-") as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(OVERFLOW_REQUEST.read_text(encoding="utf-8"), encoding="utf-8")
            witness = build_witness(
                mncs_path=RUNTIME,
                program_path=PROGRAM,
                request_path=request_path,
                cwd=PROGRAM.parent,
            )
            degraded = copy.deepcopy(witness)
            degraded["trace"]["completeness"]["stream"] = copy.deepcopy(
                degraded["trace"]["completeness"]["stream"]
            )
            observation = degraded.get("runtime", {}).get("observation", {})
            observation["completeness"]["status"] = "truncated"
            degraded["trace"]["completeness"]["stream"]["status"] = "complete"
            inspection = inspect_witness(degraded)
            inspection["trace"]["completeness"] = {"status": "partial"}
            for frame in inspection["frames"]:
                frame["source_location"] = None
            result = diagnostic_loop(
                degraded,
                mncs_path=RUNTIME,
                max_steps=4,
                initial_inspection=inspection,
            )
            operations = [
                step.get("projection", {}).get("operation")
                for step in result["steps"]
                if isinstance(step.get("projection"), dict)
            ]
            self.assertEqual(operations, ["trace", "provenance"])
            self.assertEqual(
                [item["operation"] for item in result["requested_projections"]],
                ["trace", "provenance"],
            )
            self.assertEqual(result["status"], "sufficient")
            self.assertLessEqual(result["budget"]["used"], 5)


if __name__ == "__main__":
    unittest.main()
