"""Semantic stop-set and value-watch tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mncs_debug.protocol import validate_document
from mncs_debug.targets import (
    NoSourceMap,
    TargetError,
    build_stop_set,
    record_stop_set,
    resolve_function,
    resolve_line,
    resolve_operation,
    resolve_witness_target,
    watch_binding,
)


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "mncs-debug"
NESTED_PROGRAM = ROOT / "examples/nested.mncs"
NESTED_REQUEST = ROOT / "examples/nested-request.json"
RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))
RUNTIME_AVAILABLE = RUNTIME.is_file() and os.access(RUNTIME, os.X_OK)


def synthetic_source_map() -> dict:
    return {
        "schema_version": "mncs.execution-source-map/1",
        "functions": [
            {"identity": "fn::increment", "name": "increment", "declaration_span": {"line": 5}},
            {"identity": "fn::wrapper", "name": "wrapper", "declaration_span": {"line": 9}},
        ],
        "blocks": [],
        "operations": [
            {"identity": "op::inc::0", "function_identity": "fn::increment",
             "source_span": {"line": 6, "column": 12}, "synthetic": False},
            {"identity": "op::inc::1", "function_identity": "fn::increment",
             "source_span": {"line": 6, "column": 20}, "synthetic": False},
            {"identity": "op::wrap::0", "function_identity": "fn::wrapper",
             "source_span": {"line": 10, "column": 12}, "synthetic": False},
            {"identity": "op::wrap::synth", "function_identity": "fn::wrapper",
             "synthetic": True},
        ],
    }


def synthetic_manifest_witness() -> dict:
    return {
        "witness_id": "mncs:debug:witness:synthetic",
        "execution_identity": "mncs:test:execution:synthetic",
        "static": {"source": {}},
        "runtime": {},
        "trace": {
            "events": [
                {"event_id": "e1", "kind": "semantic_operation",
                 "location": {"runtime": {"operation": "op::seen"}},
                 "payload": {}, "relationships": {}},
            ],
        },
        "limitations": [],
    }


class TargetResolutionTests(unittest.TestCase):
    def test_resolve_function(self) -> None:
        resolution = resolve_function(synthetic_source_map(), "increment")
        self.assertEqual(resolution["status"], "resolved")
        self.assertEqual(
            [item["identity"] for item in resolution["operations"]],
            ["op::inc::0", "op::inc::1"],
        )
        self.assertEqual(resolution["function"]["identity"], "fn::increment")
        missing = resolve_function(synthetic_source_map(), "absent")
        self.assertEqual(missing["status"], "unresolved")

    def test_resolve_function_ambiguous(self) -> None:
        source_map = synthetic_source_map()
        source_map["functions"].append({"identity": "fn::other", "name": "increment"})
        resolution = resolve_function(source_map, "increment")
        self.assertEqual(resolution["status"], "ambiguous")
        self.assertEqual(len(resolution["candidates"]), 2)

    def test_resolve_operation_exact_only(self) -> None:
        resolution = resolve_operation(synthetic_source_map(), "op::inc::0")
        self.assertEqual(resolution["status"], "resolved")
        self.assertFalse(resolution["operations"][0]["synthetic"])
        missing = resolve_operation(synthetic_source_map(), "op::inc")
        self.assertEqual(missing["status"], "unresolved")

    def test_resolve_line_matches_every_spanning_operation(self) -> None:
        resolution = resolve_line(synthetic_source_map(), 6)
        self.assertEqual(resolution["status"], "resolved")
        self.assertEqual(len(resolution["operations"]), 2)
        missing = resolve_line(synthetic_source_map(), 7)
        self.assertEqual(missing["status"], "unresolved")
        invalid = resolve_line(synthetic_source_map(), 0)
        self.assertEqual(invalid["status"], "unresolved")

    def test_build_stop_set_validates(self) -> None:
        resolution = resolve_function(synthetic_source_map(), "wrapper")
        stop_set = build_stop_set(
            kind="function",
            value="wrapper",
            resolution=resolution,
            witness_id="mncs:debug:witness:synthetic",
            executions=2,
            capture_policy="selected",
            matched=["e1"],
        )
        self.assertEqual(stop_set["schema_version"], "mncs.debug-stop-set/1")
        self.assertEqual(validate_document(stop_set, "mncs.debug-stop-set/1"), [])
        self.assertFalse(stop_set["suspension"]["supported"])
        self.assertEqual(stop_set["matched_event_count"], 1)

    def test_witness_target_without_map_is_operation_only(self) -> None:
        witness = synthetic_manifest_witness()
        observed = resolve_witness_target(witness, "operation", "op::seen")
        self.assertEqual(observed["status"], "observed_only")
        missing = resolve_witness_target(witness, "operation", "op::unseen")
        self.assertEqual(missing["status"], "unresolved")
        refused = resolve_witness_target(witness, "function", "anything")
        self.assertEqual(refused["status"], "unresolved")

    def test_watch_binding_unobserved_without_values(self) -> None:
        document = watch_binding(synthetic_manifest_witness(), "a")
        self.assertEqual(document["schema_version"], "mncs.debug-provenance/1")
        self.assertEqual(document["claims"][0]["status"], "unobserved")

    def test_record_stop_set_masks_only_missing_maps(self) -> None:
        witness = {"witness_id": "mncs:debug:witness:synthetic", "trace": {"events": []}}
        with mock.patch("mncs_debug.targets.fetch_source_map", side_effect=NoSourceMap("manifest")), mock.patch(
            "mncs_debug.targets.build_witness", return_value=witness
        ):
            _, stop_set = record_stop_set(
                mncs_path=Path("/nonexistent/mncs"),
                program_path=Path("program.json"),
                request_path=Path("request.json"),
                cwd=Path("."),
                kind="operation",
                value="op::opaque",
            )
        self.assertEqual(stop_set["resolution"]["status"], "opaque")
        self.assertEqual(stop_set["executions"], 2)
        with mock.patch("mncs_debug.targets.fetch_source_map", side_effect=TargetError("timeout")):
            with self.assertRaises(TargetError):
                record_stop_set(
                    mncs_path=Path("/nonexistent/mncs"),
                    program_path=Path("program.json"),
                    request_path=Path("request.json"),
                    cwd=Path("."),
                    kind="operation",
                    value="op::opaque",
                )

    def test_watch_binding_ambiguous_lists_candidates(self) -> None:
        witness = synthetic_manifest_witness()
        witness["runtime"] = {
            "observation": {
                "values": [
                    {"identity": "v::1", "binding": "value", "frame": "f", "version": 0},
                    {"identity": "v::2", "binding": "value", "frame": "f", "version": 1},
                ]
            }
        }
        document = watch_binding(witness, "value")
        self.assertEqual(document["claims"][0]["status"], "ambiguous")
        self.assertEqual(len(document["claims"][0]["candidates"]), 2)


@unittest.skipUnless(RUNTIME_AVAILABLE, "MNCS runtime not available")
class TargetRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory(prefix="mncs-debug-targets-runtime-")
        cls.addClassCleanup(cls._temporary.cleanup)
        root = Path(cls._temporary.name)
        cls.witness_path = root / "nested.json"
        environment = dict(os.environ)
        environment["MNCS"] = str(RUNTIME)
        completed = subprocess.run(
            [sys.executable, str(BIN), "record", str(NESTED_PROGRAM), str(NESTED_REQUEST),
             "--output", str(cls.witness_path)],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise unittest.SkipTest(f"nested record failed: {completed.stderr}")

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["MNCS"] = str(RUNTIME)
        return subprocess.run(
            [sys.executable, str(BIN), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_break_witness_modes(self) -> None:
        function = json.loads(
            self.run_cli("break", "--witness", str(self.witness_path), "--function", "wrapper").stdout
        )
        self.assertEqual(function["resolution"]["status"], "resolved")
        self.assertGreater(len(function["matched_events"]), 0)
        self.assertEqual(function["executions"], 0)
        line = json.loads(
            self.run_cli("break", "--witness", str(self.witness_path), "--line", "8").stdout
        )
        self.assertEqual(line["resolution"]["status"], "resolved")
        self.assertEqual(len(line["resolution"]["operations"]), 2)
        operation_id = function["resolution"]["operations"][0]["identity"]
        operation = json.loads(
            self.run_cli("break", "--witness", str(self.witness_path), "--operation", operation_id).stdout
        )
        self.assertEqual(operation["resolution"]["status"], "resolved")
        missing = self.run_cli("break", "--witness", str(self.witness_path), "--function", "absent")
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(json.loads(missing.stdout)["resolution"]["status"], "unresolved")

    def test_break_record_mode(self) -> None:
        root = Path(self._temporary.name)
        stop_path = root / "stop.json"
        completed = self.run_cli(
            "break", "--program", str(NESTED_PROGRAM), "--request", str(NESTED_REQUEST),
            "--function", "increment", "--output", str(stop_path),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        stop_set = json.loads(stop_path.read_text(encoding="utf-8"))
        self.assertEqual(stop_set["resolution"]["status"], "resolved")
        self.assertEqual(stop_set["executions"], 2)
        self.assertEqual(stop_set["capture_policy"], "selected")
        self.assertGreater(len(stop_set["matched_events"]), 0)
        witness_path = root / "stop.witness.json"
        self.assertTrue(witness_path.is_file())
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        self.assertLess(len(witness["trace"]["events"]), 16)

    def test_watch_binding_modes(self) -> None:
        single = json.loads(
            self.run_cli("watch", str(self.witness_path), "--binding", "$mncs$v$1").stdout
        )
        self.assertTrue(any(claim["kind"] == "value_observation" for claim in single["claims"]))
        ambiguous = json.loads(
            self.run_cli("watch", str(self.witness_path), "--binding", "value").stdout
        )
        self.assertEqual(ambiguous["claims"][0]["status"], "ambiguous")
        self.assertEqual(len(ambiguous["claims"][0]["candidates"]), 2)


if __name__ == "__main__":
    unittest.main()
