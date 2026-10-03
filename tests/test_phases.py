"""Compiler-phase projection tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "mncs-debug"
NESTED_PROGRAM = ROOT / "examples/nested.mncs"
NESTED_REQUEST = ROOT / "examples/nested-request.json"
MANIFEST_PROGRAM = ROOT / "tests/fixtures/checked-add.mncs.json"
MANIFEST_REQUEST = ROOT / "tests/fixtures/checked-add-success-request.json"
RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))
RUNTIME_AVAILABLE = RUNTIME.is_file() and os.access(RUNTIME, os.X_OK)


@unittest.skipUnless(RUNTIME_AVAILABLE, "MNCS runtime not available")
class CompilerPhasesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory(prefix="mncs-debug-phases-runtime-")
        cls.addClassCleanup(cls._temporary.cleanup)
        root = Path(cls._temporary.name)
        cls.nested_witness = root / "nested.json"
        cls.manifest_witness = root / "manifest.json"
        environment = dict(os.environ)
        environment["MNCS"] = str(RUNTIME)
        for program, request, output in (
            (NESTED_PROGRAM, NESTED_REQUEST, cls.nested_witness),
            (MANIFEST_PROGRAM, MANIFEST_REQUEST, cls.manifest_witness),
        ):
            completed = subprocess.run(
                [sys.executable, str(BIN), "record", str(program), str(request), "--output", str(output)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                raise unittest.SkipTest(f"record failed for {program}: {completed.stderr}")

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

    def test_source_phases(self) -> None:
        completed = self.run_cli("phases", str(self.nested_witness))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual(document["schema_version"], "mncs.debug-phases/1")
        self.assertEqual(document["status"], "complete")
        self.assertGreater(document["pass_count"], 0)
        self.assertIn("semantic_fingerprint", document["compilation"])
        self.assertTrue(document["resolutions"])
        self.assertEqual(
            {item["name"] for item in document["static"]["functions"]}, {"wrapper", "increment"}
        )

    def test_manifest_phases(self) -> None:
        completed = self.run_cli("phases", str(self.manifest_witness), "--kind", "summary")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual(document["status"], "complete")
        self.assertEqual(document["kind"], "summary")
        self.assertGreater(document["pass_count"], 0)

    def test_phases_session_query(self) -> None:
        root = Path(self._temporary.name) / "phases-session"
        self.assertEqual(
            self.run_cli("session", "open", str(self.nested_witness), "--root", str(root)).returncode, 0
        )
        cold = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "phases").stdout
        )
        self.assertFalse(cold["memo_hit"])
        self.assertEqual(cold["result"]["schema_version"], "mncs.debug-phases/1")
        warm = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "phases").stdout
        )
        self.assertTrue(warm["memo_hit"])
        self.assertEqual(warm["result"], cold["result"])


if __name__ == "__main__":
    unittest.main()
