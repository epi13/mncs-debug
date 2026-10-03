from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mncs_debug.native_core import (
    _libraries,
    default_core_path,
    default_stdlib_library,
)


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "mncs-debug"
PROGRAM = ROOT / "tests/fixtures/checked-add.mncs.json"
SUCCESS_REQUEST = ROOT / "tests/fixtures/checked-add-success-request.json"
RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))
RUNTIME_AVAILABLE = RUNTIME.is_file() and os.access(RUNTIME, os.X_OK)
WORKSPACE_STDLIB = ROOT.parents[0] / "mncs-stdlib" / "library"


class StdlibResolutionTests(unittest.TestCase):
    def test_explicit_root_wins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-stdlib-root-") as directory:
            library = Path(directory) / "library"
            library.mkdir()
            with mock.patch.dict(os.environ, {"MNCS_STDLIB_ROOT": directory}, clear=False):
                self.assertEqual(default_stdlib_library(), library)

    def test_explicit_library_path_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-stdlib-root-") as directory:
            library = Path(directory) / "library"
            library.mkdir()
            with mock.patch.dict(os.environ, {"MNCS_STDLIB_ROOT": str(library)}, clear=False):
                self.assertEqual(default_stdlib_library(), library)

    def test_empty_override_disables_derivation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-stdlib-ws-") as directory:
            workspace = Path(directory)
            (workspace / "mncs-stdlib" / "library").mkdir(parents=True)
            with mock.patch.dict(os.environ, {"MNCS_STDLIB_ROOT": ""}, clear=False):
                self.assertIsNone(default_stdlib_library(workspace))

    def test_missing_override_does_not_fall_through(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-stdlib-ws-") as directory:
            workspace = Path(directory)
            (workspace / "mncs-stdlib" / "library").mkdir(parents=True)
            with mock.patch.dict(
                os.environ,
                {"MNCS_STDLIB_ROOT": str(workspace / "absent")},
                clear=False,
            ):
                self.assertIsNone(default_stdlib_library(workspace))

    def test_workspace_sibling_fallback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-stdlib-ws-") as directory:
            workspace = Path(directory)
            library = workspace / "mncs-stdlib" / "library"
            library.mkdir(parents=True)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MNCS_STDLIB_ROOT", None)
                self.assertEqual(default_stdlib_library(workspace), library)

    def test_libraries_orders_explicit_then_stdlib(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-stdlib-order-") as directory:
            explicit = Path(directory) / "explicit"
            explicit.mkdir()
            stdlib_root = Path(directory) / "stdlib-root"
            (stdlib_root / "library").mkdir(parents=True)
            environment = {
                "MNCS_LIBRARY_PATH": str(explicit),
                "MNCS_STDLIB_ROOT": str(stdlib_root),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                libraries = _libraries(default_core_path())
            self.assertIn(explicit, libraries)
            self.assertIn(stdlib_root / "library", libraries)
            self.assertLess(libraries.index(explicit), libraries.index(stdlib_root / "library"))
            self.assertEqual(len(libraries), len(set(libraries)))

    def test_libraries_survives_custom_core_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-core-") as directory:
            core = Path(directory) / "custom.mncs"
            core.write_text("mncs 0.18;\nmodule custom.debug;\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"MNCS_STDLIB_ROOT": ""}, clear=False):
                libraries = _libraries(core)
            self.assertIsInstance(libraries, list)


@unittest.skipUnless(RUNTIME_AVAILABLE, "MNCS runtime not available")
@unittest.skipUnless(WORKSPACE_STDLIB.is_dir(), "mncs-stdlib sibling checkout not available")
class StdlibRecordingTests(unittest.TestCase):
    def test_recorded_witness_carries_derived_stdlib(self) -> None:
        environment = dict(os.environ)
        environment["MNCS"] = str(RUNTIME)
        environment.pop("MNCS_STDLIB_ROOT", None)
        with tempfile.TemporaryDirectory(prefix="mncs-debug-stdlib-test-") as directory:
            witness_path = Path(directory) / "witness.json"
            completed = subprocess.run(
                [sys.executable, str(BIN), "record", str(PROGRAM), str(SUCCESS_REQUEST),
                 "--output", str(witness_path)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            witness = json.loads(witness_path.read_text(encoding="utf-8"))
            recorded = {
                entry.get("path")
                for entry in witness["provenance"]["libraries"]
                if isinstance(entry, dict)
            }
            self.assertIn(str(WORKSPACE_STDLIB.resolve()), recorded)


if __name__ == "__main__":
    unittest.main()
