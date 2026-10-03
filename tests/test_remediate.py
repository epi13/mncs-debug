"""Doctor-facing remediation provider tests (stub toolchain, fake targets)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mncs_debug.remediate import remediate


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "mncs-debug"
COMMONS_SCHEMA = ROOT.parents[0] / "MNCS-Commons" / "schemas" / "mncs-remediation-v1.schema.json"

try:
    import jsonschema  # type: ignore[import-not-found]

    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

HAVE_GIT = shutil.which("git") is not None

STUB_IDENTITY = "ab" * 32


def write_stub(path: Path, identity: str = STUB_IDENTITY) -> Path:
    payload = json.dumps(
        {
            "schema_version": "0.1",
            "interface_identity": identity,
            "module": "stub",
            "functions": {},
            "composites": {},
        }
    )
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "abi" ]; then\n'
        f"  echo '{payload}';\n"
        "else\n"
        "  exit 1\n"
        "fi\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def write_descriptor(path: Path, *, libraries: list[str], identity: str, source: str = "sources/mod.mncs") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / "sources").mkdir(exist_ok=True)
    (path.parent / "sources" / "mod.mncs").write_text("mncs 0.18;\nmodule stub.mod;\n", encoding="utf-8")
    path.write_text(
        json.dumps(
            {
                "schema_version": "mncs.native-application/1",
                "module": "stub.mod",
                "source": source,
                "profile": "0.18",
                "interface_identity": identity,
                "libraries": libraries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def git_commit(target: Path) -> None:
    subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(target), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        check=True,
        capture_output=True,
    )


class RemediateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mncs-debug-remediate-test-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "libs" / "present").mkdir(parents=True)
        self.stub = write_stub(self.root / "mncs-stub")
        self._saved_env = {key: os.environ.get(key) for key in ("MNCS_STDLIB_ROOT", "MNCS_LIBRARY_PATH")}
        os.environ.pop("MNCS_STDLIB_ROOT", None)
        os.environ.pop("MNCS_LIBRARY_PATH", None)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_dead_library_entry_repaired(self) -> None:
        write_descriptor(
            self.target / "native-applications" / "d.json",
            libraries=["../libs/present", "../libs/absent"],
            identity=STUB_IDENTITY,
        )
        envelope = remediate(target=self.target, dry_run=False, mncs_path=str(self.stub))
        self.assertEqual(envelope["schema_version"], "mncs.remediation/1")
        repairs = [item for item in envelope["repairs"] if "dead-descriptor-library" in item["id"]]
        self.assertEqual(len(repairs), 1)
        self.assertTrue(repairs[0]["validated"])
        self.assertEqual(envelope["summary"]["repaired"], 1)
        reread = json.loads((self.target / "native-applications" / "d.json").read_text(encoding="utf-8"))
        self.assertEqual(reread["libraries"], ["../libs/present"])
        # Re-runs stay quiet.
        again = remediate(target=self.target, dry_run=False, mncs_path=str(self.stub))
        self.assertEqual(again["summary"]["repaired"], 0)
        self.assertEqual(again["summary"]["reconciled"], 0)

    def test_dry_run_mutates_nothing(self) -> None:
        path = self.target / "native-applications" / "d.json"
        write_descriptor(path, libraries=["../libs/absent"], identity=STUB_IDENTITY)
        before = path.read_bytes()
        envelope = remediate(target=self.target, dry_run=True, mncs_path=str(self.stub))
        self.assertTrue(envelope["dry_run"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(envelope["summary"]["repaired"], 0)
        for item in envelope["repairs"]:
            self.assertFalse(item["validated"])

    def test_changed_path_hints_gate_mutation(self) -> None:
        write_descriptor(
            self.target / "native-applications" / "d.json",
            libraries=["../libs/absent"],
            identity=STUB_IDENTITY,
        )
        envelope = remediate(
            target=self.target, dry_run=False, changed_paths=["unrelated/"], mncs_path=str(self.stub)
        )
        self.assertEqual(envelope["summary"]["repaired"], 0)
        reread = json.loads((self.target / "native-applications" / "d.json").read_text(encoding="utf-8"))
        self.assertEqual(reread["libraries"], ["../libs/absent"])
        self.assertTrue(any("hint-scope-excluded" in item["id"] for item in envelope["escalations"]))

    def test_budget_bounds_repairs(self) -> None:
        write_descriptor(
            self.target / "native-applications" / "a.json",
            libraries=["../libs/absent"],
            identity=STUB_IDENTITY,
        )
        write_descriptor(
            self.target / "native-applications" / "b.json",
            libraries=["../libs/absent"],
            identity=STUB_IDENTITY,
        )
        envelope = remediate(target=self.target, dry_run=False, budget=1, mncs_path=str(self.stub))
        self.assertEqual(envelope["summary"]["repaired"], 1)
        self.assertTrue(envelope["budget"]["exhausted"])
        self.assertTrue(any(item["id"].startswith("budget-exhausted:") for item in envelope["escalations"]))

    def test_refusals_stay_in_envelope(self) -> None:
        bad_hint = remediate(target=self.target, dry_run=True, changed_paths=["/abs"])
        self.assertEqual(bad_hint["summary"]["blockers"], 1)
        missing = remediate(target=self.root / "absent", dry_run=True)
        self.assertEqual(missing["summary"]["blockers"], 1)
        bad_budget = remediate(target=self.target, dry_run=True, budget=0)
        self.assertEqual(bad_budget["summary"]["blockers"], 1)
        for envelope in (bad_hint, missing, bad_budget):
            self.assertEqual(envelope["schema_version"], "mncs.remediation/1")

    @unittest.skipUnless(HAVE_GIT, "git not available")
    def test_stale_identity_reconciled_when_source_clean(self) -> None:
        write_descriptor(
            self.target / "native-applications" / "d.json",
            libraries=["../libs/present"],
            identity="00" * 32,
        )
        git_commit(self.target)
        envelope = remediate(target=self.target, dry_run=False, mncs_path=str(self.stub))
        reconciled = [item for item in envelope["reconciliations"] if "stale-descriptor-identity" in item["id"]]
        self.assertEqual(len(reconciled), 1)
        self.assertTrue(reconciled[0]["validated"])
        reread = json.loads((self.target / "native-applications" / "d.json").read_text(encoding="utf-8"))
        self.assertEqual(reread["interface_identity"], STUB_IDENTITY)

    @unittest.skipUnless(HAVE_GIT, "git not available")
    def test_dirty_source_escalates_instead_of_refreezing(self) -> None:
        descriptor = self.target / "native-applications" / "d.json"
        write_descriptor(descriptor, libraries=["../libs/present"], identity="00" * 32)
        git_commit(self.target)
        (self.target / "native-applications" / "sources" / "mod.mncs").write_text(
            "mncs 0.18;\nmodule stub.mod;\n// local edit\n", encoding="utf-8"
        )
        envelope = remediate(target=self.target, dry_run=False, mncs_path=str(self.stub))
        self.assertEqual(envelope["summary"]["reconciled"], 0)
        self.assertTrue(any("semantic-change-review" in item["id"] for item in envelope["escalations"]))
        reread = json.loads(descriptor.read_text(encoding="utf-8"))
        self.assertEqual(reread["interface_identity"], "00" * 32)

    @unittest.skipUnless(HAVE_JSONSCHEMA and COMMONS_SCHEMA.is_file(), "remediation schema not verifiable")
    def test_envelope_matches_commons_schema(self) -> None:
        write_descriptor(
            self.target / "native-applications" / "d.json",
            libraries=["../libs/absent"],
            identity="00" * 32,
        )
        schema = json.loads(COMMONS_SCHEMA.read_text(encoding="utf-8"))
        for dry_run in (True, False):
            envelope = remediate(target=self.target, dry_run=dry_run, mncs_path=str(self.stub))
            jsonschema.validate(envelope, schema)

    def test_cli_json_prints_exactly_one_envelope(self) -> None:
        write_descriptor(
            self.target / "native-applications" / "d.json",
            libraries=["../libs/absent"],
            identity=STUB_IDENTITY,
        )
        environment = dict(os.environ)
        environment["MNCS"] = str(self.stub)
        completed = subprocess.run(
            [sys.executable, str(BIN), "remediate", "--target", str(self.target), "--json"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        envelope = json.loads(completed.stdout)
        self.assertEqual(envelope["schema_version"], "mncs.remediation/1")
        human = subprocess.run(
            [sys.executable, str(BIN), "remediate", "--target", str(self.target)],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(human.returncode, 0, human.stderr)
        self.assertIn("remediation:", human.stdout)


if __name__ == "__main__":
    unittest.main()
