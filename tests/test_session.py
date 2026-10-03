"""Resident session lifecycle tests over synthetic and recorded witnesses."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mncs_debug.protocol import (
    TRACE_SCHEMA,
    WITNESS_SCHEMA,
    identity,
    validate_document,
    write_json,
)
from mncs_debug.session import (
    SESSION_SCHEMA,
    SessionError,
    attach_session,
    close_session,
    open_session,
    query_session,
)


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "mncs-debug"
PROGRAM = ROOT / "tests/fixtures/checked-add.mncs.json"
OVERFLOW_REQUEST = ROOT / "tests/fixtures/checked-add-overflow-request.json"
RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))
RUNTIME_AVAILABLE = RUNTIME.is_file() and os.access(RUNTIME, os.X_OK)


def synthetic_witness() -> dict:
    material = {
        "schema_version": WITNESS_SCHEMA,
        "protocol_version": 1,
        "execution_identity": "mncs:test:execution:synthetic",
        "program": {},
        "request": {},
        "outcome": {"status": "returned", "failure_class": "success"},
        "trace": {
            "schema_version": TRACE_SCHEMA,
            "protocol_version": 1,
            "trace_id": "mncs:debug:trace:synthetic",
            "execution_identity": "mncs:test:execution:synthetic",
            "events": [],
            "capture_policy": "bounded",
            "bounded": True,
        },
        "replay": {},
        "capabilities": {},
        "provenance": {},
    }
    return {**material, "witness_id": identity("witness", material)}


class ResidentSessionPureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="mncs-debug-session-test-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.witness_path = self.root / "witness.json"
        write_json(self.witness_path, synthetic_witness())
        self.session_root = self.root / "session"

    def test_open_attach_query_memo_hit(self) -> None:
        opened = open_session(witness_path=self.witness_path, root=self.session_root)
        self.assertEqual(opened["schema_version"], SESSION_SCHEMA)
        self.assertEqual(opened["state"], "open")
        self.assertEqual(validate_document(opened, SESSION_SCHEMA), [])
        self.assertTrue((self.session_root / "witness.json").is_file())
        self.assertTrue((self.session_root / "indexes" / "events.json").is_file())

        attached = attach_session(self.session_root)
        self.assertEqual(attached["state"], "open")
        self.assertFalse(attached["indexes_rebuilt"])
        self.assertEqual(attached["orientation"]["event_count"], 0)

        cold = query_session(self.session_root, "inspect", {})
        self.assertFalse(cold["memo_hit"])
        self.assertEqual(cold["result"]["schema_version"], "mncs.debug-inspection/1")
        warm = query_session(self.session_root, "inspect", {})
        self.assertTrue(warm["memo_hit"])
        self.assertEqual(warm["memo_key"], cold["memo_key"])
        self.assertEqual(warm["result"], cold["result"])

        status = attach_session(self.session_root)
        self.assertEqual(status["memo"]["hits"], 1)
        self.assertEqual(status["memo"]["misses"], 1)
        self.assertEqual(status["queries"], 2)

    def test_pure_query_operations(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        trace = query_session(self.session_root, "trace", {"kind": "failure"})
        self.assertEqual(trace["result"]["schema_version"], "mncs.debug-trace/1")
        why = query_session(self.session_root, "why", {})
        self.assertEqual(why["result"]["schema_version"], "mncs.debug-provenance/1")
        replay = query_session(self.session_root, "replay", {})
        self.assertEqual(replay["result"]["schema_version"], "mncs.debug-replay/1")

    def test_open_refuses_existing_without_force(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        with self.assertRaises(SessionError):
            open_session(witness_path=self.witness_path, root=self.session_root)
        reopened = open_session(witness_path=self.witness_path, root=self.session_root, force=True)
        self.assertEqual(reopened["state"], "open")

    def test_tampered_witness_goes_stale_and_refuses_queries(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        held = self.session_root / "witness.json"
        tampered = json.loads(held.read_text(encoding="utf-8"))
        tampered["outcome"]["status"] = "tampered"
        held.write_text(json.dumps(tampered), encoding="utf-8")
        attached = attach_session(self.session_root)
        self.assertEqual(attached["state"], "stale")
        self.assertIn("digest", attached["stale_reason"])
        with self.assertRaises(SessionError):
            query_session(self.session_root, "inspect", {})

    def test_missing_indexes_rebuilt_on_attach(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        (self.session_root / "indexes" / "events.json").unlink()
        attached = attach_session(self.session_root)
        self.assertEqual(attached["state"], "open")
        self.assertTrue(attached["indexes_rebuilt"])
        self.assertTrue((self.session_root / "indexes" / "events.json").is_file())

    def test_close_and_wipe(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        closed = close_session(self.session_root)
        self.assertEqual(closed["state"], "closed")
        self.assertFalse(closed["wiped"])
        with self.assertRaises(SessionError):
            query_session(self.session_root, "inspect", {})
        wiped = close_session(self.session_root, wipe=True)
        self.assertTrue(wiped["wiped"])
        self.assertFalse(self.session_root.exists())

    def test_unknown_operation_and_missing_session_refused(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        with self.assertRaises(SessionError):
            query_session(self.session_root, "reexecute", {})
        with self.assertRaises(SessionError):
            attach_session(self.root / "absent")
        with self.assertRaises(SessionError):
            query_session(self.session_root, "sufficiency", {})

    def test_oversize_params_refused(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        with self.assertRaises(SessionError):
            query_session(self.session_root, "why", {"question": "x" * (256 * 1024 + 1)})

    def test_numeric_params_coerced(self) -> None:
        open_session(witness_path=self.witness_path, root=self.session_root)
        envelope = query_session(self.session_root, "trace", {"start": "0", "limit": "5"})
        self.assertEqual(envelope["result"]["schema_version"], "mncs.debug-trace/1")
        with self.assertRaises(SessionError):
            query_session(self.session_root, "trace", {"limit": "bogus"})


@unittest.skipUnless(RUNTIME_AVAILABLE, "MNCS runtime not available")
class ResidentSessionRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory(prefix="mncs-debug-session-runtime-")
        cls.addClassCleanup(cls._temporary.cleanup)
        root = Path(cls._temporary.name)
        cls.witness_path = root / "overflow.json"
        cls.session_root = root / "session"
        environment = dict(os.environ)
        environment["MNCS"] = str(RUNTIME)
        completed = subprocess.run(
            [sys.executable, str(BIN), "record", str(PROGRAM), str(OVERFLOW_REQUEST),
             "--output", str(cls.witness_path)],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 1:
            raise unittest.SkipTest(f"overflow record failed: {completed.stderr}")

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

    def test_cli_round_trip(self) -> None:
        root = self.session_root.parent / "cli-session"
        self.assertEqual(
            self.run_cli("session", "open", str(self.witness_path), "--root", str(root)).returncode, 0
        )
        attached = json.loads(self.run_cli("session", "attach", "--root", str(root)).stdout)
        self.assertEqual(attached["state"], "open")
        self.assertGreater(attached["orientation"]["event_count"], 0)
        envelope = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "trace",
                         "--kind", "failure").stdout
        )
        self.assertFalse(envelope["memo_hit"])
        self.assertEqual(
            [event["kind"] for event in envelope["result"]["events"]], ["failure"]
        )
        warm = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "trace",
                         "--kind", "failure").stdout
        )
        self.assertTrue(warm["memo_hit"])
        self.assertEqual(warm["result"], envelope["result"])
        why = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "why").stdout
        )
        self.assertEqual(why["result"]["schema_version"], "mncs.debug-provenance/1")
        self.assertEqual(
            self.run_cli("session", "close", "--root", str(root), "--wipe").returncode, 0
        )
        self.assertFalse(root.exists())

    def test_native_sufficiency_memo_hit(self) -> None:
        root = self.session_root.parent / "sufficiency-session"
        self.assertEqual(
            self.run_cli("session", "open", str(self.witness_path), "--root", str(root)).returncode, 0
        )
        cold = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "sufficiency").stdout
        )
        self.assertFalse(cold["memo_hit"])
        self.assertEqual(cold["result"]["schema_version"], "mncs.debug-sufficiency/1")
        warm = json.loads(
            self.run_cli("session", "query", "--root", str(root), "--op", "sufficiency").stdout
        )
        self.assertTrue(warm["memo_hit"])
        self.assertEqual(warm["result"], cold["result"])


if __name__ == "__main__":
    unittest.main()
