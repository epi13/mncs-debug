"""Live VM debug session tests: stop, inspect, step, resume, terminate.

Integration tests drive a real ``mncs-vm debug --serve`` daemon over a
Unix socket; each test owns its session directory and closes it. Pure
unit tests cover schema validation and binary resolution without a VM.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from mncs_debug.live import (
    LiveError,
    attach_session,
    bind_stop,
    clear_stop,
    close_session,
    continue_session,
    inspect_session,
    resolve_mncs_vm,
    resume_session,
    start_session,
    step_session,
    terminate_session,
)
from mncs_debug.protocol import LIVE_EVIDENCE_SCHEMA, LIVE_SESSION_SCHEMA, validate_document


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[0]
VM = Path(os.environ.get("MNCS_VM", str(WORKSPACE / "mncs-vm" / "target" / "debug" / "mncs-vm")))
VM_AVAILABLE = VM.is_file() and os.access(VM, os.X_OK)
CORPUS = WORKSPACE / "mncs-vm" / "tests" / "corpus" / "arith.mncs"
CORPUS_AVAILABLE = CORPUS.is_file()
STORE_PACKAGE = WORKSPACE / "mncs-store" / "python" / "mncs_store"
STORE_AVAILABLE = STORE_PACKAGE.is_dir()

LIVE_AVAILABLE = VM_AVAILABLE and CORPUS_AVAILABLE


def int_arg(value: int) -> dict:
    return {"integer": {"value": value, "type": {"bits": 64, "signed": True}}}


def start_add2(root: Path, **overrides) -> dict:
    params: dict = {
        "root": root,
        "vm_path": VM,
        "target": {"module": "mncs.vmcorpus.arith.v1", "name": "add2"},
        "arguments": [int_arg(3), int_arg(4)],
        "compile_path": CORPUS,
        "capture": "none",
    }
    params.update(overrides)
    return start_session(**params)


@unittest.skipUnless(LIVE_AVAILABLE, "mncs-vm driver or corpus not available")
class LiveSessionTest(unittest.TestCase):
    def test_stop_inspect_step_resume(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = Path(directory) / "session"
            # Discover operation identities through an observed add3 run.
            probe = start_session(
                root=Path(directory) / "probe",
                vm_path=VM,
                target={"module": "mncs.vmcorpus.arith.v1", "name": "add3"},
                arguments=[int_arg(10)],
                compile_path=CORPUS,
                capture="bounded",
            )
            self.assertEqual(probe["event"]["event"], "finished")
            stream = probe["event"].get("stream") or {}
            operations = [event.get("operation") for event in stream.get("events", []) if event.get("operation")]
            self.assertTrue(operations, "observed run names operations")
            close_session(Path(directory) / "probe", remove=True)

            started = start_session(
                root=root,
                vm_path=VM,
                target={"module": "mncs.vmcorpus.arith.v1", "name": "add3"},
                arguments=[int_arg(10)],
                compile_path=CORPUS,
                capture="none",
                stops=[{"id": "s", "target": {"kind": "operation", "instruction": operations[0]}}],
            )
            session = started["session"]
            self.assertEqual(session["state"], "live")
            self.assertEqual(started["event"]["event"], "stopped")
            stop = started["event"]["stop"]
            self.assertEqual(stop["safe_point"]["instruction"], operations[0])
            self.assertTrue(stop["continuation_token"])

            stack = inspect_session(root, "stack", max_frames=4, max_values=8)
            frames = stack["stack"]["frames"]
            self.assertEqual(len(frames), 1)
            self.assertGreaterEqual(len(frames[0]["values"]), 1)

            # Step into the nested call: the next stop is in the callee.
            stepped = step_session(root, "in")
            self.assertEqual(stepped["event"]["event"], "stopped")
            self.assertEqual(stepped["event"]["stop"]["safe_point"]["depth"], 1)

            finished = resume_session(root)
            self.assertEqual(finished["event"]["event"], "finished")
            self.assertEqual(finished["event"]["outcome"], {"kind": "completed"})
            returned = finished["event"]["record"]["returned"]
            self.assertEqual(returned[0]["Integer"]["value"], 13)

            attached = attach_session(root)
            self.assertFalse(attached["stale"])
            self.assertEqual(attached["state"], "finished")
            self.assertTrue(attached["finish_evidence"])

            closed = close_session(root, remove=True)
            self.assertTrue(closed["removed"])
            self.assertFalse(root.exists())

    def test_terminate_records_termination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = Path(directory) / "session"
            probe = start_add2(Path(directory) / "probe", capture="bounded")
            operations = [event.get("operation") for event in (probe["event"].get("stream") or {}).get("events", []) if event.get("operation")]
            close_session(Path(directory) / "probe", remove=True)
            started = start_add2(
                root,
                stops=[{"id": "s", "target": {"kind": "operation", "instruction": operations[0]}}],
            )
            self.assertEqual(started["event"]["event"], "stopped")
            finished = terminate_session(root)
            self.assertEqual(finished["event"]["outcome"]["kind"], "terminated")
            finish_path = root / "finish.json"
            self.assertTrue(finish_path.exists())
            evidence = json.loads(finish_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["schema_version"], LIVE_EVIDENCE_SCHEMA)
            close_session(root, remove=True)

    def test_bind_and_clear_stop_mid_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = Path(directory) / "session"
            probe = start_add2(Path(directory) / "probe", capture="bounded")
            operations = [event.get("operation") for event in (probe["event"].get("stream") or {}).get("events", []) if event.get("operation")]
            close_session(Path(directory) / "probe", remove=True)
            started = start_add2(
                root,
                stops=[{"id": "s", "target": {"kind": "operation", "instruction": operations[0]}}],
            )
            self.assertEqual(started["event"]["event"], "stopped")
            bound = bind_stop(root, {"kind": "failure_or_trap"}, "on-failure")
            self.assertEqual(bound["condition"]["id"], "on-failure")
            cleared = clear_stop(root, "on-failure")
            self.assertTrue(cleared["cleared"])
            cleared = clear_stop(root, "missing")
            self.assertFalse(cleared["cleared"])
            finished = continue_session(root)
            self.assertEqual(finished["event"]["event"], "finished")
            close_session(root, remove=True)

    def test_stale_daemon_close_repairs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = Path(directory) / "session"
            probe = start_add2(Path(directory) / "probe", capture="bounded")
            operations = [event.get("operation") for event in (probe["event"].get("stream") or {}).get("events", []) if event.get("operation")]
            close_session(Path(directory) / "probe", remove=True)
            started = start_add2(
                root,
                stops=[{"id": "s", "target": {"kind": "operation", "instruction": operations[0]}}],
            )
            self.assertEqual(started["event"]["event"], "stopped")
            daemon_pid = started["session"]["daemon_pid"]
            self.assertIsInstance(daemon_pid, int)
            os.kill(daemon_pid, 9)
            attached = attach_session(root)
            self.assertTrue(attached["stale"])
            self.assertIn("daemon", attached["stale_reason"])
            closed = close_session(root, remove=True)
            self.assertTrue(closed["removed"])
            self.assertFalse(root.exists())

    @unittest.skipUnless(STORE_AVAILABLE, "mncs-store embedded boundary not available")
    def test_retain_fetch_live_evidence(self) -> None:
        from mncs_debug.retain import fetch_live_evidence, retain_live_evidence

        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = Path(directory) / "session"
            started = start_add2(root, capture="bounded")
            self.assertEqual(started["event"]["event"], "finished")
            store = Path(directory) / "store"
            retained = retain_live_evidence(evidence_path=root / "finish.json", store_path=store)
            self.assertGreater(retained["bytes"], 0)
            fetched_path = Path(directory) / "fetched.json"
            fetched = fetch_live_evidence(
                store_path=store, evidence_id=retained["execution_identity"], output_path=fetched_path
            )
            self.assertEqual(fetched["integrity"], "valid")
            self.assertEqual(
                fetched_path.read_bytes(),
                (root / "finish.json").read_bytes(),
                "retained live evidence is byte-identical",
            )
            close_session(root, remove=True)


class LiveUnitTest(unittest.TestCase):
    def test_session_schema_validates(self) -> None:
        document = {
            "schema_version": LIVE_SESSION_SCHEMA,
            "protocol_version": 1,
            "session_id": "mncs:debug:live-session:test",
            "state": "live",
            "socket": "/tmp/test/debug.sock",
            "daemon_pid": 1234,
            "vm_binary": "/tmp/mncs-vm",
            "execution": "mncs:vm:execution:test",
            "artifact": "sha256:test",
            "callable": {"module": "m", "name": "f"},
            "stop_sequence": 1,
            "continuation_token": "dbg:test:1:nonce",
            "created_at": "2026-10-03T00:00:00+00:00",
            "updated_at": "2026-10-03T00:00:00+00:00",
            "finish": None,
        }
        self.assertEqual(validate_document(document, LIVE_SESSION_SCHEMA), [])

    def test_resolve_mncs_vm_explicit_wins(self) -> None:
        # An explicit executable path resolves to itself (first candidate).
        if not VM_AVAILABLE:
            self.skipTest("mncs-vm driver not available")
        self.assertEqual(resolve_mncs_vm(str(VM)), VM.resolve())

    def test_attach_missing_session_is_stale(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            attached = attach_session(Path(directory) / "missing")
            self.assertTrue(attached["stale"])
            self.assertFalse(attached["attached"])


if __name__ == "__main__":
    unittest.main()
