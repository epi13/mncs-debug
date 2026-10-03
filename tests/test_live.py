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
    run_pipe,
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
class LivePipeTest(unittest.TestCase):
    def _start_stopped(self, directory: str) -> Path:
        root = Path(directory) / "session"
        probe = start_session(
            root=Path(directory) / "probe",
            vm_path=VM,
            target={"module": "mncs.vmcorpus.arith.v1", "name": "add3"},
            arguments=[int_arg(10)],
            compile_path=CORPUS,
            capture="bounded",
        )
        operations = [event.get("operation") for event in (probe["event"].get("stream") or {}).get("events", []) if event.get("operation")]
        close_session(Path(directory) / "probe", remove=True)
        # add3 nests calls, so step_in stops again instead of finishing.
        started = start_session(
            root=root,
            vm_path=VM,
            target={"module": "mncs.vmcorpus.arith.v1", "name": "add3"},
            arguments=[int_arg(10)],
            compile_path=CORPUS,
            capture="none",
            stops=[{"id": "s", "target": {"kind": "operation", "instruction": operations[0]}}],
        )
        self.assertEqual(started["event"]["event"], "stopped")
        return root

    def _serve(self, root: Path, requests: list[dict]) -> list[dict]:
        import io

        infile = io.StringIO("\n".join(json.dumps(request) for request in requests) + "\n")
        outfile = io.StringIO()
        self.assertEqual(run_pipe(root, infile, outfile), 0)
        return [json.loads(line) for line in outfile.getvalue().splitlines() if line.strip()]

    def test_pipe_serves_many_ops_one_process(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = self._start_stopped(directory)
            responses = self._serve(
                root,
                [
                    {"id": 1, "op": "status"},
                    {"id": 2, "op": "inspect", "params": {"view": "stack"}},
                    {"id": 3, "op": "inspect", "params": {"views": ["stack", "effects", "stops"]}},
                    {"id": 4, "op": "bind_stop", "params": {"target": {"kind": "failure_or_trap"}, "id": "f"}},
                    {"id": 5, "op": "clear_stop", "params": {"id": "f"}},
                    {"id": 6, "op": "step_in"},
                    {"id": 7, "op": "continue"},
                ],
            )
            self.assertEqual([response["id"] for response in responses], [1, 2, 3, 4, 5, 6, 7])
            self.assertTrue(all(response["ok"] for response in responses), responses)
            self.assertEqual(responses[0]["result"]["state"], "live")
            self.assertIn("stack", responses[1]["result"])
            self.assertEqual(set(responses[2]["result"]["views"]), {"stack", "effects", "stops"})
            self.assertEqual(responses[3]["result"]["condition"]["id"], "f")
            self.assertTrue(responses[4]["result"]["cleared"])
            # Same bookkeeping as the one-shot path: stops appended, terminal evidence written.
            stops = json.loads((root / "stops.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(stops), 2)
            self.assertEqual(responses[6]["result"]["session"]["state"], "finished")
            self.assertTrue((root / "finish.json").exists())
            close_session(root, remove=True)

    def test_pipe_errors_fail_closed(self) -> None:
        import io

        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = self._start_stopped(directory)
            infile = io.StringIO(
                '{"id": 1, "op": "bogus"}\n'
                "not json\n"
                '{"id": 2}\n'
                '{"id": 3, "op": "inspect", "params": {"view": "nope"}}\n'
                '{"id": 4, "op": "status"}\n'
            )
            outfile = io.StringIO()
            self.assertEqual(run_pipe(root, infile, outfile), 0)
            responses = [json.loads(line) for line in outfile.getvalue().splitlines()]
            self.assertEqual([response["ok"] for response in responses], [False, False, False, False, True])
            self.assertEqual([response["id"] for response in responses], [1, None, 2, 3, 4])
            # The session is untouched by failed ops: still live at the first stop.
            attached = attach_session(root)
            self.assertFalse(attached["stale"])
            self.assertEqual(attached["stop_sequence"], 1)
            close_session(root, remove=True)

    def test_pipe_interleaves_with_one_shot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-live-test-") as directory:
            root = self._start_stopped(directory)
            first = self._serve(root, [{"id": 1, "op": "inspect", "params": {"view": "stack"}}])
            self.assertTrue(first[0]["ok"])
            stepped = step_session(root, "in")
            self.assertEqual(stepped["event"]["event"], "stopped")
            second = self._serve(root, [{"id": 2, "op": "status"}])
            self.assertTrue(second[0]["ok"])
            self.assertEqual(second[0]["result"]["stop_sequence"], stepped["session"]["stop_sequence"])
            close_session(root, remove=True)


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
