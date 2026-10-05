from __future__ import annotations

import errno
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mncs_debug.live import (
    LiveClient,
    LiveError,
    _reap_child,
    _wait_for_socket,
    start_session,
)


class _DeniedSocket:
    def __init__(self) -> None:
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        pass

    def connect(self, _path: str) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> _DeniedSocket:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class _StubbornChild:
    def __init__(self, *, exits_on_terminate: bool) -> None:
        self.exits_on_terminate = exits_on_terminate
        self.running = True
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.running:
            raise subprocess.TimeoutExpired("mncs-vm", timeout)
        return 0

    def poll(self) -> int | None:
        return None if self.running else 0

    def terminate(self) -> None:
        self.terminated = True
        if self.exits_on_terminate:
            self.running = False

    def kill(self) -> None:
        self.killed = True
        self.running = False


class LiveBootstrapTests(unittest.TestCase):
    def test_socket_probe_closes_denied_connection_and_fails_immediately(self) -> None:
        probe = _DeniedSocket()
        with patch("mncs_debug.live.socket.socket", return_value=probe):
            with self.assertRaisesRegex(
                LiveError, "debug daemon socket is inaccessible"
            ):
                _wait_for_socket(Path("/tmp/mncs-debug-denied.sock"))
        self.assertTrue(probe.closed)

    def test_client_closes_socket_when_connect_is_denied(self) -> None:
        connection = _DeniedSocket()
        with patch("mncs_debug.live.socket.socket", return_value=connection):
            with self.assertRaisesRegex(LiveError, "cannot reach debug daemon"):
                LiveClient(Path("/tmp/mncs-debug-denied.sock"))._connect()
        self.assertTrue(connection.closed)

    def test_owned_child_reaping_escalates_after_graceful_timeout(self) -> None:
        terminated = _StubbornChild(exits_on_terminate=True)
        _reap_child(terminated, graceful_timeout=0.0, terminate_timeout=0.0)  # type: ignore[arg-type]
        self.assertTrue(terminated.terminated)
        self.assertFalse(terminated.killed)
        self.assertFalse(terminated.running)

        killed = _StubbornChild(exits_on_terminate=False)
        _reap_child(killed, graceful_timeout=0.0, terminate_timeout=0.0)  # type: ignore[arg-type]
        self.assertTrue(killed.terminated)
        self.assertTrue(killed.killed)
        self.assertFalse(killed.running)

    def test_startup_socket_failure_reaps_spawned_daemon(self) -> None:
        child = _StubbornChild(exits_on_terminate=True)
        with tempfile.TemporaryDirectory(prefix="mncs-debug-start-") as directory:
            with patch("mncs_debug.live.subprocess.Popen", return_value=child):  # type: ignore[arg-type]
                with patch(
                    "mncs_debug.live._wait_for_socket",
                    side_effect=LiveError("debug daemon socket is inaccessible"),
                ):
                    with self.assertRaisesRegex(LiveError, "socket is inaccessible"):
                        start_session(
                            root=Path(directory) / "live",
                            vm_path=Path("/selected/mncs-vm"),
                            artifact_path=Path("/selected/artifact.json"),
                            target={"module": "mncs.test", "name": "main"},
                            arguments=[],
                        )
            self.assertTrue(child.terminated)
            self.assertFalse(child.running)
            self.assertFalse((Path(directory) / "live" / "session.json").exists())


if __name__ == "__main__":
    unittest.main()
