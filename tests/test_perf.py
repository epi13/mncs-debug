"""Performance-collateral unit tests: no subprocesses, no native calls.

Covers the debugger-side warm-path changes: narrow native library roots,
one shared native-artifact cache directory, and memoized runtime-binary
digests. All fast; failures here mean a per-call cost regression.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mncs_debug.native_core import _ensure_shared_native_cache, _libraries, default_core_path
from mncs_debug.protocol import sha256_file, sha256_file_memoized


class LibraryRootTests(unittest.TestCase):
    def test_library_roots_are_narrow(self) -> None:
        # The native launcher hashes every file under each library root
        # per call; a broad workspace root (mncs-test holds ~340 MB of
        # build outputs) costs tens of seconds. Only narrow source roots.
        roots = _libraries(default_core_path())
        names = [root.as_posix() for root in roots]
        self.assertFalse(
            any(name.rstrip("/").endswith("/mncs-test") for name in names),
            f"broad mncs-test root regressed: {names}",
        )
        self.assertTrue(
            any("mncs-test/native" in name for name in names),
            f"mncs.test.* source root missing: {names}",
        )


class SharedCacheTests(unittest.TestCase):
    def test_shared_cache_default_is_set(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MNCS_NATIVE_APPLICATION_CACHE_DIR", None)
            os.environ.pop("XDG_CACHE_HOME", None)
            with mock.patch("pathlib.Path.home", return_value=Path("/tmp/fake-home")):
                _ensure_shared_native_cache()
                self.assertEqual(
                    os.environ["MNCS_NATIVE_APPLICATION_CACHE_DIR"],
                    "/tmp/fake-home/.cache/mncs-native-applications",
                )

    def test_operator_cache_dir_wins(self) -> None:
        with mock.patch.dict(
            os.environ, {"MNCS_NATIVE_APPLICATION_CACHE_DIR": "/tmp/operator-cache"}
        ):
            _ensure_shared_native_cache()
            self.assertEqual(os.environ["MNCS_NATIVE_APPLICATION_CACHE_DIR"], "/tmp/operator-cache")


class MemoizedDigestTests(unittest.TestCase):
    def test_memo_matches_and_invalidates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-digest-test-") as directory:
            target = Path(directory) / "binary"
            target.write_bytes(b"v1-bytes")
            with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": directory}):
                first = sha256_file_memoized(target)
                self.assertEqual(first, sha256_file(target))
                second = sha256_file_memoized(target)
                self.assertEqual(second, first)
                # Content change with new mtime/size rehashes.
                target.write_bytes(b"v1-bytes-plus-more")
                # Ensure mtime granularity cannot hide the change.
                os.utime(target, (0, 0))
                third = sha256_file_memoized(target)
                self.assertEqual(third, sha256_file(target))
                self.assertNotEqual(third, first)


if __name__ == "__main__":
    unittest.main()
