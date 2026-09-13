from __future__ import annotations

import os
import unittest
from pathlib import Path

from mncs_debug.native_core import decide


RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))


@unittest.skipUnless(RUNTIME.is_file() and os.access(RUNTIME, os.X_OK), "MNCS runtime not available")
class NativeSemanticCoreTests(unittest.TestCase):
    def test_success_is_not_a_stop(self) -> None:
        decision = decide(mncs_path=RUNTIME, status_code=0)
        self.assertEqual(decision["outcome"], "success")
        self.assertFalse(decision["should_stop"])

    def test_runtime_and_compile_failures_stop(self) -> None:
        runtime = decide(mncs_path=RUNTIME, status_code=1)
        compile_failure = decide(mncs_path=RUNTIME, status_code=5)
        self.assertEqual(runtime["outcome"], "runtime_failure")
        self.assertEqual(compile_failure["outcome"], "compile_failure")
        self.assertTrue(runtime["should_stop"])
        self.assertTrue(compile_failure["should_stop"])


if __name__ == "__main__":
    unittest.main()
