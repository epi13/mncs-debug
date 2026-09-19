from __future__ import annotations

import os
import unittest
from pathlib import Path

from mncs_debug.native_core import decide, diagnostic_loop, sufficiency
from mncs_debug.generated.debug import (
    EvidencePresence,
    MinimizationStatus,
    ProvenanceClaimKind,
    ProvenanceClaimStatus,
    ProvenanceObservation,
    ReplayStatus,
    TraceCompleteness,
    TraceObservation,
)


RUNTIME = Path(os.environ.get("MNCS", "/home/epi13/Documents/Projects/mncs-language/target/debug/mncs"))


@unittest.skipUnless(RUNTIME.is_file() and os.access(RUNTIME, os.X_OK), "MNCS runtime not available")
class NativeSemanticCoreTests(unittest.TestCase):
    def test_success_is_not_a_stop(self) -> None:
        decision = decide(mncs_path=RUNTIME, runtime_status="Returned")
        self.assertEqual(decision["outcome"], "success")
        self.assertFalse(decision["should_stop"])

    def test_runtime_and_compile_failures_stop(self) -> None:
        runtime = decide(mncs_path=RUNTIME, runtime_status="RuntimeFailure")
        compile_failure = decide(mncs_path=RUNTIME, runtime_status="CompileFailure")
        self.assertEqual(runtime["outcome"], "runtime_failure")
        self.assertEqual(compile_failure["outcome"], "compile_failure")
        self.assertTrue(runtime["should_stop"])
        self.assertTrue(compile_failure["should_stop"])

    def test_sufficiency_stops_or_names_one_next_operation(self) -> None:
        sufficient = sufficiency(
            mncs_path=RUNTIME,
            has_failure_identity=True,
            has_operation_identity=True,
            observation_complete=True,
            provenance_observed=True,
        )
        self.assertEqual(sufficient["status"], "sufficient")
        self.assertIsNone(sufficient["next_operation"])
        ambiguous = sufficiency(
            mncs_path=RUNTIME,
            has_failure_identity=True,
            has_operation_identity=False,
            observation_complete=True,
            provenance_observed=False,
        )
        self.assertEqual(ambiguous["status"], "ambiguous")
        self.assertEqual(ambiguous["next_operation"], "trace")
        self.assertEqual(ambiguous["evidence_gap"], "operation_identity")

        missing_failure_anchor = sufficiency(
            mncs_path=RUNTIME,
            has_failure_identity=False,
            has_operation_identity=False,
            observation_complete=True,
            provenance_observed=False,
        )
        self.assertEqual(missing_failure_anchor["status"], "ambiguous")
        self.assertEqual(missing_failure_anchor["next_operation"], "trace")
        self.assertEqual(missing_failure_anchor["evidence_gap"], "failure_identity")

    def test_native_bounded_loop_escalates_replay_mismatch_to_minimization(self) -> None:
        decision = diagnostic_loop(
            mncs_path=RUNTIME,
            trace_observations=[
                TraceObservation(
                    failure_anchor=EvidencePresence.Present,
                    operation_identity=EvidencePresence.Present,
                    completeness=TraceCompleteness.Complete,
                )
            ],
            provenance_observations=[
                ProvenanceObservation(
                    kind=ProvenanceClaimKind.OperationIdentity,
                    status=ProvenanceClaimStatus.Observed,
                )
            ],
            replay_statuses=[ReplayStatus.Mismatch],
            minimization_statuses=[MinimizationStatus.Unknown],
            step_budget=4,
        )
        self.assertEqual(decision["status"], "ambiguous")
        self.assertEqual(decision["next_operation"], "minimization")
        self.assertEqual(decision["evidence_gap"], "minimization")
        self.assertTrue(decision["replay_mismatch"])


if __name__ == "__main__":
    unittest.main()
