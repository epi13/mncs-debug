"""Generated-binding adapters for the MNCS-owned debug policy.

This module owns only process supervision and presentation normalization. The
generated binding owns the typed-call envelope, nominal enum identities, and
record shape. Semantic outcome/status/operation decisions are never decoded
through host integer tables.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .generated.debug import (
    Binding,
    BindingError,
    DebugOutcome,
    DecisionInput,
    DiagnosticOperation,
    EvidenceGap,
    EvidencePresence,
    EvidenceFactsInput,
    MinimizationStatus,
    ProvenanceClaimKind,
    ProvenanceClaimStatus,
    ProvenanceObservation,
    ReplayStatus,
    RuntimeStatus,
    SufficiencyInput,
    TraceCompleteness,
    TraceObservation,
)


class NativeCoreError(RuntimeError):
    pass


def default_core_path() -> Path:
    return Path(__file__).resolve().parents[1] / "native/mncs/debug/v1.mncs"


def _label(value: Any) -> str | None:
    """Render a generated enum as the established JSON spelling.

    This is presentation normalization only. It deliberately accepts enum
    instances, not arbitrary integers or strings supplied as semantic codes.
    """

    if not isinstance(value, (DebugOutcome, DiagnosticOperation, EvidenceGap)):
        return None
    name = value.value
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _runtime_status(value: str | RuntimeStatus) -> RuntimeStatus:
    if isinstance(value, RuntimeStatus):
        return value
    if not isinstance(value, str) or not value:
        raise NativeCoreError("runtime_status must be a generated RuntimeStatus")
    for candidate in RuntimeStatus:
        if value in {candidate.value, candidate.name}:
            return candidate
        if value == _label_like(candidate.value):
            return candidate
    raise NativeCoreError(f"unknown runtime status: {value}")


def _label_like(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def _binding(
    *, mncs_path: Path, core_path: Path | None, timeout_seconds: float
) -> Binding:
    core = core_path or default_core_path()
    if not core.exists():
        raise NativeCoreError(f"native debug core is missing: {core}")
    return Binding(str(mncs_path), core, timeout=timeout_seconds)


def decide(
    *,
    mncs_path: Path,
    runtime_status: str | RuntimeStatus,
    assertion_failed: bool = False,
    effect_failed: bool = False,
    core_path: Path | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Ask the native core for one typed semantic decision."""

    binding = _binding(
        mncs_path=mncs_path, core_path=core_path, timeout_seconds=timeout_seconds
    )
    try:
        decision = binding.decide(
            DecisionInput(
                runtime_status=_runtime_status(runtime_status),
                assertion_failed=assertion_failed,
                effect_failed=effect_failed,
            )
        )
    except (BindingError, ValueError, TypeError) as exc:
        raise NativeCoreError(f"native debug decision failed: {exc}") from exc
    outcome = _label(decision.outcome)
    if outcome is None:
        raise NativeCoreError("native debug core returned an unknown generated outcome")
    return {
        "outcome": outcome,
        "should_stop": decision.should_stop,
        "native_execution": binding.last_execution,
    }


def sufficiency(
    *,
    mncs_path: Path,
    has_failure_identity: bool,
    has_operation_identity: bool,
    observation_complete: bool,
    provenance_observed: bool,
    replay_required: bool = False,
    minimization_required: bool = False,
    core_path: Path | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Ask the native debugger policy for the next typed evidence operation."""

    binding = _binding(
        mncs_path=mncs_path, core_path=core_path, timeout_seconds=timeout_seconds
    )
    try:
        decision = binding.sufficiency(
            SufficiencyInput(
                has_failure_identity=has_failure_identity,
                has_operation_identity=has_operation_identity,
                observation_complete=observation_complete,
                provenance_observed=provenance_observed,
                replay_required=replay_required,
                minimization_required=minimization_required,
            )
        )
    except (BindingError, ValueError, TypeError) as exc:
        raise NativeCoreError(f"native debug sufficiency failed: {exc}") from exc
    status = _label_like(decision.status.value)
    operation = None if decision.next_operation is DiagnosticOperation.NoOperation else _label(decision.next_operation)
    gap = None if decision.evidence_gap is EvidenceGap.NoGap else _label(decision.evidence_gap)
    if status is None or (decision.next_operation is not DiagnosticOperation.NoOperation and operation is None):
        raise NativeCoreError("native debug core returned an unknown generated sufficiency value")
    return {
        "status": status,
        "sufficient": decision.sufficient,
        "next_operation": operation,
        "evidence_gap": gap,
        "native_execution": binding.last_execution,
    }


def reduce_evidence_facts(
    *,
    mncs_path: Path,
    trace_observations: list[TraceObservation],
    provenance_observations: list[ProvenanceObservation],
    replay_statuses: list[ReplayStatus],
    minimization_statuses: list[MinimizationStatus],
    core_path: Path | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Reduce bounded typed artifact observations through native policy."""

    def fixed(values: list[Any], capacity: int, default: Any) -> tuple[tuple[Any, ...], int, bool]:
        overflow = len(values) > capacity
        bounded = list(values[:capacity])
        bounded.extend(default for _ in range(capacity - len(bounded)))
        return tuple(bounded), min(len(values), capacity), overflow

    traces, trace_count, trace_overflow = fixed(
        trace_observations,
        16,
        TraceObservation(
            completeness=TraceCompleteness.Unknown,
            failure_anchor=EvidencePresence.Absent,
            operation_identity=EvidencePresence.Absent,
        ),
    )
    provenance, provenance_count, provenance_overflow = fixed(
        provenance_observations,
        64,
        ProvenanceObservation(
            kind=ProvenanceClaimKind.Other,
            status=ProvenanceClaimStatus.Unknown,
        ),
    )
    replay, replay_count, replay_overflow = fixed(
        replay_statuses, 16, ReplayStatus.Unknown
    )
    minimization, minimization_count, minimization_overflow = fixed(
        minimization_statuses, 16, MinimizationStatus.Unknown
    )

    binding = _binding(
        mncs_path=mncs_path, core_path=core_path, timeout_seconds=timeout_seconds
    )
    try:
        facts = binding.evidence_facts(
            EvidenceFactsInput(
                traces=traces,
                trace_count=trace_count,
                trace_overflow=trace_overflow,
                provenance=provenance,
                provenance_count=provenance_count,
                provenance_overflow=provenance_overflow,
                replay=replay,
                replay_count=replay_count,
                replay_overflow=replay_overflow,
                minimization=minimization,
                minimization_count=minimization_count,
                minimization_overflow=minimization_overflow,
            )
        )
    except (BindingError, ValueError, TypeError) as exc:
        raise NativeCoreError(f"native debug evidence reduction failed: {exc}") from exc
    return {
        "failure_anchor_present": facts.failure_anchor_present,
        "operation_identity_present": facts.operation_identity_present,
        "observation_complete": facts.observation_complete,
        "provenance_binding_present": facts.provenance_binding_present,
        "replay_established": facts.replay_established,
        "minimization_established": facts.minimization_established,
    }
