"""Truthful capability discovery for the pinned runtime boundary."""

from __future__ import annotations

from typing import Any

from . import __version__
from .protocol import CAPABILITIES_SCHEMA, PROTOCOL_VERSION, identity


def capability_document(*, runtime_path: str | None = None, runtime_digest: str | None = None) -> dict[str, Any]:
    capabilities = [
        {
            "id": "structured_execution_result",
            "state": "supported",
            "owner": "mncs-language/runtime",
            "evidence": "mncs execution-result/0.1 exposes status, identities, bounded trace, and effects",
        },
        {
            "id": "native_bounded_execution_observation",
            "state": "supported",
            "owner": "mncs-language/runtime",
            "evidence": "mncs.execution-observation/1 is emitted beside the unchanged execution-result/0.1 with explicit capture bounds",
        },
        {
            "id": "bounded_semantic_trace",
            "state": "supported",
            "owner": "mncs-debug",
            "evidence": "block, operation, terminator, effect, and terminal events are normalized into debug-event/1",
        },
        {
            "id": "function_entry_exit",
            "state": "supported",
            "owner": "mncs-language/runtime",
            "evidence": "execution-scoped frame_enter/frame_exit events preserve nested parent and call-operation identities",
        },
        {
            "id": "source_function_location",
            "state": "supported",
            "owner": "mncs-language/compiler",
            "evidence": "mncs.execution-source-map/1 carries compiler-owned declaration and semantic operation source spans",
        },
        {
            "id": "source_operation_location",
            "state": "supported",
            "owner": "mncs-language/compiler",
            "evidence": "runtime operation identities join exact lowered semantic operation spans without order or text inference",
        },
        {
            "id": "compiler_pass_provenance",
            "state": "partially_supported",
            "owner": "mncs-language/compiler",
            "evidence": "source-study and HIR/SSA contain stage fingerprints and pass identities when requested",
        },
        {
            "id": "return_value_inspection",
            "state": "supported",
            "owner": "mncs-language/runtime",
            "evidence": "bounded typed value observations retain argument and operation-result identities, versions, and explicit full/truncated/digest captures",
        },
        {
            "id": "frames",
            "state": "supported",
            "owner": "mncs-language/runtime",
            "evidence": "nested and repeated calls emit execution-scoped frame identities with parent and call-operation relationships",
        },
        {
            "id": "effects",
            "state": "partially_supported",
            "owner": "mncs-language/runtime",
            "evidence": "effect invocation/result observations retain frame, input value, result value, capability and grant provenance; external environment replay remains outside the contract",
        },
        {
            "id": "runtime_failure_localization",
            "state": "supported",
            "owner": "mncs-language/runtime",
            "evidence": "failure identity names the operation or function and the structured reason is preserved",
        },
        {
            "id": "assertion_failure_localization",
            "state": "partially_supported",
            "owner": "mncs-test",
            "evidence": "test-result/1 can be imported; current assertion evidence does not always carry a semantic runtime identity",
        },
        {
            "id": "trace_replay",
            "state": "supported",
            "owner": "mncs-debug",
            "evidence": "a stored bounded trace can be inspected without re-execution",
        },
        {
            "id": "bounded_reexecution",
            "state": "bootstrap_host_boundary",
            "owner": "mncs-debug/mncs-language",
            "evidence": "the launcher can re-submit an immutable request to the external mncs executable",
        },
        {
            "id": "deterministic_replay",
            "state": "unsupported",
            "owner": "mncs-language/runtime",
            "evidence": "no scheduler control, nondeterministic effect log, or environment snapshot contract exists",
        },
        {
            "id": "breakpoints",
            "state": "unsupported",
            "owner": "mncs-language/runtime",
            "evidence": "there is no safe suspension or runtime stop-condition API",
        },
        {
            "id": "step_continue_pause",
            "state": "unsupported",
            "owner": "mncs-language/runtime",
            "evidence": "execution is a bounded request, not a resumable session",
        },
        {
            "id": "watchpoints",
            "state": "unsupported",
            "owner": "mncs-language/runtime",
            "evidence": "native value versions and writes are inspectable after a bounded run, but the runtime has no safe suspension or stop-condition API",
        },
        {
            "id": "expression_evaluation",
            "state": "unsupported",
            "owner": "mncs-language/compiler/runtime",
            "evidence": "no in-process typed expression invocation/debug context contract exists",
        },
        {
            "id": "tasks_and_scheduler",
            "state": "unsupported",
            "owner": "mncs-language/runtime",
            "evidence": "the current execution result has no task/process ancestry or scheduler identity",
        },
        {
            "id": "test_result_import",
            "state": "supported",
            "owner": "mncs-debug/mncs-test",
            "evidence": "test-result/1 is consumed by reference and embedded request evidence is preserved",
        },
        {
            "id": "conservative_integer_minimization",
            "state": "partially_supported",
            "owner": "mncs-debug",
            "evidence": "bounded request mutations retain only exact failure-signature matches",
        },
        {
            "id": "forge_machine_interface",
            "state": "supported",
            "owner": "mncs-debug",
            "evidence": "debug-api/1 JSON requests are available through one-shot and JSONL stdin modes",
        },
        {
            "id": "actions_provider",
            "state": "supported",
            "owner": "mncs-actions",
            "evidence": "mncs-actions/actions/mncs-debug validates and transports bounded witness, observation, source-map, trace, provenance, replay, receipt, and evidence-manifest artifacts",
        },
        {
            "id": "native_semantic_core",
            "state": "supported",
            "owner": "mncs-language/mncs-debug",
            "evidence": "native/mncs/debug/v1.mncs is invoked through the current executor for outcome decisions",
        },
    ]
    material = {
        "protocol_version": PROTOCOL_VERSION,
        "debugger": "mncs-debug",
        "version": __version__,
        "capabilities": capabilities,
        "runtime": {"path": runtime_path, "sha256": runtime_digest},
    }
    document = {
        "schema_version": CAPABILITIES_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "debugger": "mncs-debug",
        "debugger_version": __version__,
        "capabilities_id": identity("capabilities", material),
        "capabilities": capabilities,
        "protocols": [
            "mncs.debug-session/1",
            "mncs.debug-event/1",
            "mncs.debug-trace/1",
            "mncs.debug-witness/1",
            "mncs.debug-replay/1",
            "mncs.debug-capabilities/1",
            "mncs.debug-inspection/1",
            "mncs.debug-provenance/1",
            "mncs.debug-api/1",
            "mncs.debug-validation/1",
            "mncs.debug-minimization/1",
        ],
        "runtime": {"path": runtime_path, "sha256": runtime_digest},
        "identity_basis": "content-derived capability list plus selected runtime digest; wall-clock facts are excluded",
    }
    return document
