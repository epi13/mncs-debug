# Integration contracts

The debugger is a canonical consumer of structured execution facts. It does
not own test selection or assertion semantics, and it does not reconstruct
provider requests from terminal prose.

## `mncs-test` → `mncs-debug`

`mncs-test run` emits `mncs.test-result/1`. For compiler-inventoried Profile
0.17 tests, every selected execution that reaches the retained native session
contains a canonical request, an artifact reference, and execution lineage:

```json
{
  "request": {
    "schema_version": "0.1",
    "target": {"module": "...", "function": "..."},
    "arguments": [],
    "step_budget": 200000
  },
  "request_artifact_ref": {"kind": "execution-request", "path": "...", "sha256": "..."},
  "execution_lineage": {
    "test_case_identity": "...",
    "execution_identity": "...",
    "observation_identity": "...",
    "oracle_evaluation_identity": "...",
    "source": {"path": "...", "sha256": "...", "span": {}}
  }
}
```

`mncs-debug import-test` selects an exact failing test, validates the canonical
request, retains a `test_result_reference`, and carries the selected
test/declaration/subject/execution identities into `mncs.debug-witness/1`.
The complete test result remains under the debugger integration projection;
the debugger never changes the test verdict.

Missing source or request evidence is a contract error. No command string or
human summary is parsed as a fallback.

## `mncs-actions`

`actions/mncs-debug/action.yml` and its transport script are the registered
Actions provider. They accept either a `mncs.test-result/1` artifact or a
program/request pair, invoke the pinned debugger with a bounded capture policy,
validate the witness, and package references to:

```text
mncs.debug-witness/1
mncs.debug-validation/1
mncs.debug-inspection/1
mncs.debug-trace/1
mncs.debug-provenance/1
mncs.debug-replay/1
mncs.check-result/1
execution receipt / evidence manifest
```

Failure-only capture is conditional: a passing test produces an explicit
`UNKNOWN`/`not_requested` debug claim and does not alter the test PASS. A
malformed witness removes the debug check so Actions emits `INVALID` or
`NOT_ESTABLISHED` according to its existing membrane rules.

## Forge

Forge exposes `development.mncs.failure-loop` through its CLI, Python facade,
and MCP operation registry. It invokes explicit argv prefixes and reads only
versioned JSON artifacts. On a test FAIL it requests debugger capabilities,
imports the selected failure, validates and opens the witness, then requests
inspection, a bounded trace slice, provenance/why, trace replay, and optional
bounded minimization. It can apply one exact candidate replacement only under
development authority and reruns `mncs-test` for verification.

The resulting Forge record preserves the test result/check references, debug
artifact references, execution observations, diagnosis status, before/after
source digests, and test/debug identity continuity. A test FAIL remains a
FAIL until the canonical verification run establishes PASS; unavailable debug
evidence is UNKNOWN and never becomes a confident diagnosis.

The lower-level `mncs-debug api --stdio` remains available for provider clients
that want one JSONL request/response membrane. It exposes `capabilities`,
`open`, `inspect`, `trace`, `why`, `replay`, and `minimize` without claiming
unsupported live suspension, watchpoints, expression evaluation, or
deterministic effect replay.

## LSP/source binding

`integration/lsp-contract.json` is the shared vocabulary for source identity,
revision, URI/path, module/function/test identity, source span coordinate
encoding, runtime operation identity, and binding status. Compiler-inventory
declaration spans are exact and are carried through the test/debug lineage.
Runtime operation spans and live breakpoint resolution remain unavailable;
clients must display that capability state rather than infer a location from
source text.
