# Native execution observability campaign

This report records the second campaign after the Profile 0.17 test/debug
integration. It deepens the compiler/runtime boundary; it does not replace
the ownership model established by the earlier family loop.

## Result

The reference runtime now emits one bounded, versioned observation stream
alongside the existing `execution-result/0.1`:

```text
mncs.execution-observation-policy/1
mncs.execution-observation/1
mncs.execution-source-map/1
```

The stream carries execution, frame, operation, result, return, effect, and
failure events. Events reference execution-scoped frames and typed values.
Values carry logical binding identity, version, observation kind, producer or
consumer operation references, and explicit full/truncated/digest/unavailable
capture status. Effects carry invocation/result identity, frame, operation,
capability, grant/provenance fields where available, value references, and a
replayability classification.

The semantic execution request is separate from capture policy. Changing
`none`, `failure-only`, `selected`, `bounded`, or `diagnostic` capture changes
the observation identity, not the program/request identity.

## Information-loss points found

| Pressure | Previous loss point | Owner-native correction | Current limit |
| --- | --- | --- | --- |
| P-001 | The runtime returned values but discarded intermediate producer/input relationships. | The executor now assigns bounded execution-scoped value identities and operation input/output references. | Full read/write history and watchpoints are not present. |
| P-002 | Semantic operation spans were not retained through executable lowering. | The compiler emits `mncs.execution-source-map/1`; runtime operation identities join it directly. | Synthetic operations remain explicitly unmapped. |
| P-003 | Nested call depth existed only as an implementation detail. | Runtime frames have stable identities, parent/call-operation relationships, arguments, depth, entry/exit events, and unwind fields. | The current task abstraction is not a scheduler/task execution model. |
| P-010 | The debugger launched multiple static/runtime collection commands and called the total tracing cost. | One native observe call is the normal path; benchmark modes separate event-sink cost from bootstrap/static collection. | The aggregate debugger still pays process and native semantic-core costs. |
| P-011 | Effects were flat metadata with incomplete causality. | Effect invoke/result events share an identity and reference operation/frame/value/capability data. | The current effect fixture has no input/result refs; environment capture and deterministic replay remain unsupported. |

## Compiler/source correspondence

The compiler maps module, function, test declaration, body block, semantic
operation, and source span. The runtime event carries the semantic operation
identity. `mncs-debug` joins the event to the compiler map, while
`mncs-language-service` resolves the same map for developer-facing source
locations. This avoids order matching, regex matching, and duplicated span
authorities. HIR/SSA artifacts retain their phase identities for phase-aware
joins; no source location is fabricated for generated operations.

## Debugger changes

`mncs-debug` uses the native stream on the current runtime path and no longer
needs its old validate/trace/IR/SSA/source-study collection sequence to build a
native witness. Compatibility fallback is versioned for older runtimes. The
debugger projects native frames, values, effects, provenance, and exact source
locations into its existing trace/inspection/provenance protocols. Forge and
Actions consume those projections without becoming semantic authorities.

The imported first-class failing test demonstrates that a returned assertion
failure is different from a runtime exception: `mncs-test` remains the verdict
authority, and the debugger records a complete bounded observation with
`failure_class = test_failure` without inventing a runtime failure operation.

## Evidence

- [`native-observability-demonstrations-2026-09.json`](../evidence/native-observability-demonstrations-2026-09.json) contains exact witness, observation, source-map, frame, value, effect, test, and Forge identities.
- [`native-observability-overhead-2026-09.json`](../evidence/native-observability-overhead-2026-09.json) contains five-run measurements separated by observation mode.
- The nested fixture produced 16 complete events, 5 values, and a truthful two-frame parent/child chain.
- The failing first-class test preserved the canonical run/test/execution identities and produced 52 complete events, 22 values, and 3 frames under requested `failure-only` / effective bounded capture.
- The effect fixture produced explicit `effect_invoke` and `effect_result` events sharing one effect identity.
- Forge’s native failure-loop test consumed the observation/source-map identities, produced a structured diagnosis, applied the bounded exact repair, and established canonical verification PASS.

## Overhead interpretation

On the checked-add fixture, direct execution was 7.55 ms median. Native
observation modes were 7.49–7.54 ms median. The old static bundle was 49.82 ms
median, while the complete debugger record was 715.16 ms median. The remaining
94.75x aggregate ratio is therefore not intrinsic native observation cost; it
is dominated by process/bootstrap, protocol, and the native semantic-core
invocation. Captures remain bounded.

## Pressure disposition

P-002 is resolved after the original operation-span reproducer and the
debugger, Forge, and language-service consumers pass. P-001, P-003, P-008,
P-010, and P-011 are partially resolved: their native observable tranche is
verified, but their broader requirements still include read/write history,
task ancestry, live execution control, aggregate bootstrap cost, or complete
effect/environment lineage. P-004 and P-005 remain open. P-012 remains an
operational storage/platform boundary. The machine-readable reconciliation is
in [`reconciliation-native-observability-2026-09.json`](../pressures/reconciliation-native-observability-2026-09.json).

## Boundaries intentionally retained

Process launch, timeout, filesystem/artifact movement, JSON transport,
content hashing, and the retained `mncs-embed` ABI remain host/bootstrap
boundaries. They transport or bound owner-emitted facts. Python no longer
owns source discovery, test aggregation, runtime frame inference, or native
value/effect meaning on the native path.

Safe suspension, watchpoints, expression evaluation, task scheduling,
deterministic replay, and ambient environment capture are not claimed.
