# mncs-debug first implementation campaign report

> Historical handoff: this report describes the isolated debugger foundation.
> The superseding 2026-09 family integration adds the owner-native
> `mncs-test` handoff, registered Actions provider, Forge failure loop,
> language-service source projection, and Commons pressure reconciliation.
> See [`docs/integration.md`](integration.md), the checked-in reconciliation
> ledger, and the final family campaign report in MNCS-Commons for current
> delivery state.

Date: 2026-09-13 (America/Anchorage)

This report is the handoff for the first debugging excursion. Work was
confined to `mncs-debug`; sibling repositories and Commons were inspected as
read-only references. The baseline is pinned in
[`docs/baseline/revisions.json`](baseline/revisions.json), and moving `main`
branches were not followed after capture.

## 1. Pinned baseline revisions

| Repository | Pinned `main` SHA | Role |
| --- | --- | --- |
| `mncs-language` | `39b777f19c7326002bea8f25182dc96f3fc4aa36` | language, compiler, reference runtime |
| `mncs-test` | `97ca6fa69faa67b077250d4e0945c0aaa2a3e45f` | structured test result/evidence |
| `mncs-actions` | `d8337dfff2d2d4ad8d14a676c784a448dc943f3d` | action transport, receipts, manifests, registry |
| `mncs-compiler` | `0222ebdab0dd56bbce00c77e0369af501751cd6b` | compiler architecture/pass provenance reference |
| `mncs-language-service` | `78ed96b3bf89ade67e98a079d1aff022f55d3091` | current LSP-adjacent service reference |
| `mncs-forge-mcp` | `d9f89df51130b1dbb499e97ee2982892d17ad7af` | Forge orchestration boundary |
| `MNCS-Commons` | `e93bbfaceb57e5ad28e4948d1bab2925c76fcdf9` | coordination/pressure conventions |
| `RAVEL` | `c156d9ce7b3405562bdcdcb1e7b0a6e7532aa067` | runtime/compiler execution consumer |
| `mncs-index` | `ee6a0a7fc57969ebdc6c9f571ce189438766e8bb` | family registry/discovery reference |
| `machine-native-complexity-standard` | `0735b9f721a1901f2291433ae0bf9193bf913222` | standard vocabulary reference |
| `mncs-cli` | `860376e862ccb73d331d20b2025fe5ca51041b50` | CLI convention reference |
| `mncs-harness` | `cd3927b5a24597a16bdcc867e444b2dbb10937ef` | harness/evidence convention reference |
| `mncs-debug` initial remote `main` | `9524ea24fab44a6dfa6cac2a4846d5fd97e33c9b` | empty-repository starting point |

The local language checkout was on `90a36226ff0ad4d696b361afc813792963b54db8`
on a concurrent campaign branch and was not touched. Its observed binary was
used only as a clearly identified reference executable:

```text
binary: /home/epi13/Documents/Projects/mncs-language/target/debug/mncs
sha256: 1509c72616da3e986d0fcde404de60db2dc0798d3290159e148e587a65c67a67
observed checkout: 90a36226ff0ad4d696b361afc813792963b54db8
```

The local Commons checkout was behind its remote `main` and was not changed.
A pinned-main rebuild was attempted in a temporary worktree and reached
codegen before the host filesystem quota was exhausted; the existing binary
was retained as an observed witness, not silently treated as the pinned build.

## 2. Repository architecture created

```text
native/mncs/debug/v1.mncs       MNCS-owned outcome/stop semantic core
mncs_debug/protocol.py          canonical JSON, identity, bounds, validation
mncs_debug/runner.py            narrow runtime/compiler process adapter
mncs_debug/trace.py             event/trace normalization and completeness
mncs_debug/analysis.py          inspection, provenance, replay, minimization
mncs_debug/capabilities.py      explicit capability discovery
mncs_debug/cli.py               JSON-first CLI and JSONL provider API
schemas/                        versioned protocol schemas
integration/                    local actions, Forge, LSP, and test contracts
tests/fixtures/                 deterministic programs, requests, test result
tests/                         dependency-free native/host boundary tests
pressures/                      local evidence ledger; no Commons publication
evidence/                       small checked-in demonstrations/measurements
docs/                           architecture, CLI, integration, baseline, report
scripts/measure_overhead.py     bounded bootstrap-cost probe
```

## 3. Implemented debugger capabilities

Implemented and exercised:

- structured recording of MNCS execution requests into content-derived
  witnesses;
- exact preservation of current runtime status, identities, bounded steps,
  block/operation/terminator trace entries, effects, failures, and returns;
- derived single-entry function boundary events;
- bounded static projection of trace map, HIR/IR, SSA, and source-study
  compiler/pass identities;
- terminal immutable inspection sessions, frame/value/effect projections;
- trace kind/operation/range slices;
- partial provenance from failure identity, static dataflow, request arguments,
  compiler identity, and bounded event order;
- structured compile, runtime, assertion/test, unsupported, invalid,
  timeout/budget, and infrastructure classifications through the native core;
- trace replay, bounded re-execution, and deterministic-replay rejection;
- conservative integer-input minimization;
- `mncs.test-result/1` import with full result preservation and library-root
  consumption;
- witness integrity validation and corrupt-witness rejection; and
- Forge-ready one-shot and newline-delimited API responses.

Not implemented because the baseline cannot support them correctly:

- live suspension, resume, pause, continue, semantic breakpoints;
- intermediate value/write history, watchpoints, or arbitrary expression
  evaluation;
- nested runtime frames, closure capture inspection, task/process ancestry;
- deterministic scheduler/effect/environment replay; and
- exact source operation spans or source-bound breakpoint resolution.

## 4. Debug protocol/schema

The initial versioned family is:

```text
mncs.debug-session/1
mncs.debug-event/1
mncs.debug-trace/1
mncs.debug-witness/1
mncs.debug-replay/1
mncs.debug-capabilities/1
mncs.debug-inspection/1
mncs.debug-provenance/1
mncs.debug-api/1
mncs.debug-validation/1
mncs.debug-minimization/1
```

JSON Schemas are in `schemas/`. The authoritative semantic membrane is:

```text
DebugExecutionIdentity
  → DebugEvent {identity, sequence, kind, location, payload, relationships}
  → DebugTrace {bounded ordered events, selected values, completeness}
  → DebugWitness {program/request/compiler/runtime/outcome/artifacts/replay}
  → Inspection | Provenance | Replay conclusions
```

Identity is canonical-JSON SHA-256 based, stable for the same content, and
does not depend on wall-clock time. The witness digest excludes only its own
identity (and any future non-semantic creation timestamp).

## 5. CLI surface

```text
capabilities
record | run PROGRAM REQUEST
open WITNESS
inspect WITNESS
trace WITNESS [filters]
why WITNESS [operation/value/question]
replay WITNESS --mode trace|reexecute [--deterministic]
minimize WITNESS
validate ARTIFACT
import-test TEST_RESULT
export WITNESS
api --request FILE | --stdio
```

All artifacts are JSON-first. Exit status reports outcome while `--output`
preserves the witness. `provider` is a temporary alias for `api`; it is not an
actions registry entry.

## 6. Self-hosting/bootstrap status

The campaign reached Stage 3:

```text
0  reference MNCS runtime emits structured execution result
1  host launcher supervises process and bounded artifacts
2  MNCS source owns classification and stop policy
3  debugger records/inspects deterministic fixtures and imports test evidence
4  live mncs-debug self-debugging with suspension/frames — not reached
5  host tools only as emergency/differential witnesses — future direction
```

The native file `native/mncs/debug/v1.mncs` is invoked for every recording and
decides `Outcome` plus `should_stop`. There is no host semantic fallback. If
the core is unavailable, the witness explicitly says classification is not
established.

## 7–8. Native versus host code and every host boundary

Native semantic code is currently the outcome/stop decision core: 84 lines of
MNCS source including comments and explicit transport mapping. The rest is
host code because the current MNCS profile has no process, filesystem, JSON,
compiler-artifact import, or live debug-session facilities.

| Host area | Classification | Semantic impact |
| --- | --- | --- |
| process launch, pipes, timeout, executable selection | legitimate platform/bootstrap boundary | required to cross into current runtime; timeout can perturb execution |
| bounded JSON/text/base64, SHA-256, directory artifacts | legitimate artifact/transport boundary | carries facts; does not infer MNCS values |
| execute/validate/trace/IR/SSA/source-study invocation | legitimate platform/bootstrap boundary | consumes existing structured runtime/compiler commands |
| HIR/SSA/source-study normalization | temporary adapter caused by P-002 | projection only; exact identities are retained, missing spans remain null |
| witness/session/trace/provenance queries | temporary adapter caused by P-001/P-003/P-004 | derives only documented partial facts |
| minimization candidate orchestration | temporary adapter caused by absent native process/invocation API | mutates only request integers and uses exact bounded signature |
| selected `mncs` executable | independent differential/reference witness | provides current behavior without sibling changes |

GDB/LLDB/perf/Python instrumentation were not used as the architecture. No
large host interpreter or regex-based semantic engine was added. The only
source scan is a labeled function-declaration location fallback.

## 9. `mncs-test` interoperability

The pinned `mncs-test` self-suite was run successfully:

```text
run_id: 47a2d73d9853245613a0c0d975891141b96084f1de6bb202d358909591742050
verdict/classification: PASS / success
5 passed, 1 skipped, 6 total, authority=native_suite
```

The real pinned failed-assertion result was imported:

```text
source run_id: 20c43a07994d4cbb9f855d17332201fa65966042a130ef0f22c010e9b4bcac79
test: failing-assertion
debug outcome: test_failure
native decision: assertion_failure
library roots consumed: 2
```

The complete test result is preserved under `integration.result`; test verdict
and assertion meaning remain test-owned. Re-execution of an imported test
witness is structured `blocked` because a request rerun is not a test-provider
assertion rerun. A missing source/request is rejected rather than rebuilt from
`reproduction.command` text.

The same result's real `task-lifecycle` test was imported successfully, but its
debug trace contained no task/effect lifecycle events. That negative
observation is preserved in `evidence/campaign-demonstrations.json` and is
evidence for the runtime frame/task and effect-lineage pressures.

## 10. Actions, Forge, and LSP contracts

- `integration/mncs-actions-provider.json` defines a future provider using
  `mncs.execution-receipt/1` and `mncs.evidence-manifest/1` output conventions.
  It is not registered and no actions code changed.
- `integration/forge-api.md` defines machine operations for capabilities,
  open, inspect, trace, why, replay, and minimize. Forge owns orchestration and
  conclusions; the debugger owns facts and guarantees.
- `integration/lsp-contract.json` requires source identity/revision, URI/path,
  symbol, span coordinate encoding, binding status, and operation identity.
  Current operation bindings are unavailable, so no breakpoint claim is made.

## 11. Tests, fixtures, and demonstrations

Validation run:

```text
python3 -m unittest discover -s tests -p 'test_*.py' -v
12 tests, OK
```

The fixtures cover success, checked overflow, nested calls, compile rejection,
native semantic decisions, an imported failed test result, and corrupt witness
rejection. JSON Schema validation was also run against witness, capabilities,
trace, inspection, provenance, and replay outputs using `jsonschema`.

The checked-in summaries are:

- [`evidence/campaign-demonstrations.json`](../evidence/campaign-demonstrations.json)
- [`evidence/overhead-baseline.json`](../evidence/overhead-baseline.json)

## 12. Performance and boundedness observations

For the checked-add fixture and five iterations on the selected local runtime:

```text
direct execute median: 7.57 ms
record median:         1065.79 ms
median overhead:       1058.22 ms, 140.85×
```

This is bootstrap process/static-evidence collection overhead, not a native
runtime tracing benchmark. The result motivates P-010. Captures are bounded at
64 KiB streams, 256 KiB embedded inputs, 512 trace events, and 2,048 static
records; full content digests remain available.

## 13. Pressures grouped by owning layer

### Language/runtime/compiler

- P-001: typed intermediate values/write history absent;
- P-002: operation source spans disappear before execution;
- P-003: nested call/frame/task ancestry absent;
- P-004: no safe suspension/resume/session contract;
- P-005: no deterministic scheduler/effect/environment replay;
- P-009: compiler failures do not consistently emit a debugger diagnostic
  artifact; and
- P-011: effects lack complete value/input/result/environment lineage.

### `mncs-test`

- P-006: failed test handoff needs stable source/request evidence and should
  never depend on command-text reconstruction.

### `mncs-actions`

- P-007: provider registration and receipt/evidence projection remain a later
  actions integration, not a debugger-local registry.

### LSP/compiler

- P-008: exact source binding and breakpoint resolution contract is missing.

### `mncs-debug`/runtime/platform

- P-010: current multi-process static collector has high bootstrap cost; and
- P-012: the exact pinned reference-runtime rebuild exceeded available
  workspace quota, so the observed binary was kept distinct from the baseline.

Every record under `pressures/` contains exact pinned revisions, reproducer,
expected/actual behavior, workaround, host classification, evidence, affected
modules, dependencies, and resolution criteria. No record was published to
Commons.

## 14–15. What must become first-class for first-class debugging

The evidence divides the answer sharply.

Must become language/compiler/runtime first-class:

1. semantic source maps that carry exact source spans through lowering and
   execution;
2. stable runtime frame/task/execution ancestry and closure/capture identity;
3. bounded typed value observations with producer/read/write identity;
4. safe semantic suspension points and stop-condition/session protocol;
5. explicit scheduler/effect/environment capture and replay compatibility; and
6. structured compiler/runtime diagnostics and effect invocation/result
   lineage.

Belongs in `mncs-debug`: protocol versioning, bounded artifact policy,
normalization, witness integrity, capability discovery, inspection/provenance
queries, replay guarantee labeling, and conservative minimization.

Belongs in `mncs-test`: test verdict, assertion/test-result semantics, test
selection, and the stable content-addressed handoff evidence identified by
P-006.

Belongs in `mncs-actions`: invocation/correlation, provider registration,
execution receipts, evidence manifests, and artifact transport.

Belongs in LSP: source-document identity, symbol/span mapping, diagnostics,
and editor-side breakpoint/hover binding.

Belongs in Forge: orchestration, cross-run reasoning, prioritization, and
human-facing conclusions over trustworthy debug facts.

Legitimate host/platform boundaries remain process supervision, OS timeouts,
filesystem/artifact transport, and the independent current runtime witness.

## 16. Capabilities attempted but not yet possible

The implementation attempted breakpoint/step/pause/continue, watchpoints,
intermediate value inspection, nested backtrace, expression evaluation, task
ancestry, deterministic replay, exact operation source locations, complete
effect provenance, and live self-debugging. Each is either `unsupported` or
`partially_supported` in `mncs.debug-capabilities/1` and has a local pressure
record where the missing primitive matters.

## 17. Delivery state

The implementation branch is `campaign/debugger-foundation`, based on the
initial `mncs-debug` main SHA above. The foundation commit is `b1605b9`
(`feat: add structured MNCS debugger foundation`), followed by report and
evidence-validation commits `9f56572` and `17beac9`. The delivery handoff
records the final metadata commit, merge, and pushed `main` SHA. No sibling
branch was merged or pushed.

## 18. Recommended later integration campaign order

1. Wait for the concurrent `mncs-language`/`mncs-test` campaign to finish and
   capture fresh SHAs; do not reconcile against its moving branch.
2. Re-run the fixtures and compare every local pressure to the new execution,
   diagnostic, source-map, and test-result contracts.
3. Promote source maps, value observations, frame identity, and structured
   diagnostics first; these are the information-loss boundaries that
   `mncs-debug` cannot repair later.
4. Promote scheduler/effect/environment replay and safe suspension only with
   explicit boundedness, security, and capability semantics.
5. Update `mncs-test` to guarantee debuggable failure references without
   duplicating debugger semantics.
6. Register the actions provider and verify receipt/evidence digests end to end.
7. Add LSP binding and Forge orchestration only after exact source/runtime
   identity contracts are stable.
8. Re-measure overhead and retire host adapters incrementally as native event
   and metadata APIs become available.
