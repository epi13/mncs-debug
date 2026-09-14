# mncs-debug

Self-hosted debugging, tracing, replay, and execution introspection for the
MNCS ecosystem.

`mncs-debug` is a structured debugger consumer for the current MNCS language
and reference runtime. It turns the runtime's bounded execution result and the
compiler's HIR/SSA/trace artifacts into versioned debug events, traces,
witnesses, inspection results, and replay reports. MNCS-native code owns the
small semantic decision core; the Python launcher is a narrow process and
artifact boundary.

The machine-readable documents are authoritative. Terminal summaries are only
projections of those documents.

## Current status

The initial implementation can:

- execute a checked MNCS request and preserve a content-derived
  `mncs.debug-witness/1`;
- normalize block, semantic-operation, terminator, effect, failure, and
  derived entry/exit observations into bounded `mncs.debug-event/1` and
  `mncs.debug-trace/1` documents;
- retain runtime, program, request, compiler, source, HIR, SSA, and
  `source-study` identities where the selected runtime emits them;
- inspect an immutable terminal session, return trace slices, and answer
  conservative partial provenance questions;
- replay a saved trace without executing it, or re-submit an embedded request
  for bounded reproduction;
- reject deterministic replay claims when scheduler, effect, or environment
  capture is unavailable;
- import a pinned `mncs.test-result/1` document without inventing a parallel
  test-result protocol;
- attempt conservative integer-input minimization while preserving an exact
  bounded failure signature; and
- expose capability discovery and a newline-delimited Forge-ready API.

The current runtime cannot provide true suspended sessions, source-level
operation spans, nested runtime frames, intermediate value snapshots,
watchpoints, expression evaluation, task ancestry, scheduler control, or
deterministic effect replay. These are represented as capability states and
local pressure records, not hidden behind a fake debugger interface.

This is intentionally not GDB/LLDB with MNCS text around it. GDB and LLDB can
remain independent investigative witnesses, but the stable model here is
execution identity → semantic event → transition/effect/failure → trace →
witness.

## Quick start

The launcher accepts an explicit reference runtime. The `MNCS` environment
variable is convenient for local work:

```bash
MNCS=/path/to/mncs ./bin/mncs-debug capabilities

MNCS=/path/to/mncs ./bin/mncs-debug record \
  tests/fixtures/checked-add.mncs.json \
  tests/fixtures/checked-add-overflow-request.json \
  --output /tmp/checked-add.witness.json --format text

./bin/mncs-debug validate /tmp/checked-add.witness.json --format text
./bin/mncs-debug inspect /tmp/checked-add.witness.json --format text
./bin/mncs-debug trace /tmp/checked-add.witness.json --kind failure
./bin/mncs-debug why /tmp/checked-add.witness.json
./bin/mncs-debug replay /tmp/checked-add.witness.json --mode trace
./bin/mncs-debug replay /tmp/checked-add.witness.json --mode reexecute \
  --mncs /path/to/mncs
```

`record` exits zero for a successful execution or imported test failure and
non-zero for a runtime/compile/unsupported/infrastructure outcome. The JSON
written to `--output` remains available regardless of that outcome.

The default resolver checks `--mncs`, `MNCS`, the sibling checkout used for the
campaign, and `PATH`. A witness records the selected executable's digest and
observed checkout revision, so convenience resolution never becomes an
implicit reproducibility claim.

## Semantic protocol

The initial protocol family is versioned by schema name:

| Schema | Purpose |
| --- | --- |
| `mncs.debug-capabilities/1` | explicit supported, partial, unsupported, emulated, and bootstrap-boundary capabilities |
| `mncs.debug-session/1` | immutable inspection session state |
| `mncs.debug-event/1` | one ordered semantic/runtime observation |
| `mncs.debug-trace/1` | bounded event sequence and value observations |
| `mncs.debug-witness/1` | reproducibility and failure artifact |
| `mncs.debug-replay/1` | trace replay or bounded re-execution result |
| `mncs.debug-inspection/1` | structured state/frame/value/effect inspection |
| `mncs.debug-provenance/1` | partial causal/dataflow claims with completeness labels |
| `mncs.debug-api/1` | programmatic operation envelope |
| `mncs.debug-validation/1` | validation result for a protocol artifact |

JSON schemas are under [`schemas/`](schemas/), while the implementation also
performs dependency-free structural and witness-integrity validation. Identities
use canonical JSON and SHA-256, for example:

```text
mncs:debug:witness:<sha256(canonical witness content)>
mncs:debug:event:<sha256(canonical event content)>
```

Wall-clock time is not used for primary identities. Captures are bounded:
stdout/stderr are capped at 64 KiB, embedded inputs at 256 KiB, traces at 512
events, and static correspondence projections at 2,048 records. Full digests
are retained even when content is clipped.

### Trace and provenance guarantees

Runtime block, operation, and terminator entries retain their exact runtime
identities and order. Effects preserve the runtime's effect fields and are
associated with an operation only when the runtime supplies that operation
identity. Function entry/exit events are explicitly derived from the one
requested entry point; they are not a claim that the runtime emitted a call
stack.

The `why` operation can connect a failure operation to static HIR/SSA identity,
static inputs/outputs, request arguments, and the bounded execution path. It
labels this as partial because the current runtime does not emit intermediate
values, write history, nested frames, scheduler ancestry, or complete effect
input lineage.

## Replay semantics

There are three deliberately separate operations:

1. **Trace replay** reads the preserved trace and never executes the program.
2. **Bounded re-execution** resubmits the embedded program/request to the
   selected external `mncs` executable and compares status, failure identity,
   test identity, and returned-value digest.
3. **Deterministic replay** is currently rejected. The runtime has no contract
   for scheduler decisions, nondeterministic effects, filesystem/environment
   capture, or process boundaries.

A successful re-execution is therefore evidence of bounded reproduction, not a
universal equivalence proof.

`minimize` mutates only embedded integer request values. A candidate is kept
only if it preserves the exact bounded failure signature. Imported test
failures are not re-run as test assertions by the debugger; they retain the
original `mncs.test-result/1` evidence and report when the underlying provider
is required for semantic rechecking.

## `mncs-test` integration

`import-test` consumes the canonical `mncs.test-result/1` shape and selects a
failed test's structured execution request. It preserves the complete selected
result under `integration.result`, records a `test_result_reference`, and adds
the debugger witness around request-level execution evidence. The test
provider now emits a canonical request, request artifact digest, source span,
and execution/declaration/subject/observation/oracle lineage. It does not
redefine verdict, test selection, or assertion semantics.

The current baseline can supply a request for ordinary native tests. If a
future test provider omits the request or source reference, `mncs-debug` rejects
the import and identifies the missing contract instead of reconstructing a
command from prose. The local mapping is documented in
[`docs/integration.md`](docs/integration.md).

## Actions, Forge, and LSP boundaries

- [`integration/mncs-actions-provider.json`](integration/mncs-actions-provider.json)
  is the registered provider descriptor. `mncs-actions/actions/mncs-debug`
  projects witnesses, traces, replay reports, and artifact digests into the
  existing receipt/evidence vocabulary without taking debugger semantic
  authority.
- [`integration/forge-api.md`](integration/forge-api.md) defines the
  `mncs.debug-api/1` operations Forge can call without scraping text.
- [`integration/lsp-contract.json`](integration/lsp-contract.json) records the
  source identity, symbol, span, and breakpoint-resolution fields a future LSP
  bridge will need.

Forge now exposes a structured `development.mncs.failure-loop` operation that
orchestrates these facts, preserves PASS/FAIL/UNKNOWN distinctions, and can
stage one bounded exact repair before a canonical test verification run. It
does not invent stop semantics or parse terminal output.

## Bootstrap and self-hosting

This campaign is at the following trust stage:

```text
Stage 0  reference runtime emits structured execution evidence
Stage 1  Python launcher transports bounded process/artifact facts
Stage 2  MNCS owns outcome classification and stop policy
Stage 3  mncs-debug records and inspects its own deterministic fixtures
Stage 4  not reached: debugger cannot yet suspend/debug its own live process
Stage 5  future: host tools retained only as differential/emergency oracles
```

The semantic core at [`native/mncs/debug/v1.mncs`](native/mncs/debug/v1.mncs)
classifies the explicit transport status and test/effect flags. The launcher
does not contain a fallback semantic interpreter: if the core cannot execute,
the witness records that semantic classification is unavailable.

## Self-tests and measurements

Run the dependency-free test suite with:

```bash
MNCS=/path/to/mncs python3 -m unittest discover -s tests -p 'test_*.py'
```

The tests cover protocol identity/integrity, native semantic-core decisions,
successful and failing recordings, nested-call static correspondence, import
of a `mncs-test` result, trace/provenance/replay/API operations, minimization
boundaries, and corrupt-witness rejection. Runtime-dependent tests are skipped
when `MNCS` cannot be resolved.

The bounded overhead probe is:

```bash
MNCS=/path/to/mncs python3 scripts/measure_overhead.py \
  --program tests/fixtures/checked-add.mncs.json \
  --request tests/fixtures/checked-add-success-request.json \
  --iterations 5 --output /tmp/mncs-debug-overhead.json
```

It reports wall-clock medians for direct execution versus recording and labels
the result as launcher/static-analysis overhead, not a runtime tracing
benchmark. A campaign observation is preserved under `evidence/`.

## Local pressure records

Pressure records live under [`pressures/`](pressures/). Every local record has
now been refreshed against the Profile 0.17/test integration and linked to a
canonical Commons pressure or explicitly marked obsolete/platform-boundary.
The unresolved runtime limitations remain local evidence as well as Commons
records; a registered provider is not treated as proof that those capabilities
are resolved.

## License

Apache-2.0; see [`LICENSE`](LICENSE).
