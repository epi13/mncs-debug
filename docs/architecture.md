# mncs-debug architecture

This document describes the native bounded-observability tranche and the
current family integration. It is an integration contract and pressure record,
not a promise that the current MNCS runtime provides a conventional live
debugger.

## Design objective

Testing establishes a structured answer to “what failed?”. Debugging preserves
the execution evidence needed to answer “how did it fail?”. Higher-level Forge
reasoning can later ask “why did it fail, and what change fixes it?”. The three
responsibilities are intentionally separate:

```text
mncs-language/runtime/compiler
    execution-result/0.1 + execution-observation/1
    + compiler-owned execution-source-map/1
                  │
                  ▼
mncs-debug
    native facts → bounded debug events/trace → witness → queries
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
      mncs-test actions   Forge/LSP
```

The debugger does not parse pretty output or reconstruct runtime meaning from
operation order. It consumes the language-owned observation stream and joins
runtime operation identities with the compiler-owned source map. Legacy
execution-result/static projection remains a versioned compatibility path for
older artifacts only; it is never mixed into a native observation claim.

The implemented family path is:

```text
mncs-test mncs.test-result/1
    -> mncs-debug import-test / mncs.debug-witness/1
    -> mncs-actions receipt + evidence manifest
    -> Forge development.mncs.failure-loop
    -> canonical mncs-test verification
```

The test oracle remains owned by `mncs-test`; debug evidence explains the
failure and never changes its verdict. Forge consumes versioned JSON artifacts
and does not parse terminal summaries.

## Semantic model

The minimum coherent model currently implemented is:

| Concept | Implemented representation |
| --- | --- |
| execution | language-owned semantic `execution_identity` over program identity/fingerprint and the request; observation policy is excluded |
| observation | bounded `mncs.execution-observation/1` stream with explicit policy, completeness, truncation, frames, values, effects, and events |
| transition | native event with sequence, block/operation identity, frame, value references, and status |
| semantic operation | runtime operation identity joined to `mncs.execution-source-map/1`; HIR/SSA retain the same semantic identity for phase joins |
| effect | native invocation/result pair preserving operation, frame, input/result value references, capability, target, provenance, and `lineage_only` replayability |
| source identity | compiler source-envelope identity plus exact declaration/operation spans from the source map; legacy text scans are compatibility-only |
| frame | execution-scoped invocation identity with function, parent, call operation, depth, and argument value references |
| failure | runtime structured failure, imported test failure, process timeout, or bootstrap boundary classification |
| trace | bounded projection of the native observation stream, retaining native event/value/frame/effect identities |
| witness | immutable reproducibility artifact with inputs, identities, output evidence, limitations, and replay recipe |
| provenance | native value/frame/effect references plus exact source correspondence; missing scheduler/external causality remains explicit |
| stop condition | MNCS-native semantic core's `should_stop` decision for the terminal classification |

Conventional debugger operations map onto that model as follows:

```text
breakpoint  → future stop on an event/location/condition
watchpoint  → future stop on a state relationship change
step        → future advance over one semantic transition
backtrace   → native execution-scoped frame ancestry for the bounded run
replay      → trace inspection or bounded re-execution, with guarantees named
why x?      → current partial static-dataflow and event-path provenance
```

The final three lines are not equivalent capabilities. The current runtime
supports only the explicitly stated subsets.

## Protocol family

Protocol versioning is schema-based rather than terminal-command-based:

| Protocol | Authority and use |
| --- | --- |
| `mncs.debug-capabilities/1` | discover support boundary before issuing operations |
| `mncs.debug-session/1` | identify an immutable witness-backed inspection session |
| `mncs.debug-event/1` | one event with identity, sequence, location, payload, relations, and completeness |
| `mncs.debug-trace/1` | bounded ordered event/value container |
| `mncs.debug-witness/1` | portable failure/reproduction evidence |
| `mncs.debug-replay/1` | trace replay or bounded re-execution conclusion |
| `mncs.debug-inspection/1` | state, frame, value, effect, and failure projection |
| `mncs.debug-provenance/1` | partial causal/dataflow claims and explicit omissions |
| `mncs.debug-api/1` | Forge/actions/LSP machine request envelope |
| `mncs.debug-validation/1` | validation result with no text scraping |
| `mncs.execution-observation/1` | language/runtime-owned bounded typed execution facts carried inside a witness |
| `mncs.execution-source-map/1` | compiler-owned source correspondence joined by operation identity |

JSON schemas are in `schemas/`; the dependency-free Python validator covers
the integrity membrane needed by the CLI. Unknown future fields are tolerated
by the schema/validator so consumers can add fields without invalidating a
version-1 reader, while required identity and boundedness fields remain stable.

Primary identifiers are `mncs:debug:<namespace>:<sha256>` over canonical JSON.
The witness digest omits only its own `witness_id` (and any future
non-semantic `created_at` field). Event, trace, execution, session, replay,
inspection, and provenance identities are likewise content-derived. Paths and
wall-clock facts do not define semantic identities.

## Current data path

On a current language runtime, `record` performs one bounded native observation
operation:

1. load the request JSON;
2. invoke `mncs observe` without a shell and with an OS timeout; this returns
   `execution-result/0.1`, `execution-observation/1`, validation, and (for a
   valid source program) `execution-source-map/1`;
3. invoke `native/mncs/debug/v1.mncs` through `mncs execute` to classify the
   explicit runtime status plus assertion/effect flags. The sufficiency call
   uses the language-owned `mncs.typed-call/1` boundary with a named
   `SufficiencyInput` record; the adapter no longer encodes six boolean facts
   as positional integers;
4. project the native stream into debug events and a bounded trace; and
5. embed bounded program/request inputs and process output evidence in a
   content-derived witness.

The old `execute` + `trace` + `ir` + `ssa` + `source-study` sequence remains a
compatibility fallback when `mncs observe` is unavailable. A malformed native
observation is rejected at the debugger membrane; it is not silently
reinterpreted as a legacy witness.

## Source-to-execution correspondence

The native correspondence is now:

```text
source envelope identity + exact span
        ↓ compiler
semantic operation identity ─────┐
        ↓ HIR/SSA semantic_identity│
runtime operation event ─────────┘
        ↓ runtime
frame/value/effect references
```

`mncs.execution-source-map/1` is the compiler authority for declaration and
semantic-operation spans. Synthetic operations are marked without fabricated
locations. HIR and SSA already carry the semantic operation identity, so the
join is identity-based rather than text/order-based. The current map is emitted
for the source module being executed; imported-source span projection remains
an explicit multi-source boundary until the compiler exposes source envelopes
for linked modules in one map.

`mncs-debug` therefore labels native operation locations `compiler_exact` or
`compiler_synthetic`. The old declaration scan is retained only for legacy
manifests and is labeled `heuristic`.

## Trace architecture and boundedness

The runtime emits one bounded observation stream. Events reference typed value,
frame, effect, block, operation, and failure identities; the debugger projects
that stream without inventing a second execution log. Values explicitly state
their type, logical binding, version, observation kind, origin, and whether the
capture is full, truncated, digest-only, or unavailable. Frames preserve nested
and repeated calls through execution-scoped identities. Effects are represented
as invocation/result lineage, not as a deterministic replay promise.

The default bounded policy is:

```text
stdout/stderr             64 KiB each, full digest retained
embedded program/request  256 KiB each, full digest retained
normalized trace          512 events maximum
static functions/blocks   2,048 records maximum per projection
runtime observation       4,096 events, 2,048 values, 64 KiB/value maximum
```

`none` and passing `failure-only` runs intentionally retain no observation.
Failure-only capture retains the bounded stream only when the semantic run
fails. `selected`, `bounded`, and `diagnostic` are explicit bounded policies;
the runtime reports dropped events/values and never upgrades truncated evidence
to complete evidence.

## Witness and replay

A witness records:

- protocol and execution identities;
- selected program/request bytes or their digest plus embedding status;
- compiler baseline and observed runtime identity/digest;
- outcome, failure classification, structured failure, return digest, and
  process facts;
- bounded trace, static compiler projection, effects, and captured process
  streams;
- capability document and host facts limited to OS/architecture/Python/
  byte-order;
- test-result import evidence when supplied; and
- a replay recipe with embedded inputs.

The witness does not snapshot the ambient environment. Missing environment,
filesystem, process, effect, and scheduler facts are named limitations.

`trace_replay` is a pure inspection operation. `reexecute` invokes the selected
runtime against embedded inputs where original paths/digests are unavailable,
then compares a bounded signature: status, failure class, failure identity,
test id, and return digest. It is a reproduction check, not deterministic
replay. `--deterministic` always returns a structured blocked result at this
stage.

Minimization changes only integer request arguments and keeps a candidate only
when that signature remains exact. It is conservative and can report
`no_reduction` or `blocked`; it does not claim semantic equivalence beyond the
recorded signature.

## Native/host trust boundary

The native file `native/mncs/debug/v1.mncs` owns outcome/stop policy and the
predicates that establish evidence from bounded artifact observations. The
generated Python binding owns the typed-call transport. The remaining Python
adapter owns:

| Host dependency | Classification | Why it remains |
| --- | --- | --- |
| process creation, timeout, stdout/stderr pipes | legitimate platform/bootstrap boundary | MNCS cannot yet supervise an external compiler/runtime process or OS timeout |
| JSON file read/write, bounded base64/text, SHA-256 | legitimate transport/artifact boundary | cross-process artifact transport is outside the current native program model |
| legacy HIR/SSA/source-study normalization | versioned compatibility fallback caused by identified MNCS pressure | older runtimes do not expose `execution-observation/1`; native witnesses do not use it |
| witness queries and JSON projection | canonical debugger semantic consumer | `mncs-debug` projects native facts into inspection/provenance contracts; it does not decide evidence sufficiency |
| selected `mncs` executable | independent differential/reference witness | this campaign must consume current runtime behavior without modifying it |

There is no host fallback for semantic outcome classification. If the MNCS
core cannot execute, the witness carries `available: false` and records the
unestablished classification.

## Ownership boundaries

### mncs-language/compiler/runtime

Owns exact source correspondence, semantic operation identities, runtime frames,
typed bounded value observations, and effect/task lineage. Safe suspension,
scheduler control, and deterministic replay remain future primitives and are
not implied by this stream.

### mncs-debug

Owns the versioned debug protocols, bounded trace/witness storage, capability
discovery, inspection queries, replay guarantees, conservative minimization,
and projections. It must not invent missing runtime facts.

### mncs-test

Owns test verdicts, test selection, assertion semantics, and test-specific
failure classification. It should provide a stable source identity and
embedded request/reproduction reference for a failed test; the debugger
consumes that evidence.

### mncs-actions

Owns provider invocation, action correlation, receipts, artifact manifests,
and transport lifecycle. `mncs-actions/actions/mncs-debug` is the registered
debug provider membrane; it validates and transports debugger artifacts but
does not interpret trace or replay semantics.

### LSP/language service

Owns source document identity, URI/path mapping, symbols, spans, diagnostics,
and later breakpoint resolution. The debugger supplies semantic event IDs and
locations; it does not become an editor protocol implementation.

### Forge

Owns orchestration, prioritization, cross-run reasoning, and user-facing
conclusions. It consumes `debug-api/1` facts and should not parse prose or
reimplement stop/provenance semantics.

## Bootstrap stages and evidence

The implementation has reached Stage 3 of the local trust model:

```text
0  reference runtime produces structured execution result
1  Python launcher transports bounded process/artifact facts
2  MNCS native core owns classification and stop policy
3  debugger records/inspects deterministic fixtures and imports test evidence
4  live self-debugging with suspension/frames (not reached)
5  host tools retained only as emergency/differential oracles (future)
```

The fixture demonstrations and exact baseline revisions are recorded in
`docs/campaign-report.md`. The initial local pressure records are under
`pressures/`; their reconciled canonical records and append-only verification
observations are maintained by MNCS-Commons.
