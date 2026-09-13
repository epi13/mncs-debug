# mncs-debug architecture

This document describes what the first implementation actually does at the
pinned campaign baseline. It is an integration contract and pressure record,
not a promise that the current MNCS runtime already provides a conventional
debugger.

## Design objective

Testing establishes a structured answer to “what failed?”. Debugging preserves
the execution evidence needed to answer “how did it fail?”. Higher-level Forge
reasoning can later ask “why did it fail, and what change fixes it?”. The three
responsibilities are intentionally separate:

```text
mncs-language/runtime/compiler
    structured execution result + static identities
                  │
                  ▼
mncs-debug
    bounded semantic events → trace → witness → inspection/replay facts
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
      mncs-test actions   Forge/LSP
```

The debugger does not parse its own pretty output. It consumes structured
execution/compiler documents, and every derived fact carries an evidence or
completeness label.

## Semantic model

The minimum coherent model currently implemented is:

| Concept | Implemented representation |
| --- | --- |
| execution | content-derived `execution_identity` over program, target, request, and selected runtime |
| state | terminal snapshot plus ordered bounded runtime entries |
| transition | block/terminator event with runtime step and block identity |
| semantic operation | operation event retaining the runtime operation identity and static HIR/SSA projection |
| effect | effect event preserving operation, kind, target, capability, and optional grant provenance |
| source identity | program digest, module/function identity, and a labeled function-declaration scan when source exists |
| frame | one requested entry frame, explicitly marked `requested_entry_only` |
| failure | runtime structured failure, imported test failure, process timeout, or bootstrap boundary classification |
| trace | bounded ordered event sequence plus return-value observations |
| witness | immutable reproducibility artifact with inputs, identities, output evidence, limitations, and replay recipe |
| provenance | partial claims from exact failure identity, static dataflow, request arguments, and bounded order |
| stop condition | MNCS-native semantic core's `should_stop` decision for the terminal classification |

Conventional debugger operations map onto that model as follows:

```text
breakpoint  → future stop on an event/location/condition
watchpoint  → future stop on a state relationship change
step        → future advance over one semantic transition
backtrace   → current entry frame plus future runtime causal ancestry
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

`record` performs these bounded operations:

1. load the request JSON;
2. invoke `mncs execute` without a shell and with an OS timeout;
3. invoke `mncs trace`, `mncs ir`, `mncs ssa`, and, for source programs,
   `mncs source-study` to collect structured static correspondence;
4. invoke `native/mncs/debug/v1.mncs` through `mncs execute` to classify the
   explicit runtime status plus assertion/effect flags;
5. normalize the result into debug events and a bounded trace; and
6. embed bounded program/request inputs and process output evidence in a
   content-derived witness.

The four static invocations are deliberate evidence collection, not a hidden
semantic engine. If one fails, `collection_errors` and witness limitations
remain visible.

## Source-to-execution correspondence

At the baseline, the strongest exact correspondence is:

- runtime operation/block/function identities in `execution-result/0.1`;
- matching operation/function/block identities in HIR/SSA projections;
- compiler and pass fingerprints from `source-study`; and
- a source digest and heuristic function declaration location.

The correspondence disappears at the source operation-span boundary. The
runtime result does not contain source spans, and the source-study result
contains compiler-study/name-resolution facts but no operation-to-span table
that can be carried into execution. A nested-call fixture also shows that
runtime entries retain the called operation identities while the current
execution envelope still describes the requested wrapper function; no runtime
call-stack frame events are emitted.

`mncs-debug` therefore never claims that an operation identity maps to a source
line. It retains `source: null` for those events and marks the declaration scan
`heuristic`.

## Trace architecture and boundedness

Runtime entries are retained as ordered events with explicit `sequence`, event
identity, runtime location, payload, relationship fields, and evidence source.
Derived function boundary events are intentionally separate from runtime
events. Effects and failures are appended only when present. Returned values
are preserved as selected value observations; arbitrary intermediate state is
not guessed.

The default bounded policy is:

```text
stdout/stderr             64 KiB each, full digest retained
embedded program/request  256 KiB each, full digest retained
normalized trace          512 events maximum
static functions/blocks   2,048 records maximum per projection
```

`failure-only` and `events` are accepted capture labels for the protocol
surface; with the current runtime, no additional intermediate event source is
available, so they do not create data that the runtime did not emit.

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

The native file `native/mncs/debug/v1.mncs` owns the outcome enum mapping and
stop policy. Its numeric inputs are an explicitly documented transport membrane
from the current runtime's status vocabulary. The Python adapter owns:

| Host dependency | Classification | Why it remains |
| --- | --- | --- |
| process creation, timeout, stdout/stderr pipes | legitimate platform/bootstrap boundary | MNCS cannot yet supervise an external compiler/runtime process or OS timeout |
| JSON file read/write, bounded base64/text, SHA-256 | legitimate transport/artifact boundary | cross-process artifact transport is outside the current native program model |
| HIR/SSA/source-study normalization | temporary adapter caused by identified MNCS pressure | the current runtime emits these documents but has no native library/API import surface |
| witness queries and human/JSON projection | temporary adapter caused by identified MNCS pressure | no current in-process debugger session/value inspection API exists |
| selected `mncs` executable | independent differential/reference witness | this campaign must consume current runtime behavior without modifying it |

There is no host fallback for semantic outcome classification. If the MNCS
core cannot execute, the witness carries `available: false` and records the
unestablished classification.

## Ownership boundaries

### mncs-language/compiler/runtime

Should eventually own source spans on semantic identities, retained symbols,
runtime frames, typed intermediate value observations, task/effect identities,
safe suspension points, and deterministic replay primitives. These are
runtime/compiler semantics because a debugger cannot reconstruct them reliably
after they disappear.

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
and transport lifecycle. The local descriptor under `integration/` shows how a
future debug provider can return the debug artifacts through existing action
conventions.

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
`docs/campaign-report.md`. Local pressure records are under `pressures/` and
were not published to Commons.
