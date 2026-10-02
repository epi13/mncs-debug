# Ambient diagnostics: mncs-debug as an environment provider

This document covers the provider surface `mncs-environment` consumes.
Debugger semantics (trace, provenance, replay, minimization, source
maps) live in `docs/architecture.md` and are unchanged by ambient use.

## Provided capabilities

`family-semantic-contracts-v1.json` publishes two invocable
capabilities:

- `mncs.debugger/1` (`mncs-debug:debugger`), effects `["verify"]`,
  executable `bin/mncs-debug` with the `mncs-language` release
  toolchain. Environment invokes the `import-test` subcommand.
- `mncs.debug-diagnostic-coherence/1`
  (`mncs-debug:diagnostic-coherence`), executable
  `bin/mncs-debug-coherence`, the native ambient policy app.

The `verify` effect means: execute provider code against the current
subject, writes confined to declared ephemeral roots and session
scratch, foreign ownership conflicts deny, subject dirt allowed.
Environment enforces this per invocation and verifies subject
identity before and after every capture.

## import-test contract for ambient capture

Environment calls:

```text
mncs-debug import-test <result.json> --test-id <id>
    --capture <policy> --max-events <n> --max-values <n>
    --max-value-bytes <n>
    --library <root> ... --cwd <session-scratch>
    --output witness.json
```

- `<result.json>` is a retained `mncs.test-result/1` document; the
  selected test must carry structured `source` and `request`.
- `--library` roots are explicit and complete: the debugger
  sanitizes ambient `MNCS_LIBRARY_PATH` rather than inheriting it,
  and recovers roots from `provenance.libraries` only when the
  producer emits them (the current toolchain does not; see
  pressures).
- `--cwd` points at session scratch so relative writes never land
  in a repository.
- Exit status follows witness outcome, not transport health: a
  reproduced `test_failure` exits nonzero with a valuable witness.
  Callers must parse `witness.json`, not the exit code, to decide
  usability. Only `infrastructure_failure` means the capture
  itself broke.

## Native diagnostic policy

`native/mncs/debug/diagnostic_coherence.mncs` owns ambient reuse,
selection, depth, and escalation decisions. It is deliberately
separate from the witness-level `mncs.debug` core (`sufficiency`,
`diagnostic_loop`, `decide`), which reasons about one witness's
internals; the coherence module reasons about failures across
passes. Operation names align (`witness`, `trace`, `provenance`,
`replay`, `minimize`) so host transport maps decisions without
reinterpretation.

Decisions per failure:

| status | meaning |
| --- | --- |
| `current` | recorded witness binds all identities at enough depth |
| `capture_required` | no evidence, or bound input changed |
| `extend_required` | evidence current but below requested depth |
| `deferred` | capturable but over the capture budget |
| `unsupported` | class outside the debugger domain, or no provider |
| `escalate` | missing source, request, or toolchain binding |

Debuggable classes are `test_failure` and `runtime_failure` only.
Depth admits exactly one next step: fresh captures start at
`witness`; standard extension admits `trace`; deep extension
admits `replay`. The policy never sees a test verdict and never
changes one.

The run-app descriptor is
`native-applications/debug-diagnostic-coherence.json` with frozen
interface identity
`9fcd4d008a7138df26324966ecc54f3863442e059b86c231dc88fa123eaac7af`.
Policy tests live in `tests/test_diagnostic_coherence.py` and drive
the shipped `bin/mncs-debug-coherence` adapter directly.

## Pressures and non-goals

- Test-result documents should carry their effective library roots
  in `provenance.libraries` so re-execution needs no side channel.
  The producer is toolchain-owned; until it emits them, the
  environment passes provider-declared roots explicitly.
- Shared cross-session witness reuse needs the unified family
  evidence identity first. Witnesses stay session-private.
- Replay and minimization remain explicit. The ambient layer
  admits them only through explicit depth requests with strict
  budgets, and never replays speculatively.
