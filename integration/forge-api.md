# Forge provider boundary

Forge can invoke `mncs-debug api --stdio` as a newline-delimited structured
provider. Each line is one `mncs.debug-api/1` request and each response is one
JSON document. The implemented Forge failure-loop uses the same owner-native
CLI operations as file-backed calls so Actions and Forge can share bounded
artifacts without a second semantic adapter. Neither path requires Forge to
parse a human summary.

| Operation | Input | Result |
| --- | --- | --- |
| `capabilities` | optional runtime selection | `mncs.debug-capabilities/1` |
| `open` | witness path or inline witness | `mncs.debug-session/1` |
| `inspect` | witness plus optional event ID | `mncs.debug-inspection/1` |
| `frames` / `backtrace` | witness plus optional event ID | native execution-scoped frame projection |
| `trace` | witness plus kind/operation/range | `mncs.debug-trace/1` |
| `why` | witness plus operation/value/question | `mncs.debug-provenance/1` |
| `inspect-value` / `value-origin` | witness plus native value identity | value capture and origin chain in `mncs.debug-provenance/1` |
| `effect-provenance` | witness plus native effect identity | invocation/result lineage in `mncs.debug-provenance/1` |
| `break` | witness plus exactly one of `function`, `operation_identity`, `line` | `mncs.debug-stop-set/1` resolved without execution |
| `watch` | witness plus exactly one of `binding`, `value` | value observations plus origin chain in `mncs.debug-provenance/1` |
| `replay` | witness plus `trace` or `reexecute` mode | `mncs.debug-replay/1` |
| `minimize` | witness plus bounded attempt count | `mncs.debug-minimization/1` |

Forge owns orchestration and higher-level conclusions. The provider owns only
trustworthy debugger facts, bounded artifact mutation, and explicit capability
states. A `blocked`, `mismatch`, `partially_supported`, or unavailable result
must not be promoted to a successful conclusion by the provider.

The `mncs.debug-api/1` stdio surface itself has no live session token,
stop request, evaluate operation, or scheduler control: it stays an
evidence-session provider over completed witnesses. Live execution is a
separate explicit surface: `mncs-debug live ...` holds a resident session
(`mncs.debug-live-session/1`) over one VM execution via a `mncs-vm debug
--serve` daemon, with typed stop records, continuation tokens, stepping,
and terminal evidence (`mncs.debug-live-evidence/1`). The daemon is a
VM-owned execution holder, not a second execution system. Native
backtrace/value/effect queries over evidence sessions are terminal
projections over the bounded observation stream; they do not imply
suspension or watchpoints.

## Observation submission to Forge

`record`, `run`, and `import-test` accept `--executor forge
--forge-config FORGE.toml` (default executor is `local`). Debug submits
program, request, and capture policy to Forge's `development.mncs.observe`
operation; Forge owns confinement, deadline, and provenance, invokes the
local record entry, and returns the validated witness with Forge
execution identity. Capture semantics are identical to local execution;
only execution ownership changes. This is the submission side of
MNCS-DEBUG-P-016; the contract is documented in Forge's
`docs/mncs-execution-modes.md`.
