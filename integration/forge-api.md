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
| `trace` | witness plus kind/operation/range | `mncs.debug-trace/1` |
| `why` | witness plus operation/value/question | `mncs.debug-provenance/1` |
| `replay` | witness plus `trace` or `reexecute` mode | `mncs.debug-replay/1` |
| `minimize` | witness plus bounded attempt count | `mncs.debug-minimization/1` |

Forge owns orchestration and higher-level conclusions. The provider owns only
trustworthy debugger facts, bounded artifact mutation, and explicit capability
states. A `blocked`, `mismatch`, `partially_supported`, or unavailable result
must not be promoted to a successful conclusion by the provider.

The current API has no live session token, stop request, evaluate operation,
or scheduler control because the runtime cannot support those semantics. Those
operations must be added only with a corresponding capability and evidence
contract.
