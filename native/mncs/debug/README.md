# Native debug core

`debug.mncs` is the in-place semantic decision core for the debugger. It
accepts nominal `RuntimeStatus` and bounded typed evidence observations and
returns typed `Decision`, `SufficiencyDecision`, `DiagnosticLoopDecision`, and
`EvidenceFacts` records. The native bounded loop decides evidence
sufficiency, replay-mismatch escalation, and the next operation. The host
launcher invokes it through the generated binding and `mncs execute`; it does
not reimplement outcome, stop, or evidence-establishment policy.

The host remains responsible for bounded JSON parsing, literal extraction, and
transport normalization. It cannot turn a claimed, available, truncated, or
candidate artifact into semantic evidence: those predicates are evaluated by
the native reducer.
