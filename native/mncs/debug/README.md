# Native debug core

`v1.mncs` is the semantic decision core for the first debugger profile. It
accepts nominal `RuntimeStatus` and bounded typed evidence observations and
returns typed `Decision`, `SufficiencyDecision`, and `EvidenceFacts` records.
The host launcher invokes it through the generated binding and `mncs execute`;
it does not reimplement outcome, stop, or evidence-establishment policy.

The host remains responsible for bounded JSON parsing, literal extraction, and
transport normalization. It cannot turn a claimed, available, truncated, or
candidate artifact into semantic evidence: those predicates are evaluated by
the native reducer.
