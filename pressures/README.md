# Local debugging pressure ledger

These records are the local pressure evidence for the initial debugger
campaign. Their original reproducer and workaround fields are historical
snapshots; the `campaign_review` field and
`pressures/reconciliation-2026-09.json` are the superseding post-Profile-0.17
disposition. Reconciled canonical records live in MNCS-Commons and retain the
legacy `MNCS-DEBUG-P-*` identities.

Each JSON record contains:

- a stable ID, status, severity, and candidate owner layer;
- the exact pinned revision(s) relevant to the observation;
- the attempted capability and minimal reproducer;
- expected versus actual semantics;
- transparent host-boundary classification and workaround;
- proposed primitive/direction and alternatives;
- tests/evidence, affected modules, dependencies, and resolution criteria.

Ownership is a hypothesis grounded in the evidence. A pressure may move layers
when the later campaign supplies a first-class contract. Operational
bootstrap observations (such as P-012) are retained separately from
language-semantic pressures.
