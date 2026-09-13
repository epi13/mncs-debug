# Integration contracts

This campaign changes only `mncs-debug`. The files in `integration/` are local
contracts for a later reconciliation campaign; they do not register a provider
or modify `mncs-test`, `mncs-actions`, Forge, or the language service.

## `mncs-test`

Input: `mncs.test-result/1` from the pinned `mncs-test` baseline.

`mncs-debug import-test` requires the existing top-level fields `provider`,
`verdict`, `classification`, `tests`, `provenance`, `artifacts`, and
`reproduction`. It selects an explicitly named test or the first `FAIL` test.
The selected test must provide:

```json
{
  "id": "stable-test-id",
  "source": "path-or-stable-source-reference",
  "request": {"schema_version": "0.1", "target": {}, "arguments": []}
}
```

The request is copied into the witness's bounded embedded request. The full
test result is retained under `integration.result` and its content digest is
recorded. Test verdict/assertion semantics remain owned by `mncs-test`.

The baseline native suite provides enough request evidence for ordinary native
tests. A result with only prose, a command string, or a missing source/request
is rejected rather than parsed heuristically. This is a concrete future
`mncs-test` contract pressure.

## `mncs-actions`

The future provider should accept a structured action input containing a
program/request or a test-result artifact, capability requirements, capture
policy, and timeout/budget. It should return the existing action receipt and
evidence-manifest shapes with debug artifacts listed by digest. The local
descriptor names those outputs without changing the actions registry.

The action layer transports and correlates; `mncs-debug` owns witness/trace
semantics. A failed launch or malformed artifact must remain distinct from a
debugger conclusion.

## Forge

The JSONL API accepts one request and emits one structured response. Supported
operations are `capabilities`, `open`, `inspect`, `trace`, `why`, `replay`, and
`minimize`. Forge can pass a witness path or inline witness and can request
trace kind/operation slices and provenance targets. The response schemas are
stable enough for a first provider adapter, but live suspension and arbitrary
expression evaluation are capability-gated as unsupported.

## LSP

The local LSP contract records the fields required to bind an event to a source
document: source digest, stable URI, function/symbol identity, UTF-8/UTF-16
span convention, compiler phase, and an explicit binding status. A future
breakpoint request must resolve against the compiler's source map rather than a
debugger regex scan.
