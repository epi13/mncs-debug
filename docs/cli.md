# CLI and machine API

All commands emit JSON by default. `--format text` adds a short summary only
when an output path is supplied; the artifact itself remains JSON. Commands
that produce an outcome preserve their artifact even when the process exit
code reports failure.

```text
capabilities [--mncs PATH]
record PROGRAM REQUEST [--capture POLICY] [--max-events N] [--max-values N] [--max-value-bytes N] [--operation ID] [--test-result FILE]
inspect WITNESS [--event EVENT_ID]
trace WITNESS [--kind KIND] [--operation OPERATION_ID] [--from N] [--limit N]
why WITNESS [--operation OPERATION_ID] [--value VALUE_ID] [--question TEXT]
backtrace WITNESS
value-origin WITNESS VALUE_ID
effect-provenance WITNESS EFFECT_ID
open WITNESS
replay WITNESS --mode trace|reexecute [--deterministic]
minimize WITNESS [--max-attempts N]
validate ARTIFACT
import-test TEST_RESULT [--test-id ID]
export WITNESS --kind witness|trace|inspection|provenance
api --request REQUEST.json | --stdio
```

The API request envelope is `mncs.debug-api/1`:

```json
{
  "schema_version": "mncs.debug-api/1",
  "protocol_version": 1,
  "operation": "trace",
  "witness": "/tmp/failure.witness.json",
  "kind": "failure",
  "limit": 32
}
```

The `provider` command is an alias for `api` during the bootstrap stage. The
Actions registration is owned separately by
`mncs-actions/actions/mncs-debug`; this CLI alias is only its debugger-side
JSONL transport.

`--capture selected` requires one or more `--operation` identities. `--capture
events` is retained as a compatibility alias for bounded capture. Current
native witnesses are created by one `mncs observe` call. The language
runtime keeps semantic execution identity independent from the observation
policy, and the witness carries the bounded `mncs.execution-observation/1`
stream plus the compiler-owned `mncs.execution-source-map/1` when available.
The legacy multi-command collector is used only for older runtimes that do not
provide that contract.
