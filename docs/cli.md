# CLI and machine API

All commands emit JSON by default. `--format text` adds a short summary only
when an output path is supplied; the artifact itself remains JSON. Commands
that produce an outcome preserve their artifact even when the process exit
code reports failure.

```text
capabilities [--mncs PATH]
record PROGRAM REQUEST [--capture POLICY] [--max-events N] [--max-values N] [--max-value-bytes N] [--operation ID] [--test-result FILE] [--library ROOT]
inspect WITNESS [--event EVENT_ID]
sufficiency WITNESS [--inspection FILE] [--evidence-artifact FILE] [--evidence-operation trace|provenance|replay|minimization]
diagnose WITNESS [--max-steps N] [--inspection FILE] [--evidence-artifact FILE]
trace WITNESS [--kind KIND] [--operation OPERATION_ID] [--from N] [--limit N]
why WITNESS [--operation OPERATION_ID] [--value VALUE_ID] [--question TEXT]
open WITNESS
session open WITNESS --root DIR [--force]
session attach --root DIR
session query --root DIR --op inspect|trace|why|replay|sufficiency|diagnose|phases [op options]
session close --root DIR [--wipe]
break (--program PROGRAM --request REQUEST | --witness WITNESS) (--function NAME | --operation ID | --line N)
watch WITNESS (--binding NAME | --value ID)
phases WITNESS [--kind all|summary|passes|resolutions]
replay WITNESS --mode trace|reexecute [--deterministic]
minimize WITNESS [--max-attempts N]
validate ARTIFACT
import-test TEST_RESULT [--test-id ID]
import-actions PROVIDER_RESULT PROVIDER_CHECK RECEIPT MANIFEST PROOF
retain WITNESS --store DIR
fetch --store DIR --witness-id ID --output PATH
live start (--compile SOURCE | --artifact FILE) (--callable MODULE::NAME | --function ID) [--args-json JSON] [--root DIR] [--stop-op ID] [--stop-function ID] [--stop-effect before|after|both] [--capture POLICY]
live resume|continue --root DIR
live step-in|step-over|step-out --root DIR
live inspect --root DIR [--view stack|observation|effects|stops]
live bind-stop --root DIR (--op ID | --function ID | --effect PHASE | --failure) [--id ID]
live clear-stop --root DIR --id ID
live terminate --root DIR
live attach --root DIR
live close --root DIR [--remove]
live retain --root DIR --store DIR
live fetch --store DIR --evidence-id ID --output PATH
remediate --target DIR --json [--dry-run] [--changed-path PATH] [--budget N]
export WITNESS --kind witness|trace|inspection|provenance
api --request REQUEST.json | --stdio
```

`backtrace`, `value-origin`, and `effect-provenance` are API projections, not
separate CLI commands; use `inspect`/`why` on the CLI or the matching API
operations below.

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

API operations: `capabilities`, `open`, `inspect`, `frames`/`backtrace`,
`trace`, `why`, `inspect-value`/`value-origin`, `effect-provenance`,
`break` (witness plus one of `function`, `operation_identity`, `line`),
`watch` (witness plus one of `binding`, `value`), `replay`, `minimize`.
See `integration/forge-api.md` for the Forge provider boundary.

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

Library roots resolve explicitly: `--library` flags win, then test-result
provenance, then the derived extracted-stdlib sibling (disabled by an empty
`MNCS_STDLIB_ROOT`). The ambient `MNCS_LIBRARY_PATH` is never inherited.
Derived roots are recorded in witness provenance and replay recipes.
