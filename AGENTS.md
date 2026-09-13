# mncs-debug execution contract

`mncs-debug` is the canonical debugger consumer for the MNCS family. The
semantic vocabulary and decision rules belong in `native/mncs/debug`; the
Python files under `mncs_debug/` are deliberately narrow transport,
filesystem, process-supervision, canonical-identity, and human-projection
adapters.

The adapter may:

- launch an explicitly selected `mncs` executable;
- read and write bounded JSON artifacts and source snapshots;
- preserve stdout/stderr and process facts as digests;
- invoke the MNCS debug semantic core through the current runtime;
- normalize existing `mncs-language` execution, HIR, SSA, and source-study
  documents into the versioned debug protocols; and
- provide a CLI/API projection for humans, Forge, actions, and LSP clients.

It may not:

- modify `mncs-language`, `mncs-test`, Forge, Commons, or `mncs-actions` in
  this campaign;
- replace MNCS semantics with a hidden host interpreter;
- call a trace replay deterministic when the runtime does not guarantee
  deterministic scheduling/effect capture;
- infer source-level locations from runtime identities without labeling the
  result as heuristic or partial; or
- publish local pressure records to Commons.

Every material host dependency is classified in `docs/architecture.md` as a
legitimate platform/bootstrap boundary, a temporary adapter caused by an
identified MNCS pressure, or an independent differential/reference witness.

## Local validation

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
MNCS=/path/to/mncs ./bin/mncs-debug capabilities
```

The `MNCS` path is intentionally explicit in CI and demonstrations. The
default launcher also checks the sibling checkout used by this campaign for
convenience, but the selected executable and its digest are always recorded
in a witness.
