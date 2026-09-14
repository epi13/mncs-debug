# Campaign evidence

This directory contains small, checked-in observations from the first
debugger campaign. Generated traces and witnesses are intentionally excluded;
their content-derived artifacts can be recreated from the fixtures and pinned
runtime. Evidence files identify the selected runtime digest and are not a
substitute for the baseline lock in `docs/baseline/revisions.json`.

The overhead reports separate direct execution, native observation policy
cost, debugger protocol/semantic-core cost, and the legacy bootstrap/static
collector where that comparison is available. They do not treat process
launch or static projection cost as intrinsic runtime event-sink overhead.
