# Integration surfaces

These files are the checked-in contracts for the coordinated MNCS development
loop. `mncs-test` owns test meaning, `mncs-debug` owns execution/debugging
meaning, Actions transports both through receipts/manifests, and Forge
orchestrates the structured handoff. The exact final revisions are pinned by
the family contract in `mncs-actions` after the coordinated merge.

Commons pressure records remain the coordination authority; these files do not
pretend that an implementation limitation is resolved merely because a
provider was registered.
