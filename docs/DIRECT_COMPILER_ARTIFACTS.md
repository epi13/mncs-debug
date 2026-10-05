# Direct compiler artifacts

`mncs-debug live start --compiler-product FILE --callable MODULE::NAME` loads the
producer's sealed product references, build receipt and compiler source map,
then uses the existing selected `mncs-vm debug --serve` model. It neither
recompiles source nor converts research bytecode. `canonical-vm-debug/1` binds the
exact selected VM executable through Environment.

The product membrane verifies receipt/content identities, containment, compiler
source-map validity and agreement with the VM-admitted artifact. Compiler
correspondence is retained as a separate immutable session artifact; existing
live protocol/evidence schemas remain authoritative. Stop/inspect/step/resume and
resource observations continue through the existing VM debug stream.

The compiler source map includes semantic operations plus selected SSA operation
correspondence where available. A stopped SSA operation can therefore join the
compiler-owned source span. Imported or generic operations without compiler
correspondence remain unmapped; Debug does not invent spans or specialization
facts. Runtime generic/callable identities remain sealed artifact/VM facts.

`tests/test_compiler_product.py` proves a direct artifact's operation/source join,
nested step, resume and terminal artifact/resource correlation, and rejects
product reference tampering. Existing explicit source/dev compilation and native
debugger policy reference lanes remain useful; no migration shim was added.
