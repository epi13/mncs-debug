# Versioned debug schemas

The JSON Schema documents define the wire shape of the initial debug protocol
family. Protocol names are versioned independently so a consumer can negotiate
capabilities before issuing an operation. The Python validator in
`mncs_debug.protocol` is the dependency-free runtime membrane and additionally
checks witness/event identities and bounds.

Unknown properties are intentionally allowed within version 1. Producers may
extend payloads, evidence, and completeness metadata without changing the
required identity envelope. A future incompatible semantic change requires a
new `/2` schema name rather than silently changing `/1`.
