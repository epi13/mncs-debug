# Native debug core

`v1.mncs` is the semantic decision core for the first debugger profile. It
accepts only a bounded status code plus explicit assertion/effect observations
from the transport adapter and returns a typed `Decision` record. The host
launcher invokes it through `mncs execute`; it does not reimplement the
outcome or stop policy.

The numeric boundary is intentionally documented and tested. It is a
temporary bootstrap membrane until the runtime can expose a first-class
structured debug status/value API directly to MNCS consumers.
