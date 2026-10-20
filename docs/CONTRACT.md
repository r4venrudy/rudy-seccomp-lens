# Input and output contract

Rudy Seccomp Lens accepts either an OCI runtime configuration with a `linux.seccomp` object or a standalone `LinuxSeccomp` object with `defaultAction`. It reads one UTF-8 JSON document, rejects duplicate object keys, limits files to 8 MiB, limits nesting to 64 levels, and caps JSON arrays/objects at 200,000 entries.

`lint` checks the supported OCI seccomp fields for malformed types and reports review leads such as allow-by-default policy, empty kill-by-default profiles, repeated architecture/syscall entries, invalid argument indexes, unsupported wildcard names, and `errnoRet` used with an incompatible action. It does not resolve syscall names against a host syscall table.

`probe` evaluates the profile's named rules for one syscall and six explicit unsigned 64-bit argument values. Every argument predicate in a rule must match. If multiple matching rules disagree on action or errno, it stops with an ambiguity error instead of guessing. The result is a symbolic policy calculation, not proof of the filter a runtime or kernel will install.

`diff` compares the default action and errno, architecture and flag declarations, plus named rule declarations. It is a structural diff. It does not normalize filter precedence, prove behavioral equivalence, or account for architecture-specific syscall-number translation.

JSON output uses `schemaVersion: 1`; SARIF output targets 2.1.0. Findings include stable `RSL` rule identifiers, severity, a JSON-style input path, and a human-readable explanation. `--fail-on error` is the default; `warning` also fails on warnings; `none` always returns success after a valid review. Parse/usage errors return 2 and ambiguous probes return 3.

## Example

```sh
seccomp-lens lint --format sarif --fail-on warning examples/deny-by-default.json
seccomp-lens probe examples/deny-by-default.json --syscall openat --args 0,0,0,0,0,0
seccomp-lens diff --format json examples/deny-by-default.json examples/allow-by-default.json
```
