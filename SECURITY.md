# Security notes

Rudy Seccomp Lens is an offline review utility. It never installs a seccomp filter, starts a container, changes host policy, runs a syscall probe against a target process, or contacts a service.

The parser has explicit input, nesting, and collection limits and rejects duplicate JSON object keys. Treat findings as review leads: deployment behavior can also depend on the host architecture, kernel, libseccomp version, container runtime, filter stacking, and workload. Verify important policy decisions with the exact runtime and an isolated test container before deployment.

Please report a security issue privately through GitHub's repository security advisory feature. Do not include credentials, private profiles, or sensitive host data in a public issue.
