# Portable release archive gate

Before upload, `python .github/scripts/release_guard.py DIRECTORY` reads outer ZIP/JAR/NuGet and TAR packages without extraction. It checks content integrity, member/count/decompressed-byte budgets and a conservative portable namespace: no links, special files, traversal, absolute paths, backslashes, alternate streams, Windows device names, trailing-dot/space names, duplicate/case/NFC collisions, or files used as directories. Root TAR directory records are supported.

Limits: 512 MiB archive input and each member, 2 GiB total expanded content, 100,000 records. Nested archives are treated as file bytes, not recursively inspected. This is a release packaging contract, not malware detection, signature authentication or universal extractor simulation. Existing release tags/assets are not rewritten by this maintenance change. Synthetic regressions run independently in the Release package contracts workflow; no real user archives are included.
