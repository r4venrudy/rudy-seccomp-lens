# Release archive audits

Verify one archive or a complete staging directory without extracting payloads.

```sh
python .github/scripts/release_guard.py dist
python .github/scripts/release_guard.py dist/package.zip
```

Directory discovery is bounded. Existing archive-format and checksum contracts still apply.

Use `--json` for schema `rudy.release.archive-report/v1`. Reports contain basenames, member counts and decompressed sizes. Output appears only after every selected archive passes.

`--max-archive-bytes N` lowers `MAX_ARCHIVE` for this invocation. Values must be positive and cannot exceed the built-in ceiling. The original limit is restored after success or error.

`--max-total-bytes N` lowers `MAX_TOTAL` for this invocation. Values must be positive and cannot exceed the built-in ceiling. The original limit is restored after success or error.

`--max-member-bytes N` lowers `MAX_MEMBER` for this invocation. Values must be positive and cannot exceed the built-in ceiling. The original limit is restored after success or error.

`--max-entries N` lowers `MAX_ENTRIES` for this invocation. Values must be positive and cannot exceed the built-in ceiling. The original limit is restored after success or error.

Byte limits apply per archive: `--max-member-bytes` caps a member and `--max-total-bytes` caps its decompressed sum. Limits do not promise an exact process-memory bound.

```sh
python .github/scripts/release_guard.py dist --json --max-archive-bytes 67108864 --max-total-bytes 268435456 --max-member-bytes 33554432 --max-entries 10000
```

## Checksum receipts

`release_checksums.py` accepts the staging directory or its canonical regular `SHA256SUMS` / `SHA256SUMS.txt` path. The full staging inventory is still verified; choosing a manifest never permits unlisted archives or a second manifest.

`--json` emits `rudy.release.checksum-report/v1`: manifest digest, sorted archive names, byte sizes and verified SHA-256 values. It emits a receipt only after the complete inventory passes.
