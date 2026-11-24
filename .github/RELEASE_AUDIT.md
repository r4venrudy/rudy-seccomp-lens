# Release archive audits

Verify one archive or a complete staging directory without extracting payloads.

```sh
python .github/scripts/release_guard.py dist
python .github/scripts/release_guard.py dist/package.zip
```

Directory discovery is bounded. Existing archive-format and checksum contracts still apply.

Use `--json` for schema `rudy.release.archive-report/v1`. Reports contain basenames, member counts and decompressed sizes. Output appears only after every selected archive passes.

`--max-archive-bytes N` lowers `MAX_ARCHIVE` for this invocation. Values must be positive and cannot exceed the built-in ceiling. The original limit is restored after success or error.
