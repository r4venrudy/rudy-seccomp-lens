# Release archive audits

Verify one archive or a complete staging directory without extracting payloads.

```sh
python .github/scripts/release_guard.py dist
python .github/scripts/release_guard.py dist/package.zip
```

Directory discovery is bounded. Existing archive-format and checksum contracts still apply.
