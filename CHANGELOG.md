# Changelog

## 0.3.0

**Upgrade if you use `--trusted-key` or rely on RFC-3161 tokens.** Versions 0.2.x
accept bundles that 0.3.0 rejects.

### Security fixes

- **A pinned key now requires signatures.** In 0.2.x `--trusted-key` only compared the
  keys the manifest chose to list. A bundle with every signature stripped and an empty
  key list still came back `VALID WITH WARNINGS` (exit 2). Now, with a pinned key, the
  manifest and every record must be signed, and every signer (manifest, records,
  human verifications, content seals) must be pinned or introduced by a valid
  key-rotation statement from a trusted key earlier in the chain. Broken rotation
  statements are errors. Without a pinned key the first finding says that the
  signer's identity was not checked, and unsigned records are a warning.
- **RFC-3161 tokens are checked against TSA roots you choose.** 0.2.x only compared a
  token's message imprint with the artifact and printed "token commits to artifact
  hash"; a token from any self-made TSA passed. `--tsa-roots <file or folder>` now
  checks the TSA signature and a certificate chain to a pinned root at the token's
  time; certificates inside the token are used only as intermediates, never as roots.
  Without `--tsa-roots` the report warns that the TSA signature was not checked; with
  it but without the `timestamps` extra, the verdict is `INVALID`. A TSA refusal stored
  as a token is an error. The `timestamps` extra now requires `rfc3161-client>=1.0.9`.
- **Paths taken from bundle data are untrusted.** `storage_path` must be the canonical
  content address; timestamp paths must stay inside the bundle. 0.2.x read a file
  outside the bundle when given an absolute path.
- **Strict input.** JSON with duplicate member names is rejected. Archives are checked
  before unpacking for unsafe member names, symlinks, duplicate members and size
  (`--max-files`, `--max-bytes`).

### New

- Every finding carries a stable code (`--list-codes`, `docs/finding-codes.md`), shown
  in brackets and as `"code"` in `--json`.
- `--allow-warning CODE` accepts a known warning: it is still printed (`[ALLOW]`) but no
  longer counts, so a script can require exit 0. Errors can never be accepted.
- `--forbid-ai-steps` makes every step that names an AI model an error
  (`policy.ai_step_forbidden`), for cases where AI is not allowed.
- `--check-tree <folder>` and `--require-head-timestamp` for VERIDICT folder seals.
- A conformance corpus in `tests/conformance/`: 20 synthetic cases with the exact
  verdict and codes a correct verifier must report (`cases.json`). 0.2.0 gets 4 of the
  runnable cases wrong.

### Compatibility

Bundles made by the VERIDICT engine are fully signed and still pass with a pinned key.
The demo bundle and the original fixtures give the same verdicts as before. Pin the key
a case started with: pinning only a rotated key does not vouch for older records.

## 0.2.0

First public release: standalone offline verifier, demo bundle, conformance fixtures.
