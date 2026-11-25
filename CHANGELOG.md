# Changelog

## 0.3.1

**Upgrade if you use `--check-tree`.** No other check changed.

### Fixed

- `--check-tree` crashed because `veridict_verify/tree.py` was not packaged. Every run
  on a bundle without earlier errors stopped with `ModuleNotFoundError` and exit 1,
  the same exit code as `INVALID`, so a script reading only the exit code took a
  crash for a verdict. 0.3.1 ships the module and reports `tree.matched`,
  `tree.mismatch` (added, changed or missing files), `tree.inventory_count` or
  `tree.unreadable`.
- `--check-tree` on a level-two import (`veridict-seal import`): such a bundle has no
  `folder-inventory/1` Artifact, only `folder-inventory/2`. 0.3.0 with the module
  added would still have reported `tree.inventory_count`; 0.3.1 compares the folder
  with the last `folder-inventory/2` Artifact when there is no `folder-inventory/1`,
  as `docs/bundle-format.md` describes.

### Release checks

- The release workflow runs the installed wheel's `veridict-verify --check-tree`
  (`scripts/check_tree_smoke.py`), with and without the `timestamps` extra, and
  requires a report without a traceback. CI runs the same script on every push.
- `tests/test_package_imports.py` imports every `veridict_verify` module the package
  refers to, lazy imports included, from the installed copy.
- `tests/fixtures/tree/`: a synthetic folder seal, a level-two import and their
  folder, for match and mismatch tests.

Signer profiles (`enrolled/1`), the delivery receipt check and the other rules marked
"no" for 0.3.0 under **Verifier versions** in `docs/bundle-format.md` are not in
0.3.1; they are planned for 0.4.0.

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
  (`--check-tree` crashed in 0.3.0 because a module was missing from the package;
  fixed in 0.3.1.)
- A conformance corpus in `tests/conformance/`: 20 synthetic cases with the exact
  verdict and codes a correct verifier must report (`cases.json`). 0.2.0 gets 4 of the
  runnable cases wrong.

### Compatibility

Bundles made by the VERIDICT engine are fully signed and still pass with a pinned key.
The demo bundle and the original fixtures give the same verdicts as before. Pin the key
a case started with: pinning only a rotated key does not vouch for older records.

## 0.2.0

First public release: standalone offline verifier, demo bundle, conformance fixtures.
