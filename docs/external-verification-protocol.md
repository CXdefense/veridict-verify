# External verification protocol

Ask someone who did **not** produce the bundle to run this on their machine.
Goal: prove the trust anchor works under adversarial curiosity.

## Prerequisites

- Python 3.11+
- `pip install veridict-verify` (from PyPI after the `verify-v*` release)
- The case bundle (`.veridict.zip`) and the investigator fingerprint published
  out-of-band (see [key-policy.md](key-policy.md))

## Protocol

### A. Clean verify

```bash
veridict-verify case.veridict.zip --trusted-key <fingerprint>
```

Record: verdict, exit code, any warnings. Pass criterion: `VALID` or
`VALID WITH WARNINGS` (document each warning). Exit `0` or `2`.

Use `veridict-verify` 0.3.0 or later. Earlier versions did not require signatures
when a key was pinned, so a pass with 0.2.x does not show who signed the bundle.
Read every warning: a warning is not a pass by itself.

If the bundle carries RFC-3161 tokens, get the TSA root certificate(s) the producer
used from the TSA itself (not from the bundle) and add `--tsa-roots <file or folder>`.
Only then does "signature verified to pinned TSA root" appear; earlier versions never
checked the TSA signature at all.

Record the code of every finding (in brackets, or `"code"` in `--json`). If the case
was one where AI was not allowed (for example an exam), add `--forbid-ai-steps`: any
step naming a model is then an error. An automated check that must reach exit `0` may
accept specific warnings with `--allow-warning CODE`, never errors; list the accepted
codes in the report.

### B. Required tampers

For each tamper, start from a fresh copy of the original bundle. Expect
`INVALID` (exit `1`) every time.

1. **Object byte flip** — unzip; XOR the first byte of any `objects/sha256/...`
   file; re-zip; verify. Expect an artifacts sha256 mismatch.
2. **Log reorder** — unzip; swap two non-adjacent lines in `graph/log.jsonl`
   (or delete one middle record); re-zip; verify. Expect a chain/prev/seq error.
3. **Confidence inflation** — unzip; in the log, find an inferred Claim whose
   independence ceiling is below `1.00` and raise `confidence` above that
   ceiling **without** fixing hashes (or rebuild hashes incorrectly). Simpler
   path for reviewers: mutate the claim body's `confidence` field in the log
   line and leave `body_hash` unchanged — expect a body-hash mismatch. For a
   semantic confidence check, forge a new signed claim node with
   `confidence > ceiling` (as in engine tests) and confirm the verifier emits a
   corroboration error.
4. **Stripped signatures** — unzip; delete the `sig` and `signer` fields from every
   line of `graph/log.jsonl` and set `manifest_signature` to `null`; re-zip; verify
   **with** `--trusted-key`. Expect `INVALID` with "unsigned record" and
   "manifest is unsigned" errors. (Without the pin the same bundle is
   `VALID WITH WARNINGS` and the verifier says identity was not checked.)

### C. Report back

Send:

- OS / Python version
- `veridict-verify --version`
- Verdict of clean run + full warning text
- For each tamper: the error message that fired
- Any surprising false accept / false reject

## Producer checklist (before handing off)

- [ ] Browser or WACZ capture used for any live web evidence (`--browser` or WACZ)
- [ ] `veridict timestamp sync` run online so critical artifacts are not pending
- [ ] High-stakes Claims human-signed
- [ ] Bundle verifies in a clean venv with only `veridict-verify`
- [ ] Fingerprint published out-of-band to the reviewer
- [ ] Verdict, finding codes and the verifier version (`veridict-verify --version`) recorded with the bundle
