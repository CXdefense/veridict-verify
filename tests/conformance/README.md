# veridict-verify conformance corpus

Synthetic bundles with the outcome a correct verifier must report. `cases.json` is the machine-readable form: for each case the bundle, the recipient's options, the verdict, and the exact sets of error and warning codes (info findings are not part of the expectations). Codes are listed in `docs/finding-codes.md`.

Options name files relative to this folder: `keys/<name>.fingerprint` for pinned keys, `tsa-roots/` for TSA roots. Cases that require `timestamps` need `veridict-verify[timestamps]`.

The corpus is byte-for-byte reproducible: keys come from fixed seeds, the engine's clock and ids are counters while building, and ZIPs are stored with a fixed time. Regenerate with `python scripts/make_conformance_fixtures.py veridict-verify/tests/conformance` in the VERIDICT repository; the script stops if any outcome differs from `cases.json`. Expectations are written by hand from the format's rules, not copied from a verifier run.

| Case | What was done to the bundle | Recipient options | Verdict | Codes ((w) = warning) |
|---|---|---|---|---|
| `valid` | none | none | VALID WITH WARNINGS | `timestamps.pending` (w) |
| `valid-pinned` | none (the analyst key is pinned) | pinned key | VALID WITH WARNINGS | `timestamps.pending` (w) |
| `valid-pinned-accepting-pending` | none; the recipient accepts pending timestamps | pinned key; accepts `timestamps.pending` | VALID | none |
| `tampered-object` | first byte of a stored object flipped | none | INVALID | `artifacts.hash_mismatch`, `timestamps.pending` (w) |
| `forged-record` | the claim text edited in the journal, hashes left as they were | none | INVALID | `chain.body_hash_mismatch`, `semantics.verification_hash_mismatch`, `timestamps.pending` (w) |
| `deleted-record` | one journal record removed | none | INVALID | `chain.prev_mismatch`, `chain.seq_mismatch`, `corroboration.claim_invalid`, `semantics.edge_target_missing`, `chain.record_count_mismatch` (w), `timestamps.pending` (w) |
| `forged-manifest-head` | manifest chain_head replaced | none | INVALID | `chain.head_mismatch`, `manifest.hash_mismatch`, `timestamps.pending` (w) |
| `swapped-public-key` | manifest public key replaced with an attacker key | none | INVALID | `artifacts.content_signature_invalid`, `manifest.hash_mismatch`, `manifest.key_id_mismatch`, `manifest.signature_invalid`, `semantics.verification_invalid`, `signatures.record_invalid`, `timestamps.pending` (w) |
| `stripped-signatures-pinned` | claim changed, human verification dropped, every signature and key removed, hashes recomputed; the analyst key is pinned | pinned key | INVALID | `artifacts.content_signer_unknown`, `keys.no_pinned_key`, `manifest.unsigned`, `signatures.record_unsigned`, `timestamps.pending` (w) |
| `stripped-signatures-unpinned` | the same bundle without a pinned key: identity is not checked | none | VALID WITH WARNINGS | `artifacts.content_signer_unknown` (w), `manifest.unsigned` (w), `signatures.records_unsigned` (w), `timestamps.pending` (w) |
| `added-signer-pinned` | claim changed and every record re-signed by an added attacker key | pinned key | INVALID | `keys.not_trusted`, `manifest.signer_not_trusted`, `signatures.signer_not_trusted`, `timestamps.pending` (w) |
| `storage-path-outside` | an artifact's storage_path set to an absolute path outside the bundle (journal re-signed by the analyst) | pinned key | INVALID | `artifacts.path_not_content_address`, `timestamps.pending` (w) |
| `duplicate-json-member` | manifest.json with a duplicated member name | none | INVALID | `manifest.unreadable` |
| `unsafe-archive-member` | an archive member named ../escape.txt | none | INVALID | `archive.unsafe_name` |
| `ai-step-forbidden` | none; the recipient forbids AI steps (the bundle has one) | pinned key; AI forbidden | INVALID | `policy.ai_step_forbidden`, `timestamps.pending` (w) |
| `tsa-genuine` | an RFC 3161 token from the test TSA; its root is pinned | pinned key; TSA root | VALID | none |
| `tsa-genuine-no-roots` | the same token without pinned TSA roots | pinned key | VALID WITH WARNINGS | `timestamps.tsa_not_checked` (w) |
| `tsa-fake` | a token from a TSA under another root | pinned key; TSA root | INVALID | `timestamps.tsa_untrusted` |
| `tsa-smuggled-root` | a fake TSA token that carries its own root | pinned key; TSA root | INVALID | `timestamps.tsa_untrusted` |
| `tsa-refused` | a TSA refusal stored as if it were a token | pinned key | INVALID | `timestamps.tsa_refused` |
