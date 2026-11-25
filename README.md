# veridict-verify

Standalone offline verifier for VERIDICT case bundles (`.veridict.zip`).
Free and open: **trust, but re-check.**

This package shares **no runtime code** with the VERIDICT engine. It re-checks
hashes, signatures, timestamps, citation spans, corroboration ceilings, and
graph semantics from the published bundle format so a skeptic does not have to
trust the tool that produced the case. You do not need an account, a server,
or the engine — only this package and the bundle you were handed.

> **Upgrade from 0.2.x.** In 0.2.x a pinned key (`--trusted-key`) did not require
> any signature, so a bundle with every signature stripped still passed, and RFC-3161
> tokens were never checked for a TSA signature. Use 0.3.0 or later. See
> [CHANGELOG.md](CHANGELOG.md).

## Install

```bash
pip install veridict-verify
# RFC-3161 timestamp checking (needed for --tsa-roots):
pip install 'veridict-verify[timestamps]'
```

Or from this repository:

```bash
pip install .
```

## Usage

```bash
veridict-verify path/to/case.veridict.zip
veridict-verify path/to/case.veridict.zip --json
veridict-verify path/to/case.veridict.zip --trusted-key <sha256-fingerprint>
```

Try it right now on the demo bundle in this repository:

```bash
veridict-verify examples/demo.veridict.zip
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | `VALID` — no findings that count |
| 2 | `VALID WITH WARNINGS` — integrity holds; review warnings (e.g. pending timestamps, single-source) |
| 1 | `INVALID` — hash/signature/semantic failure |

### Key pinning

Cryptographic verification proves integrity, not identity. Pin a published
investigator fingerprint:

```bash
veridict-verify case.veridict.zip --trusted-key abcdef...64hex...
```

With a pinned key the manifest and every record must be signed, and every signer must
be pinned or introduced by a valid key-rotation statement from a trusted key earlier in
the chain. Otherwise the verdict is `INVALID`. Without a pinned key the verifier
reports that the signer's identity was not checked. See
[docs/key-policy.md](docs/key-policy.md) for custody and publication guidance.

### Time-stamp authority roots

```bash
pip install 'veridict-verify[timestamps]'
veridict-verify case.veridict.zip --trusted-key <fingerprint> --tsa-roots ./tsa-roots/
```

`--tsa-roots` takes a PEM/DER certificate file or a folder of them: the TSA roots
**you** trust. Each RFC-3161 token is then checked for a valid TSA signature and a
certificate chain to one of these roots at the token's time. Roots are never taken
from the bundle, and a root a token carries inside itself is never trusted. Without
`--tsa-roots` a token is only matched to its artifact and the report warns that the
TSA signature was not checked. With `--tsa-roots` but without the `timestamps` extra
installed, the verdict is `INVALID`. Revocation is not checked offline.

### Finding codes and accepted warnings

Every finding has a stable code, printed in brackets and as `"code"` in `--json`
(`veridict-verify --list-codes`, or [docs/finding-codes.md](docs/finding-codes.md)).
A script that must require exit code 0 can accept specific warnings it understands:

```bash
veridict-verify case.veridict.zip --trusted-key <fp> \
  --allow-warning timestamps.pending --allow-warning semantics.single_source
```

Accepted warnings are still printed (`[ALLOW]`, `"allowed": true`); other warnings
still count. Errors can never be accepted.

### Cases where AI is not allowed

```bash
veridict-verify exam-case.veridict.zip --trusted-key <fp> --forbid-ai-steps
```

Every step that names an AI model becomes an error (`policy.ai_step_forbidden`).

### Sealed folders

A VERIDICT folder seal records an inventory of a case folder. Compare a folder with
it, and optionally require the one RFC-3161 token that covers the sealed journal:

```bash
veridict-verify seal.veridict.zip --trusted-key <fp> --check-tree ./case
veridict-verify seal.veridict.zip --trusted-key <fp> --tsa-roots roots.pem \
  --require-head-timestamp --check-tree ./case
```

### Limits

`--max-files N` and `--max-bytes N` cap how much of an untrusted archive is unpacked
(defaults: 100 000 members, 8 GiB).

## What it checks

- Archive safety before unpacking: member names, symlinks, duplicates, size limits
- Strict JSON: duplicate member names, non-finite numbers, unsafe integers
- Manifest hash and Ed25519 signature; key id ↔ public key binding
- Append-only hash chain (seq, prev, body_hash, chain_hash, record signatures)
- Artifact CAS object re-hash at its canonical content address only; optional
  standalone `content_signature`
- Claim grounding (`supported-by`), exact citation quote/offsets
- Human `verified-by` signatures; `contradicts` / `supersedes` semantics
- Independence corroboration ceilings (N vs M)
- RFC-3161 tokens: status, imprint, and with `--tsa-roots` the TSA signature and chain
  to a pinned root
- OpenTimestamps proof structure where present
- Key-rotation statements (`veridict-key-rotation/1`)

## Documentation

- [Verify a bundle in 5 minutes](docs/verify-in-5-minutes.md)
- [External verification protocol](docs/external-verification-protocol.md)
- [Bundle format specification](docs/bundle-format.md)
- [Key policy: custody, publication, rotation](docs/key-policy.md)
- [Finding codes](docs/finding-codes.md)
- [Changelog](CHANGELOG.md)

## Conformance tests

`tests/` contains engine-independent conformance suites:

- [tests/conformance/](tests/conformance/README.md): 20 synthetic cases, each with the
  recipient's options and the exact verdict, error codes and warning codes a correct
  verifier must report — forged and stripped signatures, an added signer, paths
  outside the bundle, duplicate JSON members, unsafe archive names, fake and refused
  timestamps, and the AI policy. `cases.json` is the machine-readable form, for other
  implementations too.
- [tests/fixtures/](tests/fixtures/README.md): the original valid bundle and five
  tampered variants.

```bash
pip install '.[timestamps]' pytest
pytest tests -q
```

## Relationship to the VERIDICT engine

The engine that *builds* cases (capture, sealing, AI-assisted analysis,
reporting) is developed separately. This verifier is intentionally
independent so that opposing counsel, auditors, and editors can re-check
conclusions without trusting — or even having — the engine. A larger
engine-coupled test suite additionally runs in the engine's CI on every
commit, and the conformance corpus is rebuilt there byte for byte.

## License

MIT
