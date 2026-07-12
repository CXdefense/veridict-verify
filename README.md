# veridict-verify

Standalone offline verifier for VERIDICT case bundles (`.veridict.zip`).
Free and open: **trust, but re-check.**

This package shares **no runtime code** with the VERIDICT engine. It re-checks
hashes, signatures, timestamps, citation spans, corroboration ceilings, and
graph semantics from the published bundle format so a skeptic does not have to
trust the tool that produced the case. You do not need an account, a server,
or the engine — only this package and the bundle you were handed.

## Install

```bash
pip install veridict-verify
# optional RFC-3161 token parsing:
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
| 0 | `VALID` — no findings |
| 2 | `VALID WITH WARNINGS` — integrity holds; review warnings (e.g. pending timestamps, single-source) |
| 1 | `INVALID` — hash/signature/semantic failure |

### Key pinning

Cryptographic verification proves integrity, not identity. Pin a published
investigator fingerprint:

```bash
veridict-verify case.veridict.zip --trusted-key abcdef...64hex...
```

See [docs/key-policy.md](docs/key-policy.md) for custody and publication guidance.

## What it checks

- Manifest hash and Ed25519 signature; key id ↔ public key binding
- Append-only hash chain (seq, prev, body_hash, chain_hash, record signatures)
- Artifact CAS object re-hash; optional standalone `content_signature`
- Claim grounding (`supported-by`), exact citation quote/offsets
- Human `verified-by` signatures; `contradicts` / `supersedes` semantics
- Independence corroboration ceilings (N vs M)
- RFC-3161 / OpenTimestamps proof structure where present
- Key-rotation statements (`veridict-key-rotation/1`)

## Documentation

- [Verify a bundle in 5 minutes](docs/verify-in-5-minutes.md)
- [Bundle format specification](docs/bundle-format.md)
- [Key policy: custody, publication, rotation](docs/key-policy.md)

## Conformance tests

`tests/` contains an engine-independent conformance suite: a committed valid
bundle plus five tampered variants (flipped object byte, forged record,
deleted record, forged manifest head, swapped public key). Run it yourself:

```bash
pip install . pytest
pytest tests -q
```

Every tampered fixture must come back `INVALID`. See
[tests/fixtures/README.md](tests/fixtures/README.md) for the corpus.

## Relationship to the VERIDICT engine

The engine that *builds* cases (capture, sealing, AI-assisted analysis,
reporting) is developed separately. This verifier is intentionally
independent so that opposing counsel, auditors, and editors can re-check
conclusions without trusting — or even having — the engine. A larger
engine-coupled test suite additionally runs in the engine's CI on every
commit.

## License

MIT
