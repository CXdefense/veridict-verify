# Investigator key policy

VERIDICT attributions are only as strong as the key that signs them. Cryptographic
verification proves *integrity* (bytes were not altered after sealing). It does not
by itself prove *who* held the private key. That identity link is out-of-band.

## Custody

- Private keys live at `~/.veridict/id_ed25519.pem` by default.
- Prefer a passphrase at rest (`veridict keys init --passphrase ...`).
- Never put a private key or passphrase in a case directory, bundle, prompt, log, or
  screenshot.
- Bundles carry only public keys (and fingerprints derived from them).

## Fingerprints

- **Fingerprint** = SHA-256 (hex, 64 chars) over the raw 32-byte Ed25519 public key.
- **Key id** = first 16 hex characters of the fingerprint (used in log `signer` fields).
- Publish the full fingerprint, not only the key id.

Show yours:

```bash
veridict keys show
```

## Publishing a fingerprint out-of-band

Pick at least one channel a skeptic already trusts for your organization:

- Organization website or trust page
- GPG-signed statement naming the fingerprint and validity window
- Business card / engagement letter for a named engagement
- Secure messaging from a known investigator identity

The published statement should include: investigator/org name, fingerprint, key id,
valid-from date, and how to report compromise.

## Verifying with a pinned key

```bash
veridict-verify case.veridict.zip --trusted-key <full-fingerprint>
# or a file containing the fingerprint / public key:
veridict-verify case.veridict.zip --trusted-key ./alice.fingerprint
```

When `--trusted-key` is set (verifier 0.3.0 and later), the bundle is `INVALID` unless:

- the manifest is signed;
- every record in `graph/log.jsonl` is signed;
- every signer — of the manifest, of records, of `verified-by` edges and of content
  seals — is a pinned key, or a key that a pinned key handed over to in a valid
  `human/key-rotation` statement **earlier in the chain**;
- every key listed in the manifest is pinned or introduced that way;
- every key-rotation statement verifies.

Pin the key the case started with (or every key you trust). Pinning only the newest
key does not vouch for records signed before the rotation.

Without the flag, the verifier still checks signatures against keys embedded in the
bundle but cannot assert identity. It says so in its first finding and warns about
unsigned records. Before 0.3.0 a pinned key only compared the keys the manifest
listed, so a bundle with every signature stripped still passed.

## Rotation

```bash
veridict keys rotate --case ./mycase
```

This:

1. Generates a new keypair.
2. Appends a `human/key-rotation` Step whose statement is signed by the **old** key and
   names the new fingerprint (`veridict-key-rotation/1`).
3. Archives the old PEM as `id_ed25519.pem.<old-key-id>.bak` (never deletes it).
4. Writes the new PEM to the default path.

Publish the new fingerprint out-of-band immediately. Old signatures remain valid under
the old key; the rotation Step is the bridge a verifier can re-check.

## Compromise procedure

1. Stop using the compromised key.
2. Rotate (`veridict keys rotate --case ...`) from a still-trusted machine if possible;
   otherwise generate a fresh key with `keys init --force` and document the break in
   custody in the case as a human Step with a clear reason.
3. Publish a revocation notice for the old fingerprint on the same out-of-band channels.
4. Re-sign any high-stakes Claims that must carry the new key (`veridict claim sign`).
5. Export a new bundle; ask skeptics to pin the new fingerprint.
