# Conformance fixtures

Produced once by the VERIDICT engine and committed here so the verifier can be
tested without the engine.

| Fixture | Mutation | Expected verdict |
|---|---|---|
| `valid.veridict.zip` | none | `VALID` / `VALID WITH WARNINGS` (offline timestamps pending) |
| `tampered-object.veridict.zip` | first byte of a sealed object flipped | `INVALID` |
| `forged-record.veridict.zip` | one log record body edited in place | `INVALID` |
| `deleted-record.veridict.zip` | one log record removed | `INVALID` |
| `forged-manifest-head.veridict.zip` | manifest `chain_head` replaced | `INVALID` |
| `swapped-public-key.veridict.zip` | manifest public keys replaced with an attacker key | `INVALID` |

Regeneration lives with the engine (`scripts/make_conformance_fixtures.py`);
each tampered variant changes exactly one thing relative to `valid.veridict.zip`.
