# VERIDICT Bundle Format — `veridict-bundle/2`

A bundle is a ZIP file (conventional extension `.veridict.zip`) containing a complete,
self-verifying investigation case. A verifier needs **nothing else**: no account, no
network (except optional timestamp chain validation), no trust in the producing tool.

## Version compatibility

`veridict-bundle/2` is the current export format. It adds atomic `batch` log
records. Current importers and verifiers accept both v1 and v2:

- **v1:** `node`, `edge`, and `seal` records only.
- **v2:** all v1 records plus `batch`.

A v1 manifest containing a batch record is invalid. A v1-only verifier cannot
read v2 and MUST reject its unknown spec; it must be upgraded rather than
silently treating v2 as v1.

## Layout

```
manifest.json        top-level commitment: spec, chain head, public keys, signature
case.json            case metadata (id, name, created_at, tool_version)
graph/log.jsonl      hash-chained append-only event log — the source of truth
objects/sha256/…     content-addressed artifact store (path embeds the hash)
timestamps/          RFC-3161 tokens (<artifact_id>.tsr), OpenTimestamps proofs
                     (<artifact_id>.ots), pending.json + ots-status.json queues
```

## Trust chain

```
manifest_signature (Ed25519)
  └─ signs manifest_hash
       └─ manifest_hash = SHA-256 over RFC 8785 canonical JSON of the manifest
            └─ manifest commits to chain_head
                 └─ chain_head = chain_hash of the last log record
                      └─ every record's chain_hash commits to {seq, prev, kind, body_hash}
                           └─ body_hash commits to the node/edge/batch body
                                └─ artifact bodies commit to object bytes via sha256
```

One signature at the top; hashes all the way down. Any byte-level change anywhere
breaks the chain.

## Canonicalization

All hashes are SHA-256 over **RFC 8785 (JCS)** canonical JSON bytes, written as
`sha256:<64 lowercase hex>`. Implementations MUST use an RFC 8785 library;
`json.dumps` is not compliant.

## Log records

One JSON object per line:

| Field | Meaning |
|-------|---------|
| `seq` | 0-based, contiguous |
| `prev` | `chain_hash` of the previous record (`null` for seq 0) |
| `kind` | v1: `node` \| `edge` \| `seal`; v2 also permits `batch` |
| `body` | the node/edge body, ordered batch payload, or seal payload |
| `body_hash` | `hash(body)` |
| `chain_hash` | `hash({seq, prev, kind, body_hash})` |
| `signer` | key id (optional) |
| `sig` | base64 Ed25519 signature over the `chain_hash` string, UTF-8 (optional) |

Key id = first 16 hex chars of SHA-256 over the raw 32-byte Ed25519 public key.

### V2 batch records

A batch commits an ordered set of graph mutations as one signed, hash-chained
JSONL event:

```json
{
  "kind": "batch",
  "body": {
    "entries": [
      {"kind": "node", "body": {"id": "clm_...", "kind": "claim"}},
      {"kind": "edge", "body": {"id": "edg_...", "edge_type": "supported-by"}}
    ]
  }
}
```

`entries` MUST be a non-empty array. Every child MUST contain exactly `kind`
(`node` or `edge`) and `body`. Consumers expand children in array order. The
record's `body_hash` commits to the complete ordered batch. Where a semantic
signature refers to an individual node body (for example `verified-by`), the
verifier hashes that child node body independently.

## Node kinds (PROV alignment)

| Kind | PROV concept | Required fields |
|------|--------------|-----------------|
| `artifact` | Entity | `sha256`, `size`, `media_type`, `storage_path`, `capture_method`, `captured_at`, `tool_version`, `timestamp_status`, `ots_status`; recommended: `content_signature`, `content_signer` |
| `claim` | Entity (assertion) | `text`, `label` (`raw`\|`inferred`), `status`, `method`, `source_count`, `single_source`; `confidence` required when inferred |
| `step` | Activity | `tool`; AI steps carry `model`, `prompt_sha256`, `response_sha256` |
| `agent` | Agent | `agent_kind` (`human`\|`system`), `name`; humans carry `public_key` |

## Edge types

| Type | Direction | Meaning |
|------|-----------|---------|
| `supported-by` | claim → artifact/claim | evidence backing |
| `transformed-by` | node → step | how the node was produced |
| `verified-by` | claim → agent | human sign-off; `meta` carries `claim_body_hash`, `signature`, `signer`, `signed_at` |
| `derived-from` | node → node | lineage (e.g. extracted text → original PDF) |
| `used` | step → artifact | W3C PROV activity-to-entity usage; Source Brief steps use one edge for each declared source and analysis artifact |

## Source Brief steps

Hardened Source Brief steps use tool `ollama/source-brief`, role
`source-brief`, and params field:

```json
{"source_brief_schema": "veridict-source-brief/1"}
```

For this schema, the step and its `used` edges are appended in one batch. The
step's `inputs`, `validated_brief.source_artifact_id`, and
`validated_brief.analysis_artifact_id` must agree with those edges. Retrieval
spans contain offsets, scores, and text hashes but not full span text. Every
persisted factual item is inferred, confidence-scored, and cited; each citation
must match the analysis artifact and lie inside one hashed retrieval span. The
`validated_brief_sha256` is the RFC 8785 canonical hash of `validated_brief`.

Protocol retrieval limits for `veridict-source-brief/1` are:

- `max_context_chars`: integer from **1 through 64,000**, inclusive.
- `spans`: at most **64** entries.
- Each span has global character offsets with `0 <= start < end`; total
  `selected_chars` equals the sum of span lengths and cannot exceed
  `max_context_chars`.
- `score` is a finite, non-negative number and `text_sha256` is 64 lowercase
  hexadecimal characters.

Legacy steps that only carry `role: source-brief` have no hardened schema
contract. Verifiers keep them readable and warn that hardened semantic checks
are unavailable; they do not infer missing `used` edges or reject the legacy
step solely for lacking them.

## Verifier obligations

A conforming verifier MUST:

1. Reject unknown `spec` values.
2. Recompute `manifest_hash` and verify `manifest_signature` against the embedded keys,
   and each key id against its key bytes.
3. Replay the full chain: seq contiguity, `prev` links, `body_hash`, `chain_hash`.
4. Verify every record signature against manifest keys.
5. Re-hash every artifact object and compare with its node's `sha256`.
6. Verify `verified-by` signatures against the signed claim's actual `body_hash`.
7. Flag as **errors**: any hash/signature mismatch, missing objects, claims with no
   `supported-by` edge, edges to nonexistent nodes.
8. Flag as **warnings**: `single_source` claims, pending timestamps, unsigned manifest,
   unsigned records, unknown signers.
9. Parse JSON strictly (I-JSON): reject duplicate member names, non-finite numbers and
   integers outside ±(2^53−1).
10. Treat every path taken from bundle data as untrusted. An artifact's
    `storage_path` MUST equal `objects/sha256/<first 2 hex>/<sha256>`. `timestamp_ref`
    and `timestamp_ots_ref` MUST be plain relative paths inside the bundle (no absolute
    paths, drive letters, backslashes, `.`/`..` segments or colons). Anything else is an
    error and the file is not read.
11. Before unpacking an archive, refuse members with unsafe names, symbolic links,
    duplicate names, and archives over a member-count or total-size limit.
12. For an RFC 3161 token: refuse a response whose status is not granted; check that
    the message imprint is the token's declared hash (SHA-256/384/512) of the
    artifact's raw SHA-256 digest (a SHA-256 token may also carry the digest itself).
    The TSA roots come from the **recipient**, never from the bundle. With roots:
    verify the token signature, the critical `timeStamping` key usage, and a
    certificate chain from the signer to a pinned root that is valid at `genTime`.
    Certificates carried inside the token may only serve as intermediates; a root
    the token brings along is never trusted. Report one of three outcomes: verified
    to a pinned root (information), no roots given so only the imprint was matched
    (warning), anything else (error). Revocation cannot be checked offline and the
    report says so.

**Pinned keys.** When the recipient pins one or more keys, identity problems become
errors: an unsigned manifest, any unsigned record, and any signer (manifest, record,
`verified-by`, content seal) that is neither pinned nor introduced by a valid
`human/key-rotation` statement signed by an already-trusted key earlier in the chain.
Keys listed in the manifest must also be pinned or introduced that way, and a broken
rotation statement is an error. Without a pinned key the verifier MUST state that the
signer's identity was not checked.

Verdicts: `VALID` (no findings), `VALID WITH WARNINGS`, `INVALID` (any error).
Reference exit codes: 0 / 2 / 1.

## Capture methods

`capture_method` values: `file-ingest`, `http-fetch`, `browser-render` (Playwright
Chromium DOM HTML), `browser-screenshot` (full-page PNG derived from a
`browser-render` artifact), `wacz` (browsertrix-crawler capture), `wacz-import`
(externally produced WACZ), `text-extraction` (derived text artifact — always
linked to its source with a `derived-from` edge and to the extraction
`transformed-by` step).

WACZ artifacts (`media_type: application/wacz`) are self-describing web archives
(Webrecorder format): they replay in ReplayWeb.page and carry per-resource digests
in their internal `datapackage.json`, on top of VERIDICT's whole-file sealing.

### Standalone content signature (recommended)

Optional Artifact fields `content_signature` (base64 Ed25519) and `content_signer`
(key id) seal the digest independently of the log record. The signed message is the
UTF-8 string `sha256:<64 lowercase hex>`. A conforming verifier MUST:

- when both fields are present: verify the signature against a manifest public key
  (mismatch = error; unknown signer = warning);
- when both are absent: emit a warning (`artifact has no standalone content signature`)
  so older bundles remain valid.

Current engines populate these fields on every sealed Artifact.

## Timestamps

Two independent anchors per artifact; both stamp the SHA-256 digest only (content
never leaves the machine). `pending` states are legal — offline sealing must never
block an investigation — but are always surfaced by the verifier.

**RFC-3161** — `timestamp_status: anchored` requires a token at `timestamp_ref`.
The engine timestamps the artifact digest as the TSA message; the token's message
imprint is a hash of that message. Verifiers must accept `SHA-512(digest)`
(current engine default), `SHA-256(digest)`, or the raw digest as the imprint.
Anchors may also land *after* sealing (via `timestamp sync`): tokens at the
conventional path `timestamps/<artifact_id>.tsr` are validated even when the
node's status says `pending`, since append-only nodes are never rewritten.

**OpenTimestamps** — `ots_status: stamped | upgraded` requires a proof at
`timestamp_ots_ref` (default `timestamps/<artifact_id>.ots`). The proof must carry
the OTS magic header (`\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94`)
and commit to the artifact digest. `stamped` means calendar attestation only;
`upgraded` means a Bitcoin block attestation is present (proofs upgrade
asynchronously via `veridict timestamp sync`). A conforming verifier MUST check
existence, magic, and digest commitment; full Bitcoin chain validation via the OTS
client is recommended but out of the minimal verifier's scope.
