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

The `enrolled/1` signer profile, deliveries and level-two imports (M2) stay within
`veridict-bundle/2`, but the public verifier 0.3.0 does not check them; see
**Verifier versions**.

## Layout

```
manifest.json        top-level commitment: spec, chain head, public keys, signature
case.json            case metadata (id, name, created_at, tool_version)
graph/log.jsonl      hash-chained append-only event log — the source of truth
objects/sha256/…     content-addressed artifact store (path embeds the hash)
timestamps/          RFC-3161 tokens (<artifact_id>.tsr, chain-head.tsr), OpenTimestamps
                     proofs (<artifact_id>.ots), pending.json + ots-status.json queues
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

Hashes all the way down, and signatures on top of them (see **Signatures**). Any
byte-level change anywhere breaks the chain.

## Manifest

`manifest.json` is one JSON object:

| Field | Meaning |
|-------|---------|
| `spec` | `veridict-bundle/2` (or `/1`) |
| `case` | a copy of `case.json`: `spec`, `case_id`, `name`, `created_at`, `tool_version` and `investigator_agent` (the founding agent's id, in every case). In an enrolled case (see **Signer profiles**) it also carries `signer_policy: "enrolled/1"` |
| `created_at` | when this manifest was written (engine clock, RFC 3339 UTC) |
| `chain_head` | `chain_hash` of the last log record |
| `record_count` | number of log records |
| `public_keys` | `{key id: base64 raw 32-byte Ed25519 public key}`: the exporting key, keys announced by `human/key-rotation` steps, the investigator agent's key, every key a record declares in `signer_public` (in either profile), the key a step in a `batch` record carries in `params.signer_public` (captures write it) when it matches that record's `signer` and, in an enrolled case, every enrolled agent's key. A record signed by a key missing here is reported as an unknown signer |
| `signers` | enrolled cases only: `{key id: {agent, kind, first, last, records}}` — the agent the key was enrolled for, `human` or `system`, the `seq` of the first and last record it signed and how many (`null`, `null`, `0` for a key that has not signed yet) |
| `artifacts` | `[{id, sha256, path}]`, one per Artifact node; `path` is the canonical content address |
| `counts` | `{artifacts, claims, steps, agents}` |
| `chain_timestamp` | optional: `{path: "timestamps/chain-head.tsr", sha256}` (`sha256` is the token file's digest as 64 lowercase hex, without a `sha256:` prefix) and, when the timestamp transport returned one, `egress_ref` — one RFC 3161 token over the journal head (see **Timestamps**) |
| `manifest_hash` | `hash()` of the manifest without `manifest_hash` and `manifest_signature` |
| `manifest_signature` | `{signer: key id, sig}` or absent/`null` (unsigned) |

`manifest_hash` covers every other field, `chain_timestamp` and `signers` included, so
the signature binds the exact journal timestamp to the exact journal head.

## Signatures

Every signature is Ed25519 over the UTF-8 bytes of a `sha256:<64 hex>` string. The
signer is named by **key id** (first 16 hex characters of SHA-256 over the raw public
key); the **fingerprint** is the full 64 hex characters. A key id in `public_keys` MUST
match its key bytes.

| What is signed | Message | Where |
|---|---|---|
| a log record | its `chain_hash` | record fields `signer`, `sig` |
| the manifest | `manifest_hash` | `manifest_signature` |
| a human verification | the verified Claim node's body hash (`hash(claim body)`; inside a batch, the child body alone) | `verified-by` edge `meta.signer`, `meta.signature`, `meta.claim_body_hash` |
| an artifact's bytes | `sha256:<artifact sha256>` | Artifact `content_signer`, `content_signature` |
| a key rotation | `statement_hash = hash({schema, old_key_id, old_fingerprint, new_key_id, new_fingerprint, new_public_b64})`, signed by the **old** key | params of a `human/key-rotation` step (`veridict-key-rotation/1`) |
| a key enrollment (enrolled cases) | no separate signature: the `agent` node with the new `public_key` sits in a record signed by an enrolled human | the record's `signer`, `sig` |
| a folder-import revision (outside the bundle) | the RFC 8785 canonical bytes of `state` themselves, **not** a `sha256:` string | `record.json` `{state, signature}` beside the bundle; checked by `veridict-seal`, not by `veridict-verify` |

What a valid signature shows depends on the recipient. **Without a pinned key** it
shows only that the bytes were not changed after signing by *some* key listed in the
bundle; anyone can produce such a bundle, and the verifier says identity was not
checked. **With a pinned key** (`--trusted-key`) every record and the manifest must be
signed, and every signer must be a pinned key or a key that a pinned key handed over
to in a valid rotation statement — or, in an enrolled case, a key enrolled by a trusted
human (see **Signer profiles**). A record signer that is not pinned must have been
introduced earlier in the chain; for the other signatures see **Pinned keys** under
**Verifier obligations**. A signature never shows that a claim is true.

## Signer profiles

A case uses one of two profiles. The profile is fixed by the first record and cannot
change later.

**Single investigator (no `signer_policy`).** One human key signs; it may hand over to
a new key with `human/key-rotation`. This is every case made before M2 and every case
made without `--enrolled-signers`.

**`enrolled/1`.** Several people and system accounts sign, each with its own key, and
every key is introduced inside the journal. Level-two folder imports always use it.

1. **Founding record.** Record `seq 0` is a `node` record whose body is a human
   `agent` with `signer_policy: "enrolled/1"` and a `public_key`, signed by that same
   key. `manifest.case.signer_policy` is `enrolled/1` exactly when this record says so,
   and `manifest.case.investigator_agent` is this agent's id.
2. **Enrollment.** A later `agent` node with a `public_key` enrolls that key. The
   record that carries it must be signed by an enrolled **human**; the key must be
   listed in `public_keys`, not enrolled already, and `agent_kind` must be `human` or
   `system`. A system key cannot enroll anyone. A replacement key is enrolled the same
   way; `keys rotate` refuses an enrolled case.
3. **Every record** after `seq 0` is signed by a key enrolled in an *earlier* record.
4. **Steps.** If a step's `agent` is present and not `null`, it must be the id of an
   `agent` node that appears in an earlier record or earlier in the same batch;
   otherwise the error is `keys.not_trusted`. If that agent is human, the record must be
   signed by the key enrolled for that same agent. A step may name a system agent (with
   or without a key) or no agent at all (`veridict/recovery`). The rule looks at
   `agent` only, not at the `tool` name (see **Known gaps**).
5. **Human verification.** A `verified-by` edge must point at the signer's own enrolled
   human agent, and `meta.signer` must be the record's signer. A system key cannot
   verify a claim.
6. **Manifest.** The manifest is signed by an enrolled key, and `manifest.signers`
   equals the counts computed from the journal.

A recipient pins the **founding investigator's** key. Keys enrolled under rule 2
become trusted the way a rotation hands over trust, so the recipient does not need to
pin the second analyst or the system account. Without a pin the rules are still
checked, but nothing ties the founding key to a person.

In either profile, a record whose signer is not the founding investigator's key (a
second analyst, a system account, a key after a rotation) carries that signer's public
key in `signer_public`. The engine refuses to export a record whose `signer_public`
does not match its `signer`; the verifier reads keys from `public_keys` only.

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
| `signer_public` | base64 public key of `signer`, written when the signer is not the founding investigator (optional; not covered by `chain_hash`) |

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
| `artifact` | Entity | `sha256`, `size`, `media_type`, `storage_path`, `capture_method`, `captured_at`, `tool_version`, `timestamp_status`, `ots_status`; recommended: `content_signature`, `content_signer`; optional `timestamp_egress_ref` (see **Timestamps**) |
| `claim` | Entity (assertion) | `text`, `label` (`raw`\|`inferred`), `status`, `method`, `source_count`, `single_source`; `confidence` required when inferred |
| `step` | Activity | `tool`, `params`, `inputs`, `outputs`; AI steps carry `model`, `prompt_sha256`, `response_sha256` (see **Step registry**) |
| `agent` | Agent | `agent_kind` (`human`\|`system`), `name`; humans carry `public_key`, and so does every enrolled system account; the founding agent of an enrolled case carries `signer_policy: "enrolled/1"` |

Every node also has `id` and `created_at` (the engine clock when the node was written).

### Times

A case holds several times, each with a different author and a different strength.
They are kept apart; none is silently "the" time.

| Time | Who vouches for it | Where in format 2 |
|---|---|---|
| **Seal time**: when the engine stored the bytes and wrote the Artifact | the engine's clock; a caller cannot set it | Artifact `captured_at` |
| **Acquisition time**: when the bytes were fetched, captured or received | whoever is named as its basis (a fetching tool, a tool record inside the file, the analyst's log, the file system) | the capture step's `params` (tool-specific today; a common schema `veridict-capture/1` is planned). In a level-two import, each register row keeps the analyst's own columns with `time_basis: "analyst-stated"`, and the import catalog's `capture_times` lists `analyst_reported_at` beside `registered_at` (the row Artifact's `captured_at`) |
| **Source time**: a publication or modification date the source states | the source | capture step `params`, tool-specific |
| **Upper bound from an independent service** | the time-stamp authority | RFC 3161 token (per artifact, or `chain_timestamp` for the whole journal); OpenTimestamps proof |

`captured_at` therefore means *sealed at*, not *captured from the source*. For a page
fetched by the engine the two are seconds apart; for a file from a folder assembled by
hand they can be days apart, and the difference must stay visible. Only the seal time
(as the engine's own record) and a verified token are *attested*; acquisition and
source times are *stated* or *recorded by a tool* and must be presented that way.

Times the engine takes from its clock for nodes, records and the manifest
(`created_at`, `captured_at`, `signed_at`, `sealed_at`) are RFC 3339 in UTC with a `Z`
suffix, second precision (for example `2026-11-25T18:12:49Z`). Analyst-stated times,
such as the register's own columns and `analyst_reported_at`, are kept as the analyst
wrote them. A level-two import's `imported_at` (in the `folder-catalog/2` content and
the `import-receipt/1` text) currently carries microseconds and `+00:00` instead (see
**Known gaps**). Format-2 verifiers check only that `captured_at` is a string.

## Edge types

| Type | Direction | Meaning |
|------|-----------|---------|
| `supported-by` | claim → artifact/claim | evidence backing |
| `transformed-by` | node → step | how the node was produced |
| `verified-by` | claim → agent | human sign-off; `meta` carries `claim_body_hash`, `signature`, `signer`, `signed_at` |
| `derived-from` | node → node | lineage (e.g. extracted text → original PDF) |
| `used` | step → artifact | W3C PROV activity-to-entity usage; Source Brief steps use one edge for each declared source and analysis artifact |
| `contradicts` | artifact/claim → a different claim | contrary evidence the claim must face; `meta.reason` is non-blank text (missing or blank: warning `semantics.contradicts_no_reason`); other endpoints: error `semantics.contradicts_invalid` |
| `supersedes` | old claim → a different new claim | an append-only correction; the engine writes `meta.reason`. A claim has at most one successor (`semantics.supersedes_ambiguous`), the chain has no cycle (`semantics.supersession_cycle`) and ends at a claim with a `supported-by` edge (`semantics.supersedes_no_successor`); other endpoints: `semantics.supersedes_invalid`. All are errors |

The list is closed: the reference verifier reports any other `edge_type` as the error
`semantics.edge_type_unknown`.

## Seal records

A `seal` record closes an export: its body is `{sealed_at, chain_head_before_seal,
record_count_before_seal}`. A normal export appends one before writing the manifest.
A snapshot export (`veridict export --snapshot`) packages the journal at its current
head without appending anything, so repeating it gives the same journal bytes.

## Step registry

A Step's `tool` names what ran; structured `params` carry a schema identifier when the
shape is fixed. Verifiers MUST NOT reject a step because its `tool` or schema is
unknown: unknown steps are recorded, not judged. A schema whose shape changes gets a
new version (`…/2`); old versions stay readable. New schemas are added to this table.

Prefixes: `human/…` names a decision attributed to a person; `veridict/…` is the
engine's own bookkeeping. Nothing checks the prefix itself. In an `enrolled/1` case the
record must be signed by the person's own key only when the step's `agent` is a human
agent (rule 4); the engine also lets a system key write a `human/…` step attributed to
its own system agent, including `human/origin-assessment`, which changes confidence
ceilings (see **Known gaps**). A step that names a `model` is an **AI step**, whatever
its `tool` (`veridict-verify --forbid-ai-steps` rejects them).

| `tool` | Params schema | What it records | Checked by the verifier |
|---|---|---|---|
| `human/key-rotation` | `veridict-key-rotation/1` | an old key hands over to a new key | yes: statement hash and old-key signature; with a pinned key a broken statement is an error |
| `human/origin-assessment` | `corroboration/1` | a person's grouping of sources into independent origins | yes: shape, and confidence ceilings derived from it |
| `ollama/source-brief` (role `source-brief`) | `veridict-source-brief/1` | an AI reading of one source with cited spans | yes: spans, citations, hashes, `used` edges |
| `human/source-brief-decision`, `human/source-brief-intelligence` | — | a person accepting or rejecting AI candidates | recorded |
| `veridict/folder-seal` | Artifact `capture_method: folder-inventory/1` | an inventory of a case folder and its changes | yes, with `--check-tree` |
| `veridict/folder-import` | catalog Artifact `folder-catalog/2` with params `schema: veridict-folder-import/2`; receipt Artifact `import-receipt/1` | one revision of a level-two import: exact relative names → artifacts, changes, quarantine, register rows, filename hints, earlier checksum lists, capture times | recorded |
| `veridict/tree-seal` | Artifact `folder-inventory/2` | the revision's `SHA256SUMS.txt` list (accepted and quarantined files) | yes, with `--check-tree` (see **Verifier versions**) |
| `veridict/capture-record`, `veridict/search`, `veridict/source`, `veridict/command`, `veridict/journal-row` | `veridict-<kind>/1`: `row`, `time_basis`, `reference_status`; `basis` for searches; `corrects` when a row changed | one row of the owner's register as an Artifact `journal-entry`; `inputs` are the register file and, only when `reference_status` is `matched`, the referenced file (see **Register rows** below) | recorded |
| `veridict/hash-list-check` | Artifact `checksum-reconciliation` | an earlier checksum list kept as its digest and reconciliation result, not its text | recorded |
| `veridict/delivery` | `veridict-delivery/1` | that the analyst recorded handing one PDF and one ZIP to a recipient profile | yes: see **Deliveries** |
| `veridict/timestamp` | — (`token`, `egress_ref`) | a token obtained later by `timestamp sync`, with the gateway's outgoing-request id | recorded |
| `veridict/recovery` | — (`torn_file`, `torn_bytes`, `torn_sha256`, `truncated_at`) | half a record left by a crash, moved aside | recorded |
| `domain-profile`, `human/domain-profile-decision` | — | derived domain signals and a person's decision on them | recorded |
| `impersonation-comparison` | — | a comparison of two sites | recorded |
| `registry/<connector>`, `http-fetch`, `playwright/chromium`, `browsertrix-crawler`, `wacz-import` | — | how bytes were acquired | recorded |
| `pypdf-extract`, `stdlib-htmlparser-extract`, `wacz-pages-extract`, `tesseract-ocr` | — | text derived from an artifact | recorded |
| `ollama`, `nvidia`, `deepseek`, `<provider>/reader-brief` | — | AI calls (with `model`, prompt and response hashes) | AI-step policy only |

"Recorded" means the verifier checks the step's generic shape (`tool`, `params`,
`inputs`, `outputs`) and that it is signed like every record, not the meaning of its
params.

**Register rows.** `reference_status` is `matched` when the row's file reference
resolves to exactly one imported file and the row's `SHA256` column, if filled, equals
that file's digest. A reference that resolves but whose stated digest differs is
`digest-mismatch`: the file is not an input and is named only in the `resolved` field
of the `journal-entry` content. The other values are `ambiguous` (more than one
candidate), `missing` and `unrecorded` (no reference in the row).

## Deliveries

`veridict record-delivery` writes one signed record: a receipt Artifact and a
`veridict/delivery` step. It shows what the analyst said they handed over and to which
recipient profile. It does not show that anything was sent or received. A verifier
checks every `veridict/delivery` step, in any signer profile:

1. The record carrying it is validly signed (with a pinned key: by a trusted key).
2. `params.schema` is `veridict-delivery/1`, `params.recipient` is `owner`, `client` or
   `reviewer`, and `params.pdf_sha256` and `params.zip_sha256` are 64 lowercase hex.
3. The step has exactly one output: an Artifact in the **same record** with
   `capture_method: delivery-record`, `media_type: application/json` and the canonical
   storage path.
4. The receipt bytes are at most 1 MiB and match the Artifact's `sha256`. They parse
   as strict JSON with a string `reference` that is not blank (empty, or only
   characters for which Python's `str.isspace()` is true, is refused), and equal the
   RFC 8785 bytes of `{schema, recipient, pdf_sha256, zip_sha256, reference}` taken
   from the step.
5. `params.op_id` is `hash(["delivery", reference])`.

Any failure is the error `delivery.receipt_invalid`.

## Level-two folder imports

`veridict-seal import FOLDER` publishes a revision beside the folder, in
`FOLDER.imports/seal-NNNNNNNN/`:

| File | What it is |
|---|---|
| `case.veridict.zip` | a snapshot export of an `enrolled/1` case (no seal record) |
| `SHA256SUMS.txt` | the inventory; the same bytes are the `folder-inventory/2` Artifact |
| `appendix-a.csv`, `receipt.txt`, `import-summary.json` | Appendix A, the import receipt (also the `import-receipt/1` Artifact), and a summary of changes and register issues |
| `record.json` | `{state, signature}`: the signed state of this revision, with the bundle's SHA-256, the previous bundle's SHA-256 and the hashes of the files above. It is signed with the import key, which is also the case's founding key; the file does not name the key |

Files that look like credentials are not copied: they appear as hashes in the
quarantine list. A later revision keeps earlier evidence; a removed file needs a
reason. `veridict-verify --check-tree FOLDER` compares the folder with the bundle's
`folder-inventory/1` Artifact, or, when there is none, with the last
`folder-inventory/2` Artifact. `record.json` is checked by `veridict-seal`, not by
`veridict-verify`. The import guide ships with the VERIDICT engine
(`docs/level-two-import.md`).

**Inventory bytes.** `folder-inventory/1`, `folder-inventory/2` and `SHA256SUMS.txt`
are UTF-8 with one line per file: the SHA-256 as 64 lowercase hex, two spaces, the
relative path, LF. Paths use `/`, have no empty, `.` or `..` segment and no
duplicates, and are sorted by Unicode code point; the last line ends with LF.

**`--check-tree`** runs only when the archive, manifest, journal (record signatures and
`chain_timestamp` included) and artifact (hashes and content seals) checks found no
error; after such an error the folder is not compared and no `tree` finding appears.
The graph-semantics, corroboration, Source Brief, per-artifact timestamp and
`--forbid-ai-steps` checks run after it, so their errors do not stop it. It walks
FOLDER and skips files whose name starts with `~$` or is `thumbs.db`, `desktop.ini` or
`.ds_store` in any letter case (the engine skips the same names when it seals). Each
difference is a `tree.mismatch` error (`added: P`, `changed: P`, `missing: P`). A
malformed inventory, a link, reparse point or offline placeholder, any other
non-regular entry, two names that are equal after NFC normalisation and case folding,
or a file that changes while it is read is `tree.unreadable`. Anything other than
exactly one selected inventory is `tree.inventory_count`.

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
   `supported-by` edge, edges to nonexistent nodes, edge types not listed in **Edge
   types**, and `contradicts` or `supersedes` edges that break the rules listed there.
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
12. For an RFC 3161 token: refuse a response whose PKIStatus is not 0 (`granted`).
    `grantedWithMods` (1), which RFC 3161 counts as granted, is refused too
    (`timestamps.token_not_granted`); 2 and above is `timestamps.tsa_refused`. Check
    that the message imprint is the token's declared hash (SHA-256/384/512) of the
    artifact's raw SHA-256 digest (a SHA-256 token may also carry the digest itself).
    The TSA roots come from the **recipient**, never from the bundle. With roots:
    verify the token signature, the critical `timeStamping` key usage, and a
    certificate chain from the signer to a pinned root that is valid at `genTime`.
    Certificates carried inside the token may only serve as intermediates; a root
    the token brings along is never trusted. Report one of three outcomes: verified
    to a pinned root (information), no roots given so only the imprint was matched
    (warning), anything else (error). Revocation cannot be checked offline and the
    report says so.
13. Check every `veridict/delivery` step against its receipt (see **Deliveries**).
14. When the manifest names `enrolled/1`, apply the rules of **Signer profiles**, with
    or without a pinned key. When the manifest and the founding record disagree about
    the profile, report the error `keys.not_trusted`. The reference verifier switches
    the rules on from the manifest only, so when only the founding record names
    `enrolled/1` it reports that one error and not rules 2–6 (see **Known gaps**).

**Pinned keys.** When the recipient pins one or more keys, identity problems become
errors: an unsigned manifest, any unsigned record, and any signer (manifest, record,
`verified-by`, content seal) that is neither pinned nor introduced by a valid
`human/key-rotation` statement signed by an already-trusted key or, in an enrolled
case, enrolled under **Signer profiles** rule 2 by a trusted human. A record signer
that is not pinned must have been introduced in an earlier record. The manifest
signer, `verified-by` signers and content-seal signers are checked against the keys
trusted at the end of the journal (see **Known gaps**). Keys listed in the manifest
must also be pinned or introduced that way, and a broken rotation statement is an
error. Without a pinned key the verifier MUST state that the signer's identity was not
checked.

Verdicts: `VALID` (no findings), `VALID WITH WARNINGS`, `INVALID` (any error).
Reference exit codes: 0 / 2 / 1.

## Verifier versions

Not every rule above is checked by the public release. "0.3.0" is `veridict-verify`
0.3.0 on PyPI. "main" is the development verifier in the VERIDICT engine repository
at the merge of M2 (engine commit `4c760f1`); it is not released yet. Work on
historical release pins (M3) is in progress and not covered here.

The rows on the manifest and key ids, signed records and manifest under a pinned key,
the journal timestamp and `egress_ref`, `captured_at`, the new fields, **Signer
profiles**, `manifest.signers`, **Deliveries** and `--check-tree` were tested on a
synthetic case with two analysts and a system key, built and verified with both
verifiers by check scripts in the engine repository. Those scripts make no key
rotation, origin assessment, Source Brief, AI step or seal record (every bundle is a
snapshot export). The rows on rotation handover, key rotation, origin assessment,
Source Brief and the seal record body come from reading the code: that verifier code
is the same in 0.3.0 and main (the one Source Brief change reads text spans as a
stream). The AI-step policy is covered by the conformance case `ai-step-forbidden`.

| Rule | 0.3.0 | main |
|---|---|---|
| manifest hash and signature; key id matches key bytes | yes | yes |
| pinned key: signed records and manifest, rotation handover | yes | yes |
| journal timestamp: `chain_timestamp` bound by the manifest signature, token to recipient roots | yes | yes |
| `chain_timestamp.egress_ref` | not read; an edit breaks `manifest_hash` | the same |
| `captured_at` is a string | yes | yes |
| key rotation, origin assessment, Source Brief, AI-step policy | yes | yes |
| new fields `signers`, `signer_public`, `timestamp_egress_ref` | ignored; a bundle with them still opens | `signers` is checked (rule 6); the other two are not read |
| **Signer profiles** `enrolled/1`, rules 1–6 | **no** | yes: `keys.not_trusted`, `signatures.signer_not_trusted`, `semantics.verification_invalid` |
| `manifest.signers` equals the journal | no | yes: `keys.not_trusted` |
| **Deliveries** receipt check | no | yes: `delivery.receipt_invalid` |
| `--check-tree` | **crashes** (`ModuleNotFoundError`: `veridict_verify/tree.py` is missing from the 0.3.0 package) whenever every earlier check passed, for example with no pin or on a single-signer import with its key pinned. After an earlier error (for example the founding key pinned on an enrolled bundle with more signers) the folder comparison is skipped without a message | yes: `folder-inventory/1`, else the last `folder-inventory/2`; skipped without a message after an earlier error |
| seal record body | not checked | not checked |

What this means for a recipient of an enrolled bundle (for example any level-two
import) who has only 0.3.0:

- **With the founding key pinned**, 0.3.0 marks a *correct* bundle with a second analyst
  or a system key `INVALID` (`signatures.signer_not_trusted`, `keys.not_trusted`,
  `artifacts.content_signer_not_trusted`, `semantics.verifier_not_trusted`): it does
  not know enrollment, so every enrolled key looks like a stranger.
- **Without a pin**, 0.3.0 says `VALID WITH WARNINGS` both for a correct bundle and for
  bundles broken in ways only main catches: an edited signer summary, a delivery that
  differs from its receipt, a record signed by a key nobody enrolled, a system key
  enrolling another key or verifying a claim, a system step attributed to an analyst,
  a manifest that drops the profile.

An enrolled bundle therefore needs a verifier newer than 0.3.0.

### Known gaps (to be fixed in the engine/verifier)

This page describes what main does. In four places that falls short of what the format
intends. Each fix is tracked for the engine owner; until it lands, a recipient should
read verdicts with these limits.

1. **A `human/…` step need not be signed by a person.** Rule 4 looks at the step's
   `agent`, not its `tool`. The engine lets a system key write a `human/…` step
   attributed to its own system agent, and the verifier accepts it, pinned or not.
   *Effect:* a system account can record a `human/origin-assessment` that marks two
   sources independent and so raises a confidence ceiling. Check that the step's
   `agent` is a human agent before reading it as a person's decision.
2. **Content seals are checked against the keys trusted at the end of the journal**,
   not at the artifact's record. *Effect:* with a pinned key, a standalone seal passes
   when its key was enrolled or rotated in only after the artifact was written. The
   record itself must still be signed by a key trusted at that point, and the engine
   always seals with the record's signer, so engine output is unaffected. The same
   applies to `verified-by` signers after a rotation in the single-investigator
   profile (rule 5 covers enrolled cases). 0.3.0 has the rotation half of this gap too.
3. **`enrolled/1` is switched on only by the manifest.** When only the founding record
   names it, the verifier reports the mismatch (`keys.not_trusted`, so `INVALID`) and
   skips rules 2–6. *Effect:* the verdict is right, but the findings are incomplete:
   other rule breaks go unreported, and with a pin the correctly enrolled keys are
   reported as untrusted.
4. **A level-two import's `imported_at` is not in the `Z`, second-precision form**
   (for example `2026-11-25T22:05:02.863920+00:00`, in the `folder-catalog/2` content
   and the `import-receipt/1` text). *Effect:* the value is still RFC 3339 UTC and no
   verdict changes, but a reader that parses the catalog strictly by **Times** rejects
   it.

## Capture methods

`capture_method` values: `file-ingest`, `http-fetch`, `browser-render` (Playwright
Chromium DOM HTML), `browser-screenshot` (full-page PNG derived from a
`browser-render` artifact), `wacz` (browsertrix-crawler capture), `wacz-import`
(externally produced WACZ), `text-extraction` (derived text artifact — always
linked to its source with a `derived-from` edge and to the extraction
`transformed-by` step), `folder-inventory/1` (a sealed folder's inventory).

Level-two imports add `folder-import` (a file copied from the folder),
`journal-entry` (one register row, JSON), `checksum-reconciliation` (an earlier
checksum list, as digest and result), `import-receipt/1`, `folder-catalog/2` and
`folder-inventory/2`. A delivery adds `delivery-record` (its JSON receipt).

WACZ artifacts (`media_type: application/wacz`) are self-describing web archives
(Webrecorder format): they replay in ReplayWeb.page and carry per-resource digests
in their internal `datapackage.json`, on top of VERIDICT's whole-file sealing.

### Standalone content signature (recommended)

Optional Artifact fields `content_signature` (base64 Ed25519) and `content_signer`
(key id) seal the digest independently of the log record. The signed message is the
UTF-8 string `sha256:<64 lowercase hex>`. A conforming verifier MUST:

- when both fields are present: verify the signature against a manifest public key
  (mismatch = error; unknown signer = warning, or an error when a key is pinned; with a
  pinned key the signer must also be trusted, which the reference verifier checks
  against the keys trusted at the end of the journal, not at the artifact's record:
  see **Known gaps**);
- when both are absent: emit a warning (`artifact has no standalone content signature`)
  so older bundles remain valid.

Current engines populate these fields on every sealed Artifact.

## Timestamps

Two independent anchors per artifact; both stamp the SHA-256 digest only (content
never leaves the machine). `pending` states are legal — offline sealing must never
block an investigation — but are always surfaced by the verifier.

**RFC-3161** — `timestamp_status: anchored` requires a token at `timestamp_ref`.
The engine sends the artifact's raw SHA-256 digest as the TSA message, so the token's
message imprint is the token's declared hash (SHA-256, SHA-384 or SHA-512) of that
digest; a SHA-256 token may also carry the digest itself (the file hashed directly).
Anchors may also land *after* sealing (via `timestamp sync`): tokens at the
conventional path `timestamps/<artifact_id>.tsr` are validated even when the
node's status says `pending`, since append-only nodes are never rewritten. The TSA
signature and certificate chain are checked only against roots the recipient supplies
(verifier obligation 12); without them a token proves nothing about time and the
verifier says so.

The engine asks for a SHA-512 imprint of that digest, with a nonce and a request for
the TSA certificate; that request is all that leaves the machine. It contacts a TSA
only through an explicitly configured transport (`VERIDICT_TSA_URL`, HTTPS, with
`VERIDICT_TSA_ROOTS`); there is no default service. A transport may return an opaque
`egress_ref`, the id of the gateway's record of that outgoing request. The engine
keeps it in the Artifact's `timestamp_egress_ref`, in a `veridict/timestamp` step for a
token obtained later by `timestamp sync`, or in `chain_timestamp.egress_ref`.
Verifiers do not interpret it. In the manifest it is covered by the signature, like
every field.

**Journal timestamp** — one RFC-3161 token can cover the whole journal: its message is
the raw digest of `chain_head`, it is stored at `timestamps/chain-head.tsr`, and the
signed manifest names it in `chain_timestamp` with its SHA-256. It shows that every
record up to the head existed no later than the token's time. A recipient can require
it (`--require-head-timestamp`, which needs `--tsa-roots`).

**OpenTimestamps** — `ots_status: stamped | upgraded` requires a proof at
`timestamp_ots_ref` (default `timestamps/<artifact_id>.ots`). The proof must carry
the OTS magic header (`\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94`)
and commit to the artifact digest. `stamped` means calendar attestation only;
`upgraded` means a Bitcoin block attestation is present (proofs upgrade
asynchronously via `veridict timestamp sync`). The engine requests OpenTimestamps
proofs only when `VERIDICT_ENABLE_OTS=1`. A conforming verifier MUST check
existence, magic, and digest commitment; full Bitcoin chain validation via the OTS
client is recommended but out of the minimal verifier's scope.
