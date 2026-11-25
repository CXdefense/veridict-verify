"""Offline bundle verification.

INDEPENDENCE: this module re-implements every check from the bundle spec
(docs/bundle-format.md). It never imports the veridict engine, so a skeptic
only has to audit this small package - not the tool that made the bundle.

Checks:
  1. manifest      - parses, known spec, hash + signature verify
  2. chain         - full replay: seq, prev links, body hashes, chain hashes
  3. signatures    - every signed record verifies against manifest public keys
  4. artifacts     - every object re-hashed; must match node sha256 and CAS path
  5. semantics     - claims have supported-by edges; verified-by signatures check;
                     edge endpoints exist; labels/confidence sane
  6. timestamps    - RFC-3161 tokens present/verified when possible; pending flagged

Verdict: VALID / VALID WITH WARNINGS / INVALID.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import tempfile
import zipfile
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from veridict_verify import CURRENT_SPEC, SUPPORTED_SPECS
from veridict_verify.codes import can_be_warning

# -- canonical hashing (independent re-implementation) ---------------------------

def _hash_obj(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value} is forbidden")


def _parse_safe_integer(value: str) -> int:
    integer = int(value)
    if not -(2**53 - 1) <= integer <= 2**53 - 1:
        raise ValueError(
            f"I-JSON integer {value} exceeds the RFC 8785 safe domain"
        )
    return integer


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # I-JSON (RFC 7493) forbids duplicate member names. Parsers disagree on which
    # duplicate wins, so a bundle could hash one value and display another.
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON member name {key!r} is forbidden")
        obj[key] = value
    return obj


def _loads_strict_json(text: str) -> Any:
    return json.loads(
        text,
        parse_constant=_reject_non_finite,
        parse_int=_parse_safe_integer,
        object_pairs_hook=_reject_duplicate_keys,
    )


# -- bundle-relative paths ----------------------------------------------------------

CAS_PREFIX = "objects/sha256/"


def _canonical_storage_path(sha256: str) -> str:
    return f"{CAS_PREFIX}{sha256[:2]}/{sha256}"


def _is_plain_relative_path(rel: Any) -> bool:
    if not isinstance(rel, str) or not rel:
        return False
    if any(bad in rel for bad in ("\\", ":", "\x00")) or rel.startswith("/"):
        return False
    return all(part not in ("", ".", "..") for part in rel.split("/"))


def _bundle_member(root: Path, rel: Any) -> Path | None:
    """Resolve a path taken from bundle data; None if it could leave the bundle.

    Paths inside records are untrusted. Only plain relative POSIX paths are
    accepted: no absolute paths, drive letters, backslashes, `.`/`..` segments,
    colons (NTFS streams) or NUL bytes, and the resolved file must stay inside
    the bundle root (no symlink escapes).
    """
    if not _is_plain_relative_path(rel):
        return None
    candidate = root.joinpath(*rel.split("/"))
    try:
        resolved_root = root.resolve()
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    if resolved != resolved_root and resolved_root not in resolved.parents:
        return None
    return candidate


def _verify_sig(pub_b64: Any, sig_b64: Any, data: Any) -> bool:
    if not isinstance(pub_b64, str) or not isinstance(sig_b64, str):
        return False
    if not isinstance(data, bytes):
        return False
    try:
        pub_bytes = base64.b64decode(pub_b64, validate=True)
        sig_bytes = base64.b64decode(sig_b64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, data)
        return True
    except Exception:
        return False


def _batch_entries(body: Any) -> list[dict[str, Any]]:
    """Independently validate and return ordered graph children."""
    if not isinstance(body, dict) or set(body) != {"entries"}:
        raise ValueError("body must contain only an entries list")
    entries = body["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("entries must be a non-empty list")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"kind", "body"}:
            raise ValueError(f"entry {index} must contain kind and body")
        if entry["kind"] not in ("node", "edge"):
            raise ValueError(f"entry {index} has invalid kind")
        if not isinstance(entry["body"], dict):
            raise ValueError(f"entry {index} body must be an object")
    return entries


def _graph_body_error(entry_kind: str, body: Any) -> str | None:
    """Validate primitive graph fields before any dictionary operations."""
    if not isinstance(body, dict):
        return f"{entry_kind} body must be an object"
    required_strings = (
        ("id", "kind", "created_at")
        if entry_kind == "node"
        else ("id", "src", "dst", "edge_type", "created_at")
    )
    if any(not isinstance(body.get(field), str) for field in required_strings):
        return f"{entry_kind} body has malformed required string fields"
    if entry_kind == "edge":
        if not isinstance(body.get("meta"), dict):
            return "edge body meta must be an object"
        if body.get("edge_type") == "verified-by":
            meta = body["meta"]
            if any(
                not isinstance(meta.get(field), str)
                for field in ("claim_body_hash", "signature", "signer")
            ):
                return "verified-by edge metadata is malformed"
        return None

    kind = body["kind"]
    if kind == "artifact":
        if any(
            not isinstance(body.get(field), str)
            for field in ("sha256", "media_type", "storage_path")
        ):
            return "artifact body has malformed required string fields"
        size = body.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            return "artifact body size must be a non-negative integer"
        sha256 = body["sha256"]
        if len(sha256) != 64 or any(
            character not in "0123456789abcdef" for character in sha256
        ):
            return "artifact body sha256 must be lowercase hexadecimal"
        for field in (
            "timestamp_ref",
            "timestamp_ots_ref",
            "content_signature",
            "content_signer",
        ):
            if body.get(field) is not None and not isinstance(body.get(field), str):
                return f"artifact body {field} must be a string or null"
        for field in (
            "capture_method",
            "captured_at",
            "tool_version",
            "timestamp_status",
            "ots_status",
        ):
            if not isinstance(body.get(field), str):
                return f"artifact body {field} must be a string"
    elif kind == "claim":
        if not isinstance(body.get("text"), str) or not isinstance(body.get("label"), str):
            return "claim body has malformed text or label"
        if not isinstance(body.get("single_source"), bool):
            return "claim body single_source must be boolean"
    elif kind == "step":
        if not isinstance(body.get("tool"), str):
            return "step body tool must be a string"
        if not isinstance(body.get("params"), dict):
            return "step body params must be an object"
        for field in ("inputs", "outputs"):
            value = body.get(field)
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                return f"step body {field} must be a string list"
    elif kind == "agent":
        if not isinstance(body.get("agent_kind"), str) or not isinstance(
            body.get("name"), str
        ):
            return "agent body has malformed required fields"
    else:
        return f"node body has unknown kind {kind!r}"
    return None


# -- results ------------------------------------------------------------------------

@dataclass
class Finding:
    level: str  # "error" | "warning" | "info"
    check: str
    message: str
    code: str = ""  # stable identifier, e.g. "manifest.unsigned" (see docs/finding-codes.md)
    allowed: bool = False  # a warning the recipient explicitly accepted (--allow-warning)


@dataclass
class Report:
    bundle: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    allowed_warnings: frozenset[str] = frozenset()

    def error(self, check: str, msg: str, code: str = "") -> None:
        self.findings.append(Finding("error", check, msg, code))

    def warn(self, check: str, msg: str, code: str = "") -> None:
        allowed = bool(code) and code in self.allowed_warnings
        self.findings.append(Finding("warning", check, msg, code, allowed))

    def info(self, check: str, msg: str, code: str = "") -> None:
        self.findings.append(Finding("info", check, msg, code))

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "error"]

    @property
    def warnings(self) -> list[Finding]:
        """Warnings that count against the verdict (not explicitly allowed)."""
        return [f for f in self.findings if f.level == "warning" and not f.allowed]

    @property
    def allowed(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "warning" and f.allowed]

    @property
    def verdict(self) -> str:
        if self.errors:
            return "INVALID"
        if self.warnings:
            return "VALID WITH WARNINGS"
        return "VALID"

    def to_json(self) -> dict[str, Any]:
        return {
            "bundle": self.bundle,
            "verdict": self.verdict,
            "stats": self.stats,
            "allowed_warnings": sorted(self.allowed_warnings),
            "findings": [
                {
                    "level": f.level,
                    "code": f.code,
                    "check": f.check,
                    "message": f.message,
                    **({"allowed": True} if f.allowed else {}),
                }
                for f in self.findings
            ],
        }


# -- verification -----------------------------------------------------------------------

#: Default limits for unpacking an untrusted archive (both can be raised by the caller).
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_BYTES = 8 * 1024**3


def _archive_problems(
    zf: zipfile.ZipFile,
    *,
    max_members: int,
    max_total_bytes: int,
) -> list[tuple[str, str]]:
    """Reject archives that are too large or whose member names are unsafe."""
    infos = zf.infolist()
    problems: list[tuple[str, str]] = []
    if len(infos) > max_members:
        problems.append(
            ("archive.too_many_members", f"archive has {len(infos)} members (limit {max_members})")
        )
    total = sum(info.file_size for info in infos)
    if total > max_total_bytes:
        problems.append(
            ("archive.too_large", f"archive unpacks to {total} bytes (limit {max_total_bytes})")
        )
    seen: set[str] = set()
    for info in infos:
        name = info.filename
        stripped = name[:-1] if info.is_dir() else name
        if not _is_plain_relative_path(stripped):
            problems.append(("archive.unsafe_name", f"archive member has an unsafe name: {name!r}"))
        elif (info.external_attr >> 16) & 0o170000 == 0o120000:
            problems.append(("archive.symlink", f"archive member is a symbolic link: {name!r}"))
        elif name in seen:
            problems.append(("archive.duplicate_member", f"archive member appears twice: {name!r}"))
        seen.add(name)
    return problems


def verify_bundle(
    bundle_path: Path,
    *,
    trusted_keys: set[str] | None = None,
    tsa_roots: Any = None,
    require_head_timestamp: bool = False,
    check_tree: Path | None = None,
    allow_warnings: set[str] | frozenset[str] | None = None,
    forbid_ai_steps: bool = False,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_total_bytes: int = MAX_ARCHIVE_BYTES,
) -> Report:
    """Verify a bundle file or unpacked directory.

    `tsa_roots` are the time-stamp authority roots the *recipient* trusts: a path
    to a PEM file or a folder of them, or a list of certificates. Roots are never
    taken from the bundle. Without them a token is only matched to its artifact.

    `allow_warnings` names warning codes the recipient accepts; they are still
    reported but no longer count against the verdict. Only codes that can be
    warnings are accepted (ValueError otherwise): an error can never be allowed.
    `forbid_ai_steps` makes every step that names a model an error.
    """
    allowed = frozenset(allow_warnings or ())
    unknown = sorted(code for code in allowed if not can_be_warning(code))
    if unknown:
        raise ValueError(
            "not a warning code (see docs/finding-codes.md): " + ", ".join(unknown)
        )
    bundle_path = Path(bundle_path)
    report = Report(bundle=str(bundle_path), allowed_warnings=allowed)
    if require_head_timestamp and not tsa_roots:
        report.error("timestamps", "a required journal timestamp needs trusted TSA roots", code="timestamps.roots_required")
        return report
    roots = tsa_roots
    if isinstance(tsa_roots, (str, Path)):
        try:
            roots = load_tsa_roots(tsa_roots)
        except (OSError, ValueError) as exc:
            report.error("timestamps", f"cannot read --tsa-roots {tsa_roots}: {exc}", code="timestamps.roots_unreadable")
            return report
        if not roots:
            report.error("timestamps", f"no certificates found in --tsa-roots {tsa_roots}", code="timestamps.roots_empty")
            return report

    if bundle_path.is_dir():
        return _verify_tree(bundle_path, report, trusted_keys=trusted_keys, tsa_roots=roots,
                            check_tree=check_tree, require_head_timestamp=require_head_timestamp,
                            forbid_ai_steps=forbid_ai_steps)

    if not zipfile.is_zipfile(bundle_path):
        report.error("manifest", "not a zip file / veridict bundle", code="archive.not_zip")
        return report
    with tempfile.TemporaryDirectory(prefix="veridict-verify-") as tmp:
        with zipfile.ZipFile(bundle_path) as zf:
            problems = _archive_problems(
                zf, max_members=max_members, max_total_bytes=max_total_bytes
            )
            if problems:
                for code, problem in problems:
                    report.error("archive", problem, code=code)
                return report
            zf.extractall(tmp)
        return _verify_tree(Path(tmp), report, trusted_keys=trusted_keys, tsa_roots=roots,
                            check_tree=check_tree, require_head_timestamp=require_head_timestamp,
                            forbid_ai_steps=forbid_ai_steps)


def _source_brief_artifact_text(
    root: Path,
    artifact: Any,
) -> tuple[str | None, str | None]:
    if not isinstance(artifact, dict):
        return None, "artifact node is malformed"
    media_type = artifact.get("media_type")
    if not isinstance(media_type, str) or not (
        media_type.startswith("text/")
        or media_type
        in {"application/json", "application/xml", "application/xhtml+xml"}
    ):
        return None, "citation artifact is not text-readable"
    storage_path = artifact.get("storage_path")
    sha256 = artifact.get("sha256")
    if not isinstance(storage_path, str) or not isinstance(sha256, str):
        return None, "citation artifact CAS metadata is malformed"
    if storage_path != _canonical_storage_path(sha256):
        return None, "citation artifact storage path is not its content address"
    object_path = _bundle_member(root, storage_path)
    if object_path is None:
        return None, "citation artifact storage path leaves the bundle"
    try:
        data = object_path.read_bytes()
    except OSError:
        return None, "citation artifact CAS object is unavailable"
    if hashlib.sha256(data).hexdigest() != sha256:
        return None, "citation artifact CAS verification failed"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "citation artifact is not valid UTF-8"


SOURCE_BRIEF_SCHEMA = "veridict-source-brief/1"
SOURCE_BRIEF_MAX_CONTEXT_CHARS = 64_000
SOURCE_BRIEF_MAX_SPANS = 64
ENTITY_TYPES = {
    "person", "organization", "domain", "email", "phone", "address",
    "location", "identifier", "other",
}
BRIEF_LIMITS = {
    "statement": 4_000,
    "entity_name": 320,
    "relation": 240,
    "finding": 4_000,
    "significance": 4_000,
    "quote": 4_000,
    "limitation": 1_000,
    "next_check": 2_000,
    "citations": 8,
    "entities": 100,
    "relationships": 200,
    "findings": 100,
    "limitations": 50,
    "next_checks": 50,
}


def _stable_brief_id(prefix: str, *parts: str) -> str:
    normalized = "\0".join(" ".join(part.lower().split()) for part in parts)
    return f"{prefix}_{hashlib.sha256(normalized.encode()).hexdigest()[:16]}"


def _confidence(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def _exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _verify_source_brief_steps(
    report: Report,
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    root: Path,
) -> None:
    """Independently validate the versioned, hardened Source Brief schema."""
    used_by_step: dict[str, set[str]] = {}
    for edge in edges:
        if edge.get("edge_type") == "used":
            used_by_step.setdefault(edge["src"], set()).add(edge["dst"])

    for step in nodes.values():
        if step.get("kind") != "step":
            continue
        params = step.get("params")
        tool_is_brief = step.get("tool") == "ollama/source-brief"
        role_is_brief = isinstance(params, dict) and params.get("role") == "source-brief"
        if not tool_is_brief and not role_is_brief:
            continue
        step_id = step.get("id", "<unknown>")
        if not isinstance(params, dict):
            report.error("source-brief", f"step {step_id}: params must be an object", code="source_brief.params_invalid")
            continue
        schema = params.get("source_brief_schema")
        if schema is None:
            if tool_is_brief:
                report.error(
                    "source-brief",
                    f"step {step_id}: hardened Source Brief schema is missing", code="source_brief.schema_missing",
                )
            else:
                report.warn(
                    "source-brief",
                    f"step {step_id}: legacy Source Brief; hardened semantics unavailable", code="source_brief.legacy",
                )
            continue
        if schema != SOURCE_BRIEF_SCHEMA:
            report.error(
                "source-brief", f"step {step_id}: unsupported Source Brief schema {schema!r}", code="source_brief.schema_unsupported"
            )
            continue

        brief = params.get("validated_brief")
        retrieval = params.get("retrieval")
        brief_keys = {
            "source_artifact_id", "analysis_artifact_id", "source_identity",
            "summary", "entities", "relationships", "findings", "limitations",
            "next_checks",
        }
        if not _exact_keys(brief, brief_keys):
            report.error("source-brief", f"step {step_id}: invalid brief top-level schema", code="source_brief.top_level_invalid")
            continue
        if not isinstance(retrieval, dict):
            report.error("source-brief", f"step {step_id}: retrieval must be an object", code="source_brief.retrieval_invalid")
            continue
        if params.get("validated_brief_sha256") != _hash_obj(brief):
            report.error("source-brief", f"step {step_id}: validated brief hash mismatch", code="source_brief.hash_mismatch")

        source_id, analysis_id = (
            brief["source_artifact_id"], brief["analysis_artifact_id"]
        )
        for label, artifact_id in (("source", source_id), ("analysis", analysis_id)):
            artifact = nodes.get(artifact_id) if isinstance(artifact_id, str) else None
            if not isinstance(artifact, dict) or artifact.get("kind") != "artifact":
                report.error(
                    "source-brief", f"step {step_id}: declared {label} artifact missing", code="source_brief.artifact_missing"
                )
                continue
            if artifact_id not in used_by_step.get(str(step_id), set()):
                report.error(
                    "source-brief", f"step {step_id}: no used edge to {label} artifact", code="source_brief.used_edge_missing"
                )
            if artifact_id not in step.get("inputs", []):
                report.error(
                    "source-brief", f"step {step_id}: {label} artifact missing from inputs", code="source_brief.input_missing"
                )

        retrieval_keys = {
            "method", "max_context_chars", "selected_chars", "config", "spans"
        }
        if not retrieval_keys <= set(retrieval):
            report.error("source-brief", f"step {step_id}: retrieval metadata incomplete", code="source_brief.retrieval_incomplete")
        max_context = retrieval.get("max_context_chars")
        selected_chars = retrieval.get("selected_chars")
        raw_spans = retrieval.get("spans")
        if (
            isinstance(max_context, bool) or not isinstance(max_context, int)
            or max_context <= 0
            or max_context > SOURCE_BRIEF_MAX_CONTEXT_CHARS
            or isinstance(selected_chars, bool) or not isinstance(selected_chars, int)
            or selected_chars < 0 or selected_chars > max_context
            or not isinstance(retrieval.get("method"), str)
            or not isinstance(retrieval.get("config"), dict)
            or not isinstance(raw_spans, list)
            or len(raw_spans) > SOURCE_BRIEF_MAX_SPANS
        ):
            report.error("source-brief", f"step {step_id}: retrieval metadata malformed", code="source_brief.retrieval_malformed")
            raw_spans = []

        spans: list[dict[str, Any]] = []
        span_chars = 0
        for index, span in enumerate(raw_spans):
            expected = {"artifact_id", "start", "end", "score", "text_sha256"}
            if not _exact_keys(span, expected):
                report.error("source-brief", f"step {step_id}: span {index} malformed", code="source_brief.span_malformed")
                continue
            artifact_id, start, end, score, digest = (
                span["artifact_id"], span["start"], span["end"],
                span["score"], span["text_sha256"],
            )
            if (
                not isinstance(artifact_id, str)
                or artifact_id != analysis_id
                or isinstance(start, bool) or not isinstance(start, int) or start < 0
                or isinstance(end, bool) or not isinstance(end, int) or end <= start
                or isinstance(score, bool) or not isinstance(score, (int, float))
                or not math.isfinite(float(score)) or float(score) < 0
                or not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                report.error("source-brief", f"step {step_id}: span {index} metadata invalid", code="source_brief.span_metadata_invalid")
                continue
            text, error = _source_brief_artifact_text(root, nodes.get(artifact_id))
            if error or text is None or end > len(text):
                report.error("source-brief", f"step {step_id}: span {index}: {error or 'bounds invalid'}", code="source_brief.span_bounds_invalid")
                continue
            actual = hashlib.sha256(text[start:end].encode()).hexdigest()
            if actual != digest:
                report.error("source-brief", f"step {step_id}: span {index} hash mismatch", code="source_brief.span_hash_mismatch")
                continue
            spans.append(span)
            span_chars += end - start
        if isinstance(selected_chars, int) and not isinstance(selected_chars, bool):
            if span_chars != selected_chars:
                report.error("source-brief", f"step {step_id}: selected_chars mismatch", code="source_brief.selected_chars_mismatch")

        collections = {
            "entities": BRIEF_LIMITS["entities"],
            "relationships": BRIEF_LIMITS["relationships"],
            "findings": BRIEF_LIMITS["findings"],
            "limitations": BRIEF_LIMITS["limitations"],
            "next_checks": BRIEF_LIMITS["next_checks"],
        }
        collections_ok = True
        for name, limit in collections.items():
            value = brief[name]
            if not isinstance(value, list) or len(value) > limit:
                report.error("source-brief", f"step {step_id}: {name} collection invalid", code="source_brief.collection_invalid")
                collections_ok = False
        if not collections_ok:
            continue

        factual: list[dict[str, Any]] = []
        for name in ("source_identity", "summary"):
            item = brief[name]
            if item is None:
                continue
            if (
                not _exact_keys(item, {"text", "label", "confidence", "citations"})
                or not isinstance(item["text"], str)
                or not item["text"] or len(item["text"]) > BRIEF_LIMITS["statement"]
                or item["label"] != "inferred"
                or not _confidence(item["confidence"])
            ):
                report.error("source-brief", f"step {step_id}: {name} invalid", code="source_brief.field_invalid")
            else:
                factual.append(item)

        accepted_entities: set[str] = set()
        for item in brief["entities"]:
            expected = {"entity_id", "name", "entity_type", "confidence", "citations"}
            if (
                not _exact_keys(item, expected)
                or not isinstance(item["name"], str) or not item["name"]
                or len(item["name"]) > BRIEF_LIMITS["entity_name"]
                or item["entity_type"] not in ENTITY_TYPES
                or not _confidence(item["confidence"])
            ):
                report.error("source-brief", f"step {step_id}: entity invalid", code="source_brief.entity_invalid")
                continue
            expected_id = _stable_brief_id("ent", item["entity_type"], item["name"])
            if item["entity_id"] != expected_id or expected_id in accepted_entities:
                report.error("source-brief", f"step {step_id}: entity ID invalid", code="source_brief.entity_id_invalid")
                continue
            accepted_entities.add(expected_id)
            factual.append(item)

        seen_relationships: set[str] = set()
        for item in brief["relationships"]:
            expected = {
                "relationship_id", "source_entity_id", "target_entity_id",
                "relation", "confidence", "citations",
            }
            if (
                not _exact_keys(item, expected)
                or not isinstance(item["relation"], str) or not item["relation"]
                or len(item["relation"]) > BRIEF_LIMITS["relation"]
                or not _confidence(item["confidence"])
                or item["source_entity_id"] not in accepted_entities
                or item["target_entity_id"] not in accepted_entities
            ):
                report.error("source-brief", f"step {step_id}: relationship invalid", code="source_brief.relationship_invalid")
                continue
            expected_id = _stable_brief_id(
                "rel", item["source_entity_id"], item["relation"],
                item["target_entity_id"],
            )
            if item["relationship_id"] != expected_id or expected_id in seen_relationships:
                report.error("source-brief", f"step {step_id}: relationship ID invalid", code="source_brief.relationship_id_invalid")
                continue
            seen_relationships.add(expected_id)
            factual.append(item)

        seen_findings: set[str] = set()
        for item in brief["findings"]:
            expected = {
                "candidate_id", "text", "significance", "confidence", "citations"
            }
            if (
                not _exact_keys(item, expected)
                or not isinstance(item["text"], str) or not item["text"]
                or len(item["text"]) > BRIEF_LIMITS["finding"]
                or not isinstance(item["significance"], str) or not item["significance"]
                or len(item["significance"]) > BRIEF_LIMITS["significance"]
                or not _confidence(item["confidence"])
            ):
                report.error("source-brief", f"step {step_id}: finding invalid", code="source_brief.finding_invalid")
                continue
            expected_id = _stable_brief_id("cand", item["text"], item["significance"])
            if item["candidate_id"] != expected_id or expected_id in seen_findings:
                report.error("source-brief", f"step {step_id}: finding ID invalid", code="source_brief.finding_id_invalid")
                continue
            seen_findings.add(expected_id)
            factual.append(item)

        for item in brief["limitations"]:
            if (
                not _exact_keys(item, {"code", "text"})
                or not isinstance(item["code"], str) or not item["code"]
                or len(item["code"]) > 80
                or not isinstance(item["text"], str) or not item["text"]
                or len(item["text"]) > BRIEF_LIMITS["limitation"]
            ):
                report.error("source-brief", f"step {step_id}: limitation invalid", code="source_brief.limitation_invalid")
        for item in brief["next_checks"]:
            expected = {"purpose", "source_type", "query", "reason"}
            if (
                not _exact_keys(item, expected)
                or any(
                    not isinstance(item[field], str) or not item[field]
                    or len(item[field]) > BRIEF_LIMITS["next_check"]
                    for field in expected
                )
            ):
                report.error("source-brief", f"step {step_id}: next check invalid", code="source_brief.next_check_invalid")

        for item in factual:
            citations = item.get("citations")
            if (
                not isinstance(citations, list) or not citations
                or len(citations) > BRIEF_LIMITS["citations"]
            ):
                report.error("source-brief", f"step {step_id}: citations invalid", code="source_brief.citations_invalid")
                continue
            for citation in citations:
                expected = {"artifact_id", "quote", "start", "end"}
                if not _exact_keys(citation, expected):
                    report.error("source-brief", f"step {step_id}: citation malformed", code="source_brief.citation_malformed")
                    continue
                artifact_id, quote, start, end = (
                    citation["artifact_id"], citation["quote"],
                    citation["start"], citation["end"],
                )
                if (
                    not isinstance(artifact_id, str) or artifact_id != analysis_id
                    or not isinstance(quote, str) or not quote
                    or len(quote) > BRIEF_LIMITS["quote"]
                    or isinstance(start, bool) or not isinstance(start, int) or start < 0
                    or isinstance(end, bool) or not isinstance(end, int) or end <= start
                ):
                    report.error("source-brief", f"step {step_id}: citation metadata invalid", code="source_brief.citation_metadata_invalid")
                    continue
                text, error = _source_brief_artifact_text(root, nodes.get(artifact_id))
                if error or text is None or end > len(text) or text[start:end] != quote:
                    report.error("source-brief", f"step {step_id}: citation quote/offset mismatch", code="source_brief.citation_mismatch")
                    continue
                if not any(
                    span["start"] <= start and end <= span["end"] for span in spans
                ):
                    report.error("source-brief", f"step {step_id}: citation outside retrieval span", code="source_brief.citation_outside_span")


def _verify_supported_by_citations(
    report: Report,
    edge: dict[str, Any],
    nodes: dict[str, Any],
    root: Path,
) -> None:
    """Re-check exact quote/offset citations on every supported-by edge.

    Source Brief steps already validate their own citations; this closes the
    gap for ask(), human-accepted findings, and deterministic analysis Steps
    such as impersonation-comparison.
    """
    meta = edge.get("meta")
    if not isinstance(meta, dict):
        return
    citations = meta.get("citations")
    if citations is None:
        return
    edge_id = edge.get("id", "<unknown>")
    if not isinstance(citations, list):
        report.error(
            "semantics",
            f"supported-by {edge_id}: citations must be a list", code="semantics.citations_not_list",
        )
        return
    target = nodes.get(edge.get("dst"))
    for index, citation in enumerate(citations):
        if not isinstance(citation, dict):
            report.error(
                "semantics",
                f"supported-by {edge_id}: citation[{index}] is not an object", code="semantics.citation_not_object",
            )
            continue
        quote = citation.get("quote")
        start = citation.get("start")
        end = citation.get("end")
        if (
            not isinstance(quote, str)
            or not quote
            or isinstance(start, bool)
            or not isinstance(start, int)
            or start < 0
            or isinstance(end, bool)
            or not isinstance(end, int)
            or end <= start
        ):
            report.error(
                "semantics",
                f"supported-by {edge_id}: citation[{index}] metadata invalid", code="semantics.citation_metadata_invalid",
            )
            continue
        text, error = _source_brief_artifact_text(root, target)
        if error or text is None:
            report.error(
                "semantics",
                f"supported-by {edge_id}: citation[{index}] artifact unreadable "
                f"({error or 'unknown'})", code="semantics.citation_artifact_unreadable",
            )
            continue
        if end > len(text) or text[start:end] != quote:
            report.error(
                "semantics",
                f"supported-by {edge_id}: citation[{index}] quote/offset mismatch", code="semantics.citation_mismatch",
            )


class _OriginUnion:
    def __init__(self, values: list[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            low, high = sorted((left_root, right_root))
            self.parent[high] = low


def _origin_domain(source_url: Any) -> str | None:
    if not isinstance(source_url, str) or not source_url:
        return None
    parsed = urlparse(source_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        parts = [part for part in host.split(".") if part]
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    return host


def _verify_corroboration(
    report: Report,
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    verified_claims: set[str],
) -> dict[str, dict[str, Any]]:
    """Independently derive corroboration/1 from graph nodes and edges."""
    derived: dict[str, list[str]] = {}
    supported: dict[str, list[str]] = {}
    for edge in edges:
        if edge.get("edge_type") == "derived-from":
            derived.setdefault(str(edge.get("src")), []).append(str(edge.get("dst")))
        elif edge.get("edge_type") == "supported-by":
            supported.setdefault(str(edge.get("src")), []).append(str(edge.get("dst")))

    def artifact_roots(artifact_id: str, visiting: frozenset[str] = frozenset()) -> set[str]:
        if artifact_id in visiting:
            raise ValueError(f"artifact lineage cycle at {artifact_id}")
        artifact = nodes.get(artifact_id)
        if not isinstance(artifact, dict) or artifact.get("kind") != "artifact":
            raise ValueError(f"artifact {artifact_id!r} does not exist")
        parents = sorted(
            {
                parent
                for parent in derived.get(artifact_id, [])
                if (nodes.get(parent) or {}).get("kind") == "artifact"
            }
        )
        if not parents:
            return {artifact_id}
        roots: set[str] = set()
        for parent in parents:
            roots.update(artifact_roots(parent, visiting | {artifact_id}))
        return roots

    def claim_roots(claim_id: str, visiting: frozenset[str] = frozenset()) -> set[str]:
        if claim_id in visiting:
            raise ValueError(f"claim support cycle at {claim_id}")
        roots: set[str] = set()
        for target in sorted(set(supported.get(claim_id, []))):
            node = nodes.get(target)
            if not isinstance(node, dict):
                raise ValueError(f"supporting node {target!r} does not exist")
            if node.get("kind") == "artifact":
                roots.update(artifact_roots(target))
            elif node.get("kind") == "claim":
                roots.update(claim_roots(target, visiting | {claim_id}))
            else:
                raise ValueError(f"unsupported evidence node {target!r}")
        return roots

    assessments: list[tuple[str, str, str]] = []
    for step in nodes.values():
        if step.get("kind") != "step" or step.get("tool") != "human/origin-assessment":
            continue
        step_id = step.get("id", "<unknown>")
        params = step.get("params")
        inputs = step.get("inputs")
        valid = isinstance(params, dict)
        left = params.get("artifact_a") if valid else None
        right = params.get("artifact_b") if valid else None
        decision = params.get("decision") if valid else None
        reason = params.get("reason") if valid else None
        schema = params.get("schema") if valid else None
        agent = nodes.get(step.get("agent"))
        if (
            not valid
            or schema != "corroboration/1"
            or not isinstance(left, str)
            or not isinstance(right, str)
            or left == right
            or (nodes.get(left) or {}).get("kind") != "artifact"
            or (nodes.get(right) or {}).get("kind") != "artifact"
            or decision not in {"same-origin", "independent"}
            or not isinstance(reason, str)
            or not reason.strip()
            or not isinstance(inputs, list)
            or sorted(inputs) != sorted([left, right])
            or not isinstance(agent, dict)
            or agent.get("kind") != "agent"
        ):
            report.error(
                "corroboration",
                f"origin assessment {step_id}: malformed corroboration/1 step", code="corroboration.assessment_malformed",
            )
            continue
        assessments.append((left, right, decision))

    result: dict[str, dict[str, Any]] = {}
    claims = sorted(
        (node for node in nodes.values() if node.get("kind") == "claim"),
        key=lambda node: node["id"],
    )
    for claim in claims:
        claim_id = claim["id"]
        try:
            roots = sorted(claim_roots(claim_id))
        except ValueError as exc:
            report.error("corroboration", f"claim {claim_id}: {exc}", code="corroboration.claim_invalid")
            continue
        root_set = set(roots)
        union = _OriginUnion(roots)
        hashes = {
            root: str((nodes.get(root) or {}).get("sha256", "")).lower()
            for root in roots
        }
        domains = {
            root: _origin_domain((nodes.get(root) or {}).get("source_url"))
            for root in roots
        }

        effective: dict[tuple[str, str], str] = {}
        for left, right, decision in assessments:
            try:
                left_roots = artifact_roots(left) & root_set
                right_roots = artifact_roots(right) & root_set
            except ValueError as exc:
                report.error("corroboration", f"origin assessment: {exc}", code="corroboration.assessment_invalid")
                continue
            for left_root in sorted(left_roots):
                for right_root in sorted(right_roots):
                    if left_root != right_root:
                        effective[tuple(sorted((left_root, right_root)))] = decision

        for left, right in combinations(roots, 2):
            if hashes[left] and hashes[left] == hashes[right]:
                union.union(left, right)
        for pair, decision in sorted(effective.items()):
            if decision == "same-origin":
                union.union(*pair)
        for domain in sorted({value for value in domains.values() if value}):
            domain_roots = sorted(root for root in roots if domains[root] == domain)
            components: dict[str, list[str]] = {}
            for root in domain_roots:
                representative = union.find(root)
                components.setdefault(representative, []).append(root)
            buckets: list[list[str]] = []
            for representative in sorted(components):
                placed = False
                for bucket in buckets:
                    conflicts = any(
                        effective.get(tuple(sorted((left, right)))) == "independent"
                        for existing in bucket
                        for left in components[representative]
                        for right in components[existing]
                        if left != right
                    )
                    if not conflicts:
                        bucket.append(representative)
                        placed = True
                        break
                if not placed:
                    buckets.append([representative])
            for bucket in buckets:
                for representative in bucket[1:]:
                    union.union(bucket[0], representative)

        groups: dict[str, list[str]] = {}
        for root in roots:
            groups.setdefault(union.find(root), []).append(root)
        independent_m = len(groups)
        ceiling = (
            None
            if independent_m == 0
            else 0.60
            if independent_m == 1
            else 0.85
            if independent_m == 2
            else 1.00
        )
        flags: set[str] = set()
        for members in groups.values():
            for left, right in combinations(sorted(members), 2):
                if hashes[left] and hashes[left] == hashes[right]:
                    flags.add(f"shared-bytes:{hashes[left]}")
                elif domains[left] and domains[left] == domains[right]:
                    flags.add(f"shared-domain:{domains[left]}")
        for pair, decision in sorted(effective.items()):
            joined = union.find(pair[0]) == union.find(pair[1])
            pair_ids = ":".join(pair)
            if decision == "same-origin":
                flags.add(f"human-same-origin:{pair_ids}")
            elif joined:
                flags.add(f"assessment-conflict:{pair_ids}")

        confidence = claim.get("confidence")
        confidence_valid = confidence is None or _confidence(confidence)
        if not confidence_valid:
            report.error(
                "corroboration",
                f"claim {claim_id}: confidence is invalid (expected finite 0..1 number)", code="corroboration.confidence_invalid",
            )
        elif confidence is not None and ceiling is not None and float(confidence) > ceiling:
            report.error(
                "corroboration",
                f"claim {claim_id}: asserted confidence {float(confidence):.2f} "
                f"exceeds independence ceiling {ceiling:.2f} for M={independent_m}", code="corroboration.confidence_above_ceiling",
            )
        if (
            claim.get("label") == "inferred"
            and independent_m == 1
            and confidence is not None
            and confidence_valid
            and float(confidence) >= 0.60
            and claim_id not in verified_claims
        ):
            report.warn(
                "corroboration",
                f"claim {claim_id}: single independent origin at confidence ceiling "
                "without human verification", code="corroboration.single_origin_at_ceiling",
            )
        serialized_groups: list[dict[str, Any]] = []
        for members in sorted(
            (sorted(items) for items in groups.values()),
            key=lambda items: items[0],
        ):
            member_hashes = {hashes[item] for item in members}
            member_domains = {domains[item] for item in members if domains[item]}
            if len(members) > 1 and len(member_hashes) == 1 and "" not in member_hashes:
                origin_key = f"sha256:{next(iter(member_hashes))}"
            elif len(member_domains) == 1:
                origin_key = f"domain:{next(iter(member_domains))}"
            elif len(members) == 1 and domains[members[0]]:
                origin_key = f"domain:{domains[members[0]]}"
            elif len(members) == 1:
                origin_key = f"file:{hashes[members[0]]}"
            else:
                origin_key = f"manual:{members[0]}"
            serialized_groups.append(
                {"origin_key": origin_key, "artifact_ids": members}
            )
        result[claim_id] = {
            "apparent_n": len(roots),
            "independent_m": independent_m,
            "ceiling": ceiling,
            "groups": serialized_groups,
            "collapse_flags": sorted(flags),
        }
    return result


def _verify_tree(
    root: Path,
    report: Report,
    *,
    trusted_keys: set[str] | None = None,
    tsa_roots: list[Any] | None = None,
    check_tree: Path | None = None,
    require_head_timestamp: bool = False,
    forbid_ai_steps: bool = False,
) -> Report:
    # 1. manifest --------------------------------------------------------------
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        report.error("manifest", "manifest.json missing", code="manifest.missing")
        return report
    try:
        manifest = _loads_strict_json(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as exc:
        report.error("manifest", f"manifest.json unreadable: {exc}", code="manifest.unreadable")
        return report
    if not isinstance(manifest, dict):
        report.error("manifest", "manifest root must be a JSON object", code="manifest.not_object")
        return report

    spec = manifest.get("spec")
    if spec not in SUPPORTED_SPECS:
        report.error("manifest", f"unsupported spec: {spec!r}", code="manifest.spec_unsupported")
        return report

    raw_pubkeys = manifest.get("public_keys", {})
    pubkeys: dict[str, str] = {}
    fingerprints: dict[str, str] = {}  # key_id -> full fingerprint
    if not isinstance(raw_pubkeys, dict):
        report.error("manifest", "public_keys must be an object mapping key ids to base64 keys", code="manifest.public_keys_invalid")
    else:
        for key_id, pub_b64 in raw_pubkeys.items():
            if not isinstance(key_id, str) or not isinstance(pub_b64, str):
                report.error(
                    "manifest",
                    "public_keys entries must map string key ids to base64 strings", code="manifest.public_keys_entry_invalid",
                )
                continue
            try:
                raw_public = base64.b64decode(pub_b64, validate=True)
                Ed25519PublicKey.from_public_bytes(raw_public)
            except Exception:
                report.error("manifest", f"public key {key_id!r} is not valid Ed25519 base64", code="manifest.public_key_invalid")
                continue
            fingerprint = hashlib.sha256(raw_public).hexdigest()
            actual = fingerprint[:16]
            if actual != key_id:
                report.error("manifest", f"public key id mismatch: {key_id} != {actual}", code="manifest.key_id_mismatch")
            pubkeys[key_id] = pub_b64
            fingerprints[key_id] = fingerprint
            report.info(
                "keys",
                f"signer {key_id} fingerprint {fingerprint}", code="keys.signer",
            )

    # Pinned mode: the recipient named the keys they trust. Then every record,
    # the manifest, every human verification and every content seal must be
    # signed by a pinned key or by a key that a pinned key handed over to in a
    # valid rotation statement earlier in the chain. Anything else is an error.
    pinned = bool(trusted_keys)
    authorized: set[str] = set()
    if pinned:
        normalized_trusted = {_normalize_trusted_token(token) for token in trusted_keys or ()}
        for key_id, fingerprint in fingerprints.items():
            if fingerprint in normalized_trusted or key_id in normalized_trusted:
                authorized.add(key_id)
                report.info("keys", f"signer matches pinned key ({key_id})", code="keys.pinned_match")
        if not authorized:
            report.error("keys", "no key in this bundle matches a pinned key", code="keys.no_pinned_key")
    else:
        report.info(
            "keys",
            "signer identity not checked: no key pinned "
            "(pass --trusted-key to require signatures by a known investigator)", code="keys.identity_not_checked",
        )

    def _deny(check: str, msg: str, code: str) -> None:
        # Identity problems are errors when a key is pinned, warnings otherwise.
        if pinned:
            report.error(check, msg, code=code)
        else:
            report.warn(check, msg, code=code)

    # manifest hash + signature
    declared_hash = manifest.get("manifest_hash")
    signature = manifest.get("manifest_signature")
    manifest_core = {
        k: v for k, v in manifest.items() if k not in ("manifest_hash", "manifest_signature")
    }
    recomputed = _hash_obj(manifest_core)
    if declared_hash != recomputed:
        report.error("manifest", "manifest_hash does not match manifest content", code="manifest.hash_mismatch")
    manifest_signer: str | None = None
    if signature is not None:
        if not isinstance(signature, dict):
            report.error("manifest", "manifest_signature must be an object or null", code="manifest.signature_not_object")
            signature = {}
        signer = signature.get("signer")
        sig = signature.get("sig")
        if not isinstance(signer, str) or not isinstance(sig, str):
            report.error("manifest", "manifest signature fields are malformed", code="manifest.signature_malformed")
        elif not isinstance(declared_hash, str):
            report.error("manifest", "manifest signature has a malformed manifest_hash", code="manifest.signature_hash_malformed")
        elif not (pub := pubkeys.get(signer)):
            _deny("manifest", f"manifest signed by unknown key id {signer!r}", code="manifest.signer_unknown")
        elif not _verify_sig(pub, sig, declared_hash.encode()):
            report.error("manifest", "manifest signature does not verify", code="manifest.signature_invalid")
        else:
            manifest_signer = signer
            report.info("manifest", f"manifest signature verifies (key {signer})", code="manifest.signature_ok")
    elif pinned:
        report.error("manifest", "manifest is unsigned (a pinned key requires a signed manifest)", code="manifest.unsigned")
    else:
        report.warn("manifest", "manifest is unsigned", code="manifest.unsigned")

    # 2 + 3. chain replay and record signatures --------------------------------------
    log_path = root / "graph" / "log.jsonl"
    if not log_path.exists():
        report.error("chain", "graph/log.jsonl missing", code="chain.log_missing")
        return report

    nodes: dict[str, dict[str, Any]] = {}
    node_body_hashes: dict[str, str] = {}
    edges: list[dict[str, Any]] = []
    edge_ids: set[str] = set()
    prev: str | None = None
    expected_seq = 0
    signed_records = 0
    total_records = 0

    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total_records += 1
            try:
                rec = _loads_strict_json(line)
            except (json.JSONDecodeError, ValueError) as exc:
                report.error(
                    "chain", f"record {expected_seq}: unparseable JSON: {exc}", code="chain.record_unparseable"
                )
                return report
            if not isinstance(rec, dict):
                report.error("chain", f"record {expected_seq}: must be a JSON object", code="chain.record_not_object")
                return report

            seq = rec.get("seq")
            if seq != expected_seq:
                report.error("chain", f"record {seq}: expected seq {expected_seq}", code="chain.seq_mismatch")
            if rec.get("prev") != prev:
                report.error("chain", f"record {seq}: broken prev link", code="chain.prev_mismatch")
            body_hash = _hash_obj(rec.get("body"))
            if body_hash != rec.get("body_hash"):
                report.error("chain", f"record {seq}: body hash mismatch (tampered)", code="chain.body_hash_mismatch")
            chain_hash = _hash_obj(
                {"seq": seq, "prev": rec.get("prev"), "kind": rec.get("kind"),
                 "body_hash": rec.get("body_hash")}
            )
            if chain_hash != rec.get("chain_hash"):
                report.error("chain", f"record {seq}: chain hash mismatch", code="chain.chain_hash_mismatch")

            record_trusted = False
            if "sig" in rec:
                signed_records += 1
                signer = rec.get("signer")
                sig = rec.get("sig")
                signed_hash = rec.get("chain_hash")
                if (
                    not isinstance(signer, str)
                    or not isinstance(sig, str)
                    or not isinstance(signed_hash, str)
                ):
                    report.error(
                        "signatures",
                        f"record {seq}: record signature fields are malformed", code="signatures.record_malformed",
                    )
                elif (pub := pubkeys.get(signer)) is None:
                    _deny(
                        "signatures",
                        f"record {seq}: signer {signer!r} not in manifest", code="signatures.signer_not_in_manifest",
                    )
                elif not _verify_sig(pub, sig, signed_hash.encode()):
                    report.error("signatures", f"record {seq}: record signature does not verify", code="signatures.record_invalid")
                elif pinned and signer not in authorized:
                    report.error(
                        "signatures",
                        f"record {seq}: signed by {signer}, which is neither pinned nor "
                        "introduced by an earlier valid key rotation", code="signatures.signer_not_trusted",
                    )
                else:
                    record_trusted = True
            elif pinned:
                report.error(
                    "signatures",
                    f"record {seq}: unsigned record (a pinned key requires every record "
                    "to be signed)", code="signatures.record_unsigned",
                )

            body = rec.get("body", {})
            kind = rec.get("kind")
            if kind in ("node", "edge"):
                graph_entries = [{"kind": kind, "body": body}]
            elif kind == "batch":
                if spec != CURRENT_SPEC:
                    report.error(
                        "chain",
                        f"record {seq}: batch records require {CURRENT_SPEC}", code="chain.batch_needs_v2",
                    )
                try:
                    graph_entries = _batch_entries(body)
                except ValueError as exc:
                    report.error("chain", f"record {seq}: invalid batch: {exc}", code="chain.batch_invalid")
                    graph_entries = []
            elif kind == "seal":
                graph_entries = []
            else:
                report.error("chain", f"record {seq}: unknown record kind {kind!r}", code="chain.kind_unknown")
                graph_entries = []

            for entry in graph_entries:
                child_body = entry["body"]
                body_error = _graph_body_error(entry["kind"], child_body)
                if body_error:
                    report.error(
                        "chain",
                        f"record {seq}: {body_error}", code="chain.body_invalid",
                    )
                    continue
                if entry["kind"] == "node":
                    if child_body["id"] in nodes:
                        report.error(
                            "chain",
                            f"record {seq}: duplicate node id {child_body['id']!r}", code="chain.duplicate_node",
                        )
                        continue
                    nodes[child_body["id"]] = child_body
                    node_body_hashes[child_body["id"]] = _hash_obj(child_body)
                    if (
                        pinned
                        and record_trusted
                        and child_body.get("kind") == "step"
                        and child_body.get("tool") == KEY_ROTATION_TOOL
                    ):
                        problem, new_key_id = _rotation_problem(
                            child_body, pubkeys, fingerprints
                        )
                        old_key_id = (child_body.get("params") or {}).get("old_key_id")
                        if problem is None and new_key_id and old_key_id in authorized:
                            authorized.add(new_key_id)
                elif entry["kind"] == "edge":
                    if child_body["id"] in edge_ids:
                        report.error(
                            "chain",
                            f"record {seq}: duplicate edge id {child_body['id']!r}", code="chain.duplicate_edge",
                        )
                        continue
                    edge_ids.add(child_body["id"])
                    edges.append(child_body)

            prev = rec.get("chain_hash")
            expected_seq += 1

    if manifest.get("chain_head") != prev:
        report.error("chain", "manifest chain_head does not match the log's final record", code="chain.head_mismatch")
    if require_head_timestamp and "chain_timestamp" not in manifest:
        report.error("timestamps", "required journal timestamp is missing", code="timestamps.journal_token_required")
    if "chain_timestamp" in manifest:
        proof = _bundle_member(root, "timestamps/chain-head.tsr")
        descriptor = manifest["chain_timestamp"]
        if (not isinstance(descriptor, dict) or descriptor.get("path") != "timestamps/chain-head.tsr"
                or not signature or not isinstance(prev, str) or prev != chain_hash
                or proof is None or not proof.is_file()):
            report.error("timestamps", "signed journal timestamp is missing or malformed", code="timestamps.journal_token_malformed")
        else:
            if hashlib.sha256(proof.read_bytes()).hexdigest() != descriptor.get("sha256"):
                report.error("timestamps", "journal timestamp differs from the signed manifest", code="timestamps.journal_token_mismatch")
            else:
                _verify_rfc3161_token(report, {"id": "journal head", "sha256": prev.removeprefix("sha256:")}, proof, tsa_roots)
    if manifest.get("record_count") != total_records:
        report.warn("chain", "manifest record_count does not match the log", code="chain.record_count_mismatch")

    if pinned:
        for key_id, fingerprint in sorted(fingerprints.items()):
            if key_id not in authorized:
                report.error(
                    "keys",
                    f"signer not in trusted set ({key_id}; fingerprint {fingerprint})", code="keys.not_trusted",
                )
        if manifest_signer is not None and manifest_signer not in authorized:
            report.error(
                "manifest",
                f"manifest signed by {manifest_signer}, which is neither pinned nor "
                "introduced by a valid key rotation", code="manifest.signer_not_trusted",
            )
    elif total_records and signed_records < total_records:
        report.warn(
            "signatures",
            f"{total_records - signed_records} of {total_records} records are unsigned", code="signatures.records_unsigned",
        )

    # 4. artifacts --------------------------------------------------------------------
    artifacts = [n for n in nodes.values() if n.get("kind") == "artifact"]
    for art in artifacts:
        sha, path_rel = art.get("sha256", ""), art.get("storage_path", "")
        if path_rel != _canonical_storage_path(sha):
            report.error(
                "artifacts",
                f"{art['id']}: storage path {path_rel!r} is not its content address "
                f"({_canonical_storage_path(sha)})", code="artifacts.path_not_content_address",
            )
            continue
        obj_path = _bundle_member(root, path_rel)
        if obj_path is None:
            report.error("artifacts", f"{art['id']}: storage path leaves the bundle", code="artifacts.path_escapes")
            continue
        if not obj_path.is_file():
            report.error("artifacts", f"{art['id']}: object missing ({path_rel})", code="artifacts.object_missing")
            continue
        actual = hashlib.sha256(obj_path.read_bytes()).hexdigest()
        if actual != sha:
            report.error("artifacts", f"{art['id']}: object bytes do not match sha256 (tampered)", code="artifacts.hash_mismatch")
        _verify_artifact_content_signature(
            report, art, pubkeys, pinned=pinned, authorized=authorized
        )

    if check_tree is not None and not report.errors:
        from veridict_verify.tree import compare_tree

        inventories = [a for a in artifacts if a.get("capture_method") == "folder-inventory/1"]
        if len(inventories) != 1:
            report.error("tree", "expected one sealed folder inventory", code="tree.inventory_count")
        else:
            obj = _bundle_member(root, inventories[0]["storage_path"])
            try:
                matched, issues = compare_tree(obj.read_bytes(), check_tree)
                for issue in issues:
                    report.error("tree", issue, code="tree.mismatch")
                report.info("tree", f"{matched} files matched the sealed inventory", code="tree.matched")
            except (OSError, ValueError) as exc:
                report.error("tree", str(exc), code="tree.unreadable")

    # 5. graph semantics ------------------------------------------------------------------
    supported: dict[str, list[str]] = {}
    superseded: dict[str, list[str]] = {}
    known_edge_types = {
        "supported-by",
        "transformed-by",
        "verified-by",
        "derived-from",
        "used",
        "contradicts",
        "supersedes",
    }
    for edge in edges:
        src, dst, etype = edge.get("src"), edge.get("dst"), edge.get("edge_type")
        if src not in nodes:
            report.error("semantics", f"edge {edge.get('id')}: source {src!r} does not exist", code="semantics.edge_source_missing")
            continue
        if dst not in nodes:
            report.error("semantics", f"edge {edge.get('id')}: target {dst!r} does not exist", code="semantics.edge_target_missing")
            continue
        if etype == "supported-by":
            supported.setdefault(src, []).append(dst)
            _verify_supported_by_citations(report, edge, nodes, root)
        elif etype == "verified-by":
            meta = edge.get("meta", {})
            claim_id = src
            declared = meta.get("claim_body_hash")
            actual_hash = node_body_hashes.get(claim_id)
            if declared != actual_hash:
                report.error("semantics",
                             f"verified-by {edge.get('id')}: signed hash does not match claim body", code="semantics.verification_hash_mismatch")
            pub = pubkeys.get(meta.get("signer", ""))
            if pub is None:
                _deny("semantics", f"verified-by {edge.get('id')}: unknown signer", code="semantics.verifier_unknown")
            elif not _verify_sig(pub, meta.get("signature", ""), (declared or "").encode()):
                report.error("semantics", f"verified-by {edge.get('id')}: signature does not verify", code="semantics.verification_invalid")
            elif pinned and meta.get("signer") not in authorized:
                report.error(
                    "semantics",
                    f"verified-by {edge.get('id')}: signer is neither pinned nor "
                    "introduced by a valid key rotation", code="semantics.verifier_not_trusted",
                )
        elif etype == "contradicts":
            src_kind = nodes[src].get("kind")
            dst_kind = nodes[dst].get("kind")
            if src == dst or src_kind not in {"artifact", "claim"} or dst_kind != "claim":
                report.error(
                    "semantics",
                    f"contradicts {edge.get('id')}: expected artifact/claim -> claim", code="semantics.contradicts_invalid",
                )
            reason = (edge.get("meta") or {}).get("reason")
            if not isinstance(reason, str) or not reason.strip():
                report.warn(
                    "semantics",
                    f"contradicts {edge.get('id')}: has no reason", code="semantics.contradicts_no_reason",
                )
        elif etype == "supersedes":
            if src == dst or nodes[src].get("kind") != "claim" or nodes[dst].get("kind") != "claim":
                report.error(
                    "semantics",
                    f"supersedes {edge.get('id')}: expected old claim -> different new claim", code="semantics.supersedes_invalid",
                )
            else:
                superseded.setdefault(src, []).append(dst)
        elif etype not in known_edge_types:
            report.error("semantics", f"edge {edge.get('id')}: unknown edge type {etype!r}", code="semantics.edge_type_unknown")

    for old_claim_id, successors in sorted(superseded.items()):
        if len(set(successors)) > 1:
            report.error(
                "semantics",
                f"superseded claim {old_claim_id}: multiple successors are ambiguous", code="semantics.supersedes_ambiguous",
            )

    cycle_reported = False

    def has_cycle(claim_id: str, visiting: frozenset[str], checked: set[str]) -> bool:
        if claim_id in visiting:
            return True
        if claim_id in checked:
            return False
        successors = sorted(set(superseded.get(claim_id, [])))
        if any(
            has_cycle(successor, visiting | {claim_id}, checked)
            for successor in successors
        ):
            return True
        checked.add(claim_id)
        return False

    checked_claims: set[str] = set()
    for claim_id in sorted(superseded):
        if has_cycle(claim_id, frozenset(), checked_claims):
            cycle_reported = True
            break
    if cycle_reported:
        report.error("semantics", "supersession cycle detected", code="semantics.supersession_cycle")

    def has_live_successor(claim_id: str, visiting: frozenset[str]) -> bool:
        if claim_id in visiting:
            return False
        successors = sorted(set(superseded.get(claim_id, [])))
        if len(successors) > 1:
            return False
        if not successors:
            return bool(supported.get(claim_id))
        return has_live_successor(successors[0], visiting | {claim_id})

    for old_claim_id, successors in sorted(superseded.items()):
        unique_successors = sorted(set(successors))
        if len(unique_successors) != 1 or not has_live_successor(
            unique_successors[0],
            frozenset({old_claim_id}),
        ):
            report.error(
                "semantics",
                f"superseded claim {old_claim_id}: no live evidence-backed successor", code="semantics.supersedes_no_successor",
            )

    verified_claims = {
        e["src"] for e in edges if e.get("edge_type") == "verified-by"
    }
    claims = [n for n in nodes.values() if n.get("kind") == "claim"]
    for claim in claims:
        cid = claim["id"]
        backing = supported.get(cid, [])
        if not backing:
            report.error("semantics", f"claim {cid}: NO supporting evidence edge - "
                                      f'"{claim.get("text", "")[:60]}"', code="semantics.claim_unsupported")
        if claim.get("label") == "inferred" and claim.get("confidence") is None:
            report.warn("semantics", f"claim {cid}: inferred without confidence", code="semantics.inferred_without_confidence")
        if claim.get("single_source"):
            report.warn("semantics", f"claim {cid}: single-source - "
                                     f'"{claim.get("text", "")[:60]}"', code="semantics.single_source")
        if cid not in verified_claims:
            report.info("semantics", f"claim {cid}: not human-verified", code="semantics.not_human_verified")

    corroboration = _verify_corroboration(
        report,
        nodes,
        edges,
        verified_claims,
    )
    _verify_source_brief_steps(report, nodes, edges, root)

    # 6. timestamps ---------------------------------------------------------------------------
    # Node status reflects the moment of sealing; anchors can land later via
    # `timestamp sync` (append-only nodes are never rewritten). So tokens are
    # discovered at their conventional paths regardless of node status.
    for art in artifacts:
        status = art.get("timestamp_status")
        token = _bundle_member(root, art.get("timestamp_ref") or f"timestamps/{art['id']}.tsr")
        if token is None:
            report.error("timestamps", f"{art['id']}: timestamp_ref leaves the bundle", code="timestamps.ref_escapes")
            continue
        if token.is_file():
            if status == "pending":
                report.info("timestamps",
                            f"{art['id']}: RFC-3161 token present (anchored after sealing)", code="timestamps.token_after_seal")
            _verify_rfc3161_token(report, art, token, tsa_roots)
        elif status == "anchored":
            report.error("timestamps", f"{art['id']}: anchored but token missing", code="timestamps.token_missing")
        else:
            report.warn("timestamps", f"{art['id']}: RFC-3161 timestamp pending (not yet anchored)", code="timestamps.pending")
        _check_ots_proof(report, art, root)

    # stats -----------------------------------------------------------------------------------
    steps = [n for n in nodes.values() if n.get("kind") == "step"]
    ai_steps = [s for s in steps if s.get("model")]
    if forbid_ai_steps:
        # Cases where AI is not allowed (for example an exam): any step that names a
        # model is an error, whatever it produced.
        for step in ai_steps:
            report.error(
                "policy",
                f"step {step.get('id', '?')}: AI step (model {step.get('model')!r}, tool "
                f"{step.get('tool')!r}) in a case where AI is forbidden",
                code="policy.ai_step_forbidden",
            )
        if not ai_steps:
            report.info("policy", "no AI steps in this case (--forbid-ai-steps)",
                        code="policy.no_ai_steps")
    report.stats = {
        "records": total_records,
        "signed_records": signed_records,
        "artifacts": len(artifacts),
        "claims": len(claims),
        "verified_claims": len(verified_claims & {c["id"] for c in claims}),
        "steps": len(steps),
        "ai_steps": len(ai_steps),
        "agents": len([n for n in nodes.values() if n.get("kind") == "agent"]),
        "corroboration": corroboration,
        "signer_fingerprints": fingerprints,
    }
    _verify_key_rotation_steps(report, steps, pubkeys, fingerprints, pinned=pinned)
    return report


def _normalize_trusted_token(token: str) -> str:
    """Accept a fingerprint, key id, or path to a raw/PEM public key / fingerprint file."""
    path = Path(token)
    if path.exists() and path.is_file():
        text = path.read_text(encoding="utf-8").strip()
        # Fingerprint file: single hex line.
        if len(text) in (16, 64) and all(c in "0123456789abcdef" for c in text.lower()):
            return text.lower()
        try:
            if "BEGIN" in text:
                from cryptography.hazmat.primitives import serialization

                key = serialization.load_pem_public_key(text.encode("utf-8"))
                raw = key.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            else:
                raw = base64.b64decode(text, validate=True)
            return hashlib.sha256(raw).hexdigest()
        except Exception:
            return text.lower()
    return token.lower()


KEY_ROTATION_TOOL = "human/key-rotation"


def _rotation_problem(
    step: dict[str, Any],
    pubkeys: dict[str, str],
    fingerprints: dict[str, str],
) -> tuple[str | None, str | None]:
    """Check one key-rotation statement. Returns (problem, new_key_id)."""
    params = step.get("params") or {}
    if not isinstance(params, dict):
        return "params malformed", None
    required = (
        "schema",
        "old_key_id",
        "old_fingerprint",
        "new_key_id",
        "new_fingerprint",
        "new_public_b64",
        "statement_hash",
        "statement_signature",
    )
    if any(not isinstance(params.get(field), str) for field in required):
        return "missing required statement fields", None
    if params.get("schema") != "veridict-key-rotation/1":
        return "unknown schema", None
    statement = {
        "schema": params["schema"],
        "old_key_id": params["old_key_id"],
        "old_fingerprint": params["old_fingerprint"],
        "new_key_id": params["new_key_id"],
        "new_fingerprint": params["new_fingerprint"],
        "new_public_b64": params["new_public_b64"],
    }
    expected_hash = _hash_obj(statement)
    if params["statement_hash"] != expected_hash:
        return "statement_hash does not match statement", None
    old_pub = pubkeys.get(params["old_key_id"])
    if old_pub is None:
        return f"old key {params['old_key_id']} not in manifest", None
    if not _verify_sig(old_pub, params["statement_signature"], expected_hash.encode()):
        return "rotation statement signature does not verify", None
    # Cross-check declared fingerprints against key material when present.
    if fingerprints.get(params["old_key_id"]) not in (None, params["old_fingerprint"]):
        return "old_fingerprint does not match manifest key", None
    try:
        raw_new = base64.b64decode(params["new_public_b64"], validate=True)
        actual_fp = hashlib.sha256(raw_new).hexdigest()
    except Exception:
        return "new_public_b64 invalid", None
    if actual_fp != params["new_fingerprint"] or actual_fp[:16] != params["new_key_id"]:
        return "new key fingerprint/id mismatch", None
    if pubkeys.get(params["new_key_id"]) not in (None, params["new_public_b64"]):
        return "new key differs from the manifest key with the same id", None
    return None, params["new_key_id"]


def _verify_key_rotation_steps(
    report: Report,
    steps: list[dict[str, Any]],
    pubkeys: dict[str, str],
    fingerprints: dict[str, str],
    *,
    pinned: bool = False,
) -> None:
    """Validate human/key-rotation Steps; note keys introduced by valid rotation.

    A broken rotation statement is an error when a key is pinned: the recipient
    relies on the chain of statements to accept a key they did not pin.
    """
    for step in steps:
        if step.get("tool") != KEY_ROTATION_TOOL:
            continue
        step_id = step.get("id", "?")
        problem, new_key_id = _rotation_problem(step, pubkeys, fingerprints)
        if problem is not None:
            message = f"key-rotation {step_id}: {problem}"
            if pinned:
                report.error("keys", message, code="keys.rotation_invalid")
            else:
                report.warn("keys", message, code="keys.rotation_invalid")
            continue
        old_key_id = step["params"]["old_key_id"]
        report.info(
            "keys",
            f"key-rotation {step_id}: {old_key_id} -> {new_key_id} (statement verifies)", code="keys.rotation_ok",
        )


def _verify_artifact_content_signature(
    report: Report,
    art: dict[str, Any],
    pubkeys: dict[str, str],
    *,
    pinned: bool = False,
    authorized: set[str] | None = None,
) -> None:
    """Optional standalone seal: Ed25519 over UTF-8 `sha256:<hex>`."""
    art_id = art.get("id", "?")
    sig = art.get("content_signature")
    signer = art.get("content_signer")
    sha = art.get("sha256")
    if sig is None and signer is None:
        report.warn(
            "artifacts",
            f"{art_id}: artifact has no standalone content signature", code="artifacts.content_signature_missing",
        )
        return
    if not isinstance(sig, str) or not isinstance(signer, str) or not isinstance(sha, str):
        report.error(
            "artifacts",
            f"{art_id}: content_signature/content_signer malformed", code="artifacts.content_signature_malformed",
        )
        return
    pub = pubkeys.get(signer)
    if pub is None:
        message = f"{art_id}: content signature unknown signer {signer}"
        if pinned:
            report.error("artifacts", message, code="artifacts.content_signer_unknown")
        else:
            report.warn("artifacts", message, code="artifacts.content_signer_unknown")
        return
    message = f"sha256:{sha}".encode()
    if not _verify_sig(pub, sig, message):
        report.error(
            "artifacts",
            f"{art_id}: content signature does not verify", code="artifacts.content_signature_invalid",
        )
    elif pinned and signer not in (authorized or set()):
        report.error(
            "artifacts",
            f"{art_id}: content signer {signer} is neither pinned nor introduced "
            "by a valid key rotation", code="artifacts.content_signer_not_trusted",
        )


OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


def _check_ots_proof(report: Report, art: dict[str, Any], root: Path) -> None:
    """Lightweight OpenTimestamps proof check (no Bitcoin node required).

    Verifies: the proof file exists where the node says, carries the OTS magic
    header, and embeds the artifact's SHA-256 digest as its commitment. Full
    Bitcoin-anchoring verification requires the OTS client (`ots verify`),
    which is reported as guidance, not silently assumed.
    """
    ots_status = art.get("ots_status")
    ref = art.get("timestamp_ots_ref")
    proof = _bundle_member(root, ref or f"timestamps/{art['id']}.ots")
    if proof is None:
        report.error("timestamps", f"{art['id']}: timestamp_ots_ref leaves the bundle", code="timestamps.ots_ref_escapes")
        return
    if not proof.is_file():
        if ots_status in ("stamped", "upgraded"):
            report.error("timestamps",
                         f"{art['id']}: OTS status {ots_status!r} but proof file missing", code="timestamps.ots_missing")
        elif ots_status == "pending":
            report.info("timestamps", f"{art['id']}: OTS proof pending", code="timestamps.ots_pending")
        return
    data = proof.read_bytes()
    if not data.startswith(OTS_MAGIC):
        report.error("timestamps", f"{art['id']}: OTS proof has invalid magic header", code="timestamps.ots_invalid")
        return
    digest = bytes.fromhex(art.get("sha256", ""))
    if digest not in data:
        report.error("timestamps", f"{art['id']}: OTS proof does not commit to the artifact hash", code="timestamps.ots_mismatch")
        return
    report.info(
        "timestamps",
        f"{art['id']}: OTS proof commits to artifact hash "
        f"({'Bitcoin-upgraded' if ots_status == 'upgraded' else 'calendar-stamped'}; "
        "run `ots verify` for full chain validation)", code="timestamps.ots_ok",
    )


# -- RFC 3161 ----------------------------------------------------------------------------

_IMPRINT_HASHES = {
    "2.16.840.1.101.3.4.2.1": hashlib.sha256,
    "2.16.840.1.101.3.4.2.2": hashlib.sha384,
    "2.16.840.1.101.3.4.2.3": hashlib.sha512,
}
_TSA_CHAIN_MAX_DEPTH = 6


def load_tsa_roots(source: str | Path) -> list[Any]:
    """Load the TSA roots a recipient pins: one PEM/DER file or a folder of them."""
    from cryptography import x509

    path = Path(source)
    if path.is_dir():
        files = sorted(
            p for p in path.iterdir() if p.suffix.lower() in {".pem", ".crt", ".cer", ".der"}
        )
    elif path.is_file():
        files = [path]
    else:
        return []
    roots: list[Any] = []
    for file in files:
        data = file.read_bytes()
        try:
            if b"-----BEGIN CERTIFICATE-----" in data:
                roots.extend(x509.load_pem_x509_certificates(data))
            else:
                roots.append(x509.load_der_x509_certificate(data))
        except ValueError as exc:
            raise ValueError(f"{file.name} is not a PEM or DER certificate ({exc})") from None
    return roots


def _der_first_children(data: bytes, depth: int) -> bytes | None:
    """Descend `depth` levels into the first child of each DER SEQUENCE; return that TLV."""
    pos_data = data
    for _ in range(depth):
        if len(pos_data) < 2:
            return None
        first = pos_data[1]
        header = 2 if first < 0x80 else 2 + (first & 0x7F)
        pos_data = pos_data[header:]
    return pos_data


def _tsa_response_status(data: bytes) -> int | None:
    """PKIStatus of a TimeStampResp read straight from DER (works without a token)."""
    status = _der_first_children(data, 2)  # TimeStampResp -> PKIStatusInfo -> INTEGER
    if not status or status[0] != 0x02 or len(status) < 3 or status[1] > 4:
        return None
    return int.from_bytes(status[2 : 2 + status[1]], "big")


def _short_tsa_error(exc: Exception) -> str:
    """One readable line instead of an OpenSSL error stack."""
    text = str(exc)
    marker = "Verify error: "
    if marker in text:
        reason = text.split(marker, 1)[1].split('"', 1)[0]
        return f"signature or certificate chain does not verify ({reason})"
    return text.splitlines()[0][:200] if text else type(exc).__name__


def _cert_name(cert: Any) -> str:
    from cryptography.x509.oid import NameOID

    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


def _tsa_chain_problem(
    leaf: Any, embedded: list[Any], roots: list[Any], at: Any
) -> tuple[str | None, Any]:
    """Walk from the signer certificate to a *pinned* root. Returns (problem, root).

    Certificates carried inside the token may serve only as intermediates: a root
    that a token brings along is never trusted (rfc3161-client 1.0.7 adds them to
    its trusted set, so its own chain check cannot be relied on for this).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    def der(cert: Any) -> bytes:
        return cert.public_bytes(Encoding.DER)

    def valid_at(cert: Any) -> bool:
        return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc

    def is_ca(cert: Any) -> bool:
        try:
            return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        except x509.ExtensionNotFound:
            return False

    def issued_by(child: Any, parent: Any) -> bool:
        try:
            child.verify_directly_issued_by(parent)
            return True
        except Exception:
            return False

    pinned = {der(r) for r in roots}
    current, visited = leaf, set()
    for _ in range(_TSA_CHAIN_MAX_DEPTH):
        if not valid_at(current):
            return f"certificate {_cert_name(current)!r} was not valid at genTime", None
        if der(current) in pinned:
            return None, current
        for root in roots:
            if is_ca(root) and issued_by(current, root):
                if not valid_at(root):
                    return f"pinned root {_cert_name(root)!r} was not valid at genTime", None
                return None, root
        visited.add(der(current))
        parents = [
            c for c in embedded
            if der(c) not in visited and is_ca(c) and issued_by(current, c)
        ]
        if not parents:
            return "the signer certificate does not chain to a pinned TSA root", None
        current = parents[0]
    return "the certificate chain is too long", None


def _verify_rfc3161_token(
    report: Report,
    art: dict[str, Any],
    token_path: Path,
    tsa_roots: list[Any] | None = None,
) -> None:
    """Check an RFC 3161 token: imprint always; signature and chain against pinned roots.

    Outcomes: signature verified to a pinned root -> info; no roots given -> warning
    (only the imprint was matched); anything else -> error. Revocation is not checked.
    """
    art_id = art["id"]
    data = token_path.read_bytes()
    status = _tsa_response_status(data)
    if status is not None and status not in (0, 1):
        report.error(
            "timestamps",
            f"{art_id}: the TSA refused the request (PKIStatus {status}); this is not a timestamp", code="timestamps.tsa_refused",
        )
        return
    try:
        from rfc3161_client import (
            PKIStatus,
            VerificationError,
            VerifierBuilder,
            decode_timestamp_response,
        )
    except ImportError:
        finding = report.error if tsa_roots else report.warn
        finding(
            "timestamps",
            f"{art_id}: timestamp verification unavailable; "
            "install support with pip install 'veridict-verify[timestamps]'", code="timestamps.support_missing",
        )
        return
    try:
        tsr = decode_timestamp_response(data)
        imprint = tsr.tst_info.message_imprint
        algorithm = imprint.hash_algorithm.dotted_string
        gen_time = tsr.tst_info.gen_time
    except Exception as exc:
        report.error("timestamps", f"{art_id}: token unreadable: {exc}", code="timestamps.token_unreadable")
        return
    if PKIStatus(tsr.status) != PKIStatus.GRANTED:
        report.error("timestamps", f"{art_id}: the TSA did not grant this token", code="timestamps.token_not_granted")
        return

    # The engine sends the artifact's raw SHA-256 digest as the TSA message, so the
    # imprint is H(digest) under the token's declared hash; SHA-256 tokens may also
    # carry the digest itself (the file was hashed directly).
    digest = bytes.fromhex(art.get("sha256", ""))
    hash_fn = _IMPRINT_HASHES.get(algorithm)
    if hash_fn is None:
        report.error("timestamps", f"{art_id}: token uses an unsupported hash {algorithm}", code="timestamps.hash_unsupported")
        return
    accepted = {hash_fn(digest).digest()}
    if hash_fn is hashlib.sha256:
        accepted.add(digest)
    if imprint.message not in accepted:
        report.error("timestamps", f"{art_id}: token does not commit to this artifact's hash", code="timestamps.token_mismatch")
        return

    if not tsa_roots:
        report.warn(
            "timestamps",
            f"{art_id}: RFC-3161 token matches the artifact hash, but the TSA signature "
            f"and certificate chain were NOT checked (pass --tsa-roots); genTime "
            f"{gen_time.isoformat()} is only the TSA's claim", code="timestamps.tsa_not_checked",
        )
        return

    try:
        VerifierBuilder(roots=list(tsa_roots)).build().verify(tsr, imprint.message)
    except (VerificationError, ValueError) as exc:
        report.error(
            "timestamps", f"{art_id}: token is not signed by a pinned TSA: {_short_tsa_error(exc)}", code="timestamps.tsa_untrusted"
        )
        return

    from cryptography import x509

    embedded = [x509.load_der_x509_certificate(c) for c in tsr.signed_data.certificates]
    signer_infos = list(tsr.signed_data.signer_infos)
    leaves = [
        c for c in embedded
        if len(signer_infos) == 1
        and c.issuer == signer_infos[0].issuer
        and c.serial_number == signer_infos[0].serial_number
    ]
    if len(leaves) != 1:
        report.error(
            "timestamps",
            f"{art_id}: token does not carry exactly one signer certificate "
            f"({len(leaves)} found); its chain cannot be checked", code="timestamps.signer_cert_ambiguous",
        )
        return
    problem, root = _tsa_chain_problem(leaves[0], embedded, list(tsa_roots), gen_time)
    if problem is not None:
        report.error("timestamps", f"{art_id}: token is not signed by a pinned TSA: {problem}", code="timestamps.tsa_untrusted")
        return
    report.info(
        "timestamps",
        f"{art_id}: RFC-3161 signature verified to pinned TSA root {_cert_name(root)!r} "
        f"(signer {_cert_name(leaves[0])!r}, genTime {gen_time.isoformat()}; "
        "revocation not checked offline)", code="timestamps.tsa_verified",
    )
