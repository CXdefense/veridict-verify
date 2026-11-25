"""veridict-verify: check a bundle you did not produce, on a machine you control.

Exit codes: 0 = VALID, 1 = INVALID, 2 = VALID WITH WARNINGS.
Warnings named with --allow-warning are still printed but no longer count, so a
script can require exit code 0 while accepting, say, pending timestamps.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from veridict_verify import __version__
from veridict_verify.codes import FINDING_CODES, can_be_warning
from veridict_verify.verifier import MAX_ARCHIVE_BYTES, MAX_ARCHIVE_MEMBERS, verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="veridict-verify",
        description="Offline verifier for VERIDICT case bundles.",
    )
    parser.add_argument(
        "bundle", nargs="?", help="path to a .veridict.zip bundle or unpacked bundle directory"
    )
    parser.add_argument("--json", action="store_true", help="emit a machine-readable JSON report")
    parser.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        metavar="FINGERPRINT_OR_PATH",
        help=(
            "pin an investigator key (full SHA-256 fingerprint, 16-char key id, "
            "or path to a fingerprint/pubkey file). Repeatable. When set, the "
            "manifest, every record, every human verification and every content "
            "seal must be signed by a pinned key or by a key that a pinned key "
            "handed over to in a valid rotation statement; anything else is an error. "
            "Without a pinned key the signer's identity is not checked."
        ),
    )
    parser.add_argument(
        "--tsa-roots",
        metavar="PATH",
        help=(
            "time-stamp authority root certificate(s) you trust: a PEM/DER file or a "
            "folder of them. RFC-3161 tokens are then checked for a valid TSA signature "
            "and a certificate chain to one of these roots. Roots are never taken from "
            "the bundle. Without this option a token is only matched to its artifact."
        ),
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=MAX_ARCHIVE_MEMBERS,
        metavar="N",
        help=f"refuse archives with more than N members (default {MAX_ARCHIVE_MEMBERS})",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=MAX_ARCHIVE_BYTES,
        metavar="N",
        help=f"refuse archives that unpack to more than N bytes (default {MAX_ARCHIVE_BYTES})",
    )
    parser.add_argument(
        "--allow-warning",
        action="append",
        default=[],
        metavar="CODE",
        help=(
            "accept one kind of warning (e.g. timestamps.pending): it is still printed but "
            "no longer makes the verdict VALID WITH WARNINGS. Repeatable. Errors can never "
            "be allowed. See --list-codes."
        ),
    )
    parser.add_argument(
        "--forbid-ai-steps",
        action="store_true",
        help="treat every step that names an AI model as an error (cases where AI is not allowed)",
    )
    parser.add_argument(
        "--list-codes", action="store_true", help="print every finding code and its levels, then exit"
    )
    parser.add_argument("--version", action="version", version=f"veridict-verify {__version__}")
    parser.add_argument("--check-tree", type=Path, help="Compare a folder with its sealed inventory")
    parser.add_argument("--require-head-timestamp", action="store_true", help="Require a trusted journal timestamp")
    args = parser.parse_args(argv)

    if args.list_codes:
        for code, levels in sorted(FINDING_CODES.items()):
            print(f"{code:44} {levels}")
        return 0
    if not args.bundle:
        parser.print_usage(sys.stderr)
        print("error: a bundle path is required", file=sys.stderr)
        return 1
    not_warnings = [c for c in args.allow_warning if not can_be_warning(c)]
    if not_warnings:
        print(
            "error: --allow-warning takes warning codes only (see --list-codes): "
            + ", ".join(not_warnings),
            file=sys.stderr,
        )
        return 1

    bundle = Path(args.bundle)
    if not bundle.exists():
        print(f"error: no such file or directory: {bundle}", file=sys.stderr)
        return 1

    trusted = set(args.trusted_key) if args.trusted_key else None
    if args.tsa_roots and not Path(args.tsa_roots).exists():
        print(f"error: --tsa-roots not found: {args.tsa_roots}", file=sys.stderr)
        return 1
    report = verify_bundle(
        bundle,
        trusted_keys=trusted,
        tsa_roots=args.tsa_roots,
        check_tree=args.check_tree,
        require_head_timestamp=args.require_head_timestamp,
        allow_warnings=set(args.allow_warning),
        forbid_ai_steps=args.forbid_ai_steps,
        max_members=args.max_files,
        max_total_bytes=args.max_bytes,
    )

    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        _print_human(report)

    if report.errors:
        return 1
    if report.warnings:
        return 2
    return 0


def _print_human(report) -> None:
    print(f"VERIDICT bundle verification - {report.bundle}")
    print("=" * 72)
    s = report.stats
    if s:
        print(
            f"records: {s.get('records', 0)}  (signed: {s.get('signed_records', 0)})   "
            f"artifacts: {s.get('artifacts', 0)}   claims: {s.get('claims', 0)} "
            f"(human-verified: {s.get('verified_claims', 0)})   "
            f"steps: {s.get('steps', 0)} (AI: {s.get('ai_steps', 0)})"
        )
        fps = s.get("signer_fingerprints") or {}
        if fps:
            print("signers:")
            for key_id, fingerprint in sorted(fps.items()):
                print(f"  {key_id}: {fingerprint}")
        print("-" * 72)
    for f in report.findings:
        tag = {"error": "FAIL", "warning": "WARN", "info": "  ok"}[f.level]
        if f.allowed:
            tag = "ALLOW"
        code = f"  [{f.code}]" if f.code else ""
        print(f"[{tag}] {f.check}: {f.message}{code}")
    print("-" * 72)
    if report.allowed:
        print(f"allowed warnings: {len(report.allowed)} "
              f"({', '.join(sorted({f.code for f in report.allowed}))})")
    print(f"VERDICT: {report.verdict}")


if __name__ == "__main__":
    raise SystemExit(main())
