"""veridict-verify: check a bundle you did not produce, on a machine you control.

Exit codes: 0 = VALID, 1 = INVALID, 2 = VALID WITH WARNINGS.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from veridict_verify import __version__
from veridict_verify.verifier import verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="veridict-verify",
        description="Offline verifier for VERIDICT case bundles.",
    )
    parser.add_argument("bundle", help="path to a .veridict.zip bundle or unpacked bundle directory")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable JSON report")
    parser.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        metavar="FINGERPRINT_OR_PATH",
        help=(
            "pin an investigator key (full SHA-256 fingerprint, 16-char key id, "
            "or path to a fingerprint/pubkey file). Repeatable. When set, any "
            "manifest signer not in the trusted set is an error."
        ),
    )
    parser.add_argument("--version", action="version", version=f"veridict-verify {__version__}")
    args = parser.parse_args(argv)

    bundle = Path(args.bundle)
    if not bundle.exists():
        print(f"error: no such file or directory: {bundle}", file=sys.stderr)
        return 1

    trusted = set(args.trusted_key) if args.trusted_key else None
    report = verify_bundle(bundle, trusted_keys=trusted)

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
        print(f"[{tag}] {f.check}: {f.message}")
    print("-" * 72)
    print(f"VERDICT: {report.verdict}")


if __name__ == "__main__":
    raise SystemExit(main())
