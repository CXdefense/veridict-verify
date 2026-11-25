"""Run every case in tests/conformance/cases.json against the installed verifier.

    python scripts/check_conformance.py [corpus-dir] [--skip-timestamps]

Exits 1 if any case gives another verdict or other error/warning codes than
cases.json expects. Cases that need the [timestamps] extra fail when it is missing,
unless --skip-timestamps is given. Used by the release workflow to check the built
wheel before it is published.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import veridict_verify
from veridict_verify.verifier import verify_bundle


def main(argv: list[str]) -> int:
    skip_timestamps = "--skip-timestamps" in argv
    args = [a for a in argv if not a.startswith("--")]
    corpus = Path(args[0]) if args else Path(__file__).resolve().parents[1] / "tests" / "conformance"
    cases = json.loads((corpus / "cases.json").read_text("utf-8"))["cases"]
    has_timestamps = importlib.util.find_spec("rfc3161_client") is not None
    print(f"veridict-verify {veridict_verify.__version__} from {Path(veridict_verify.__file__).parent}")
    failed = skipped = 0
    for case in cases:
        if "timestamps" in case["requires"] and not has_timestamps:
            if skip_timestamps:
                skipped += 1
                print(f"skip {case['name']} (needs [timestamps])")
                continue
            failed += 1
            print(f"FAIL {case['name']}: needs veridict-verify[timestamps]")
            continue
        options, kwargs = case["options"], {}
        if "trusted_keys" in options:
            kwargs["trusted_keys"] = {
                (corpus / "keys" / f"{name}.fingerprint").read_text("utf-8").strip()
                for name in options["trusted_keys"]
            }
        if "tsa_roots" in options:
            kwargs["tsa_roots"] = corpus / options["tsa_roots"]
        if "allow_warnings" in options:
            kwargs["allow_warnings"] = set(options["allow_warnings"])
        if options.get("forbid_ai_steps"):
            kwargs["forbid_ai_steps"] = True
        report = verify_bundle(corpus / case["bundle"], **kwargs)
        got = (report.verdict, sorted({f.code for f in report.errors}),
               sorted({f.code for f in report.warnings}))
        want = (case["verdict"], case["errors"], case["warnings"])
        if got == want:
            print(f"ok   {case['name']}")
        else:
            failed += 1
            print(f"FAIL {case['name']}: expected {want}, got {got}")
    print(f"{len(cases) - failed - skipped} ok, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
