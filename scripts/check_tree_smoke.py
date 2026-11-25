"""Run the installed veridict-verify command with --check-tree and require clean reports.

    python scripts/check_tree_smoke.py [--cli PATH]

PATH is the veridict-verify executable to test (default: the one on PATH). Uses only
the standard library and the committed fixtures, so the release workflow can point it
at the command a freshly installed wheel provides. Every run must finish without a
traceback; --json output must parse. Checked:

1. the conformance bundle valid.veridict.zip is not a folder seal: an empty folder
   gives INVALID with tree.inventory_count (exit 1), not a crash;
2. the folder seal (folder-inventory/1) and the level-two import (folder-inventory/2)
   in tests/fixtures/tree/ match their folder: tree.matched, exit 0 or 2;
3. the same bundles against an edited copy of the folder: tree.mismatch, exit 1.

0.3.0 fails step 1 with ModuleNotFoundError: veridict_verify/tree.py was not packaged.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALID = ROOT / "tests" / "conformance" / "valid.veridict.zip"
TREE = ROOT / "tests" / "fixtures" / "tree"


def run(cli: str, *args: str) -> tuple[int, str, str]:
    result = subprocess.run([cli, *args], capture_output=True, text=True, encoding="utf-8",
                            check=False)
    return result.returncode, result.stdout, result.stderr


def check(name: str, cli: str, args: list[str], exits: set[int], errors: list[str],
          info: str | None = None) -> bool:
    code, out, err = run(cli, *args, "--json")
    problems = []
    if "Traceback" in err or "Traceback" in out:
        problems.append("traceback:\n" + err.strip())
    if code not in exits:
        problems.append(f"exit {code}, expected {sorted(exits)}")
    try:
        findings = json.loads(out)["findings"]
    except (ValueError, KeyError, TypeError):
        problems.append(f"--json output is not a report: {out[:200]!r}")
        findings = []
    got = sorted(f["code"] for f in findings if f["level"] == "error")
    if findings and got != sorted(errors):
        problems.append(f"errors {got}, expected {sorted(errors)}")
    if findings and info and info not in {f["code"] for f in findings}:
        problems.append(f"no {info} finding")
    code, out, err = run(cli, *args)  # the human-readable report as well
    if "Traceback" in err or "VERDICT:" not in out:
        problems.append("human-readable run did not end in a verdict:\n" + err.strip())
    print(f"{'ok  ' if not problems else 'FAIL'} {name}")
    for problem in problems:
        print("     " + problem.replace("\n", "\n     "))
    return not problems


def main(argv: list[str]) -> int:
    cli = argv[argv.index("--cli") + 1] if "--cli" in argv else shutil.which("veridict-verify")
    if not cli:
        print("veridict-verify not found; pass --cli PATH")
        return 1
    version = run(cli, "--version")[1].strip()
    print(f"{version} ({Path(cli).name})")
    key = (TREE / "analyst.fingerprint").read_text("utf-8").strip()
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "empty"
        empty.mkdir()
        results.append(check("valid.veridict.zip, empty folder: tree.inventory_count", cli,
                             [str(VALID), "--check-tree", str(empty)], {1},
                             ["tree.inventory_count"]))
        for bundle in ("seal", "import"):
            folder = shutil.copytree(TREE / "case", Path(tmp) / bundle)
            args = [str(TREE / f"{bundle}.veridict.zip"), "--trusted-key", key,
                    "--check-tree", str(folder)]
            results.append(check(f"{bundle}.veridict.zip, sealed folder: tree.matched", cli,
                                 args, {0, 2}, [], info="tree.matched"))
            (folder / "case-journal.txt").write_bytes(b"edited after the seal\n")
            results.append(check(f"{bundle}.veridict.zip, edited folder: tree.mismatch", cli,
                                 args, {1}, ["tree.mismatch"]))
    print(f"{sum(results)} ok, {len(results) - sum(results)} failed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
