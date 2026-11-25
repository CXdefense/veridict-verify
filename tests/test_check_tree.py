"""--check-tree: compare a folder with the inventory sealed in a bundle (engine-free).

0.3.0 shipped without veridict_verify/tree.py, so every --check-tree run on a bundle
without earlier errors crashed with ModuleNotFoundError and exit 1, the same exit as
INVALID. These tests run the option on committed fixtures only:

- tests/conformance/valid.veridict.zip is not a folder seal, so --check-tree must
  give a clean tree.inventory_count finding, never a traceback;
- tests/fixtures/tree/ holds a folder seal (folder-inventory/1), a level-two import
  (folder-inventory/2 only) and the folder both were made from.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from veridict_verify.cli import main as verify_cli
from veridict_verify.verifier import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
VALID = ROOT / "tests" / "conformance" / "valid.veridict.zip"
TREE = ROOT / "tests" / "fixtures" / "tree"
FINGERPRINT = (TREE / "analyst.fingerprint").read_text("utf-8").strip()
BUNDLES = {
    "seal": (TREE / "seal.veridict.zip", "folder-inventory/1"),
    "import": (TREE / "import.veridict.zip", "folder-inventory/2"),
}


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the CLI in a fresh interpreter, as a user would, and capture everything."""
    return subprocess.run(
        [sys.executable, "-c", "import sys; from veridict_verify.cli import main; "
         "sys.exit(main(sys.argv[1:]))", *args],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    """A private copy of the sealed folder, so a test can change it."""
    return shutil.copytree(TREE / "case", tmp_path / "case")


def _codes(report, level: str) -> list[str]:
    return sorted(f.code for f in report.findings if f.level == level)


@pytest.mark.parametrize("contents", ["empty", "unrelated"])
def test_bundle_without_inventory_gives_a_finding_not_a_crash(tmp_path, contents):
    target = tmp_path / "folder"
    target.mkdir()
    if contents == "unrelated":
        (target / "note.txt").write_bytes(b"not part of any seal\n")
    result = _run_cli(str(VALID), "--json", "--check-tree", str(target))
    assert "Traceback" not in result.stderr, result.stderr
    assert result.returncode == 1, (result.returncode, result.stderr)
    report = json.loads(result.stdout)
    assert report["verdict"] == "INVALID"
    assert [f["code"] for f in report["findings"] if f["level"] == "error"] == [
        "tree.inventory_count"]


def test_human_output_without_inventory_names_the_check(tmp_path):
    result = _run_cli(str(VALID), "--check-tree", str(tmp_path))
    assert "Traceback" not in result.stderr, result.stderr
    assert result.returncode == 1
    assert "[tree.inventory_count]" in result.stdout
    assert "VERDICT: INVALID" in result.stdout


@pytest.mark.parametrize("kind", sorted(BUNDLES))
def test_fixture_carries_the_inventory_it_is_named_for(kind):
    bundle, method = BUNDLES[kind]
    with zipfile.ZipFile(bundle) as zf:
        text = b"".join(zf.read(n) for n in zf.namelist() if n.endswith((".json", ".jsonl")))
    methods = {m for m in ("folder-inventory/1", "folder-inventory/2") if m.encode() in text}
    assert methods == {method}


@pytest.mark.parametrize("kind", sorted(BUNDLES))
def test_sealed_folder_matches(kind, folder):
    report = verify_bundle(BUNDLES[kind][0], trusted_keys={FINGERPRINT}, check_tree=folder)
    assert _codes(report, "error") == []
    assert report.verdict in ("VALID", "VALID WITH WARNINGS")
    matched = [f for f in report.findings if f.code == "tree.matched"]
    assert [f.message for f in matched] == ["3 files matched the sealed inventory"]


@pytest.mark.parametrize("kind", sorted(BUNDLES))
def test_changed_added_and_missing_files_are_errors(kind, folder):
    (folder / "case-journal.txt").write_bytes(b"edited after the seal\n")
    (folder / "evidence" / "added.txt").write_bytes(b"added after the seal\n")
    (folder / "notes" / "sources.txt").unlink()
    report = verify_bundle(BUNDLES[kind][0], trusted_keys={FINGERPRINT}, check_tree=folder)
    assert report.verdict == "INVALID"
    assert _codes(report, "error") == ["tree.mismatch"] * 3
    assert sorted(f.message for f in report.errors) == [
        "added: evidence/added.txt",
        "changed: case-journal.txt",
        "missing: notes/sources.txt",
    ]


@pytest.mark.parametrize("kind", sorted(BUNDLES))
def test_cli_exit_codes(kind, folder, capsys):
    bundle = str(BUNDLES[kind][0])
    # Offline seals carry pending timestamps: VALID WITH WARNINGS.
    assert verify_cli([bundle, "--trusted-key", FINGERPRINT, "--check-tree", str(folder)]) == 2
    assert "[tree.matched]" in capsys.readouterr().out
    (folder / "case-journal.txt").write_bytes(b"edited after the seal\n")
    assert verify_cli([bundle, "--trusted-key", FINGERPRINT, "--check-tree", str(folder)]) == 1
    assert "changed: case-journal.txt  [tree.mismatch]" in capsys.readouterr().out
