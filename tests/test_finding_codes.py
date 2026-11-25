"""Finding codes, accepted warnings and the AI policy — engine-independent.

Uses only the committed conformance corpus, so it runs with nothing but this
package installed.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from veridict_verify import verifier as verifier_module
from veridict_verify.cli import main as verify_cli
from veridict_verify.codes import FINDING_CODES, can_be_warning
from veridict_verify.verifier import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "conformance"
VALID = CORPUS / "valid.veridict.zip"
FINGERPRINT = (CORPUS / "keys" / "analyst.fingerprint").read_text("utf-8").strip()


def _codes_in_source() -> dict[str, set[str]]:
    tree = ast.parse(Path(verifier_module.__file__).read_text(encoding="utf-8"))
    levels: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and len(node.elts) == 2:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and str(first.value).startswith("archive."):
                levels.setdefault(first.value, set()).add("error")
        if not isinstance(node, ast.Call):
            continue
        code = next((k.value.value for k in node.keywords
                     if k.arg == "code" and isinstance(k.value, ast.Constant)), None)
        if code is None:
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("error", "warn", "info"):
            levels.setdefault(code, set()).add(
                {"error": "error", "warn": "warning", "info": "info"}[func.attr])
        elif isinstance(func, ast.Name) and func.id in ("_deny", "finding"):
            levels.setdefault(code, set()).update({"error", "warning"})
    return levels


def test_registry_matches_the_source():
    registry = {code: set(levels.split("/")) for code, levels in FINDING_CODES.items()}
    assert _codes_in_source() == registry


def test_codes_document_lists_every_code():
    text = (ROOT / "docs" / "finding-codes.md").read_text(encoding="utf-8")
    for code, levels in FINDING_CODES.items():
        assert f"| `{code}` | {levels} |" in text, code


def test_reported_codes_are_registered():
    for name in ("valid", "tampered-object", "stripped-signatures", "added-signer"):
        report = verify_bundle(CORPUS / f"{name}.veridict.zip", trusted_keys={FINGERPRINT})
        for finding in report.findings:
            assert finding.code in FINDING_CODES, finding
            assert finding.level in FINDING_CODES[finding.code].split("/"), finding


def test_accepted_warnings(capsys):
    assert verify_cli([str(VALID), "--trusted-key", FINGERPRINT]) == 2
    capsys.readouterr()
    assert verify_cli([str(VALID), "--trusted-key", FINGERPRINT,
                       "--allow-warning", "timestamps.pending"]) == 0
    out = capsys.readouterr().out
    assert "[ALLOW]" in out and "VERDICT: VALID" in out


@pytest.mark.parametrize("code", ["chain.head_mismatch", "no.such.code"])
def test_errors_and_unknown_codes_cannot_be_accepted(code, capsys):
    assert not can_be_warning(code)
    with pytest.raises(ValueError):
        verify_bundle(VALID, allow_warnings={code})
    assert verify_cli([str(VALID), "--allow-warning", code]) == 1


def test_forbid_ai_steps(capsys):
    # The valid corpus bundle contains one AI step.
    assert verify_cli([str(VALID), "--trusted-key", FINGERPRINT, "--forbid-ai-steps"]) == 1
    assert "[policy.ai_step_forbidden]" in capsys.readouterr().out


def test_json_and_list_codes(capsys):
    assert verify_cli([str(VALID), "--json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert all(f["code"] for f in data["findings"])
    assert verify_cli(["--list-codes"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == len(FINDING_CODES)


def test_pinned_tsa_roots_without_timestamp_support_are_invalid(monkeypatch):
    """Base install (no [timestamps] extra) must not pass a pinned TSA check."""
    monkeypatch.setitem(sys.modules, "rfc3161_client", None)  # import now fails
    report = verify_bundle(CORPUS / "tsa-genuine.veridict.zip",
                           trusted_keys={FINGERPRINT},
                           tsa_roots=CORPUS / "tsa-roots" / "genuine-root.pem")
    assert report.verdict == "INVALID"
    assert any(f.code == "timestamps.support_missing" for f in report.errors)


@pytest.mark.skipif(importlib.util.find_spec("rfc3161_client") is not None,
                    reason="only meaningful in a base install")
def test_base_install_really_lacks_timestamp_support():
    report = verify_bundle(CORPUS / "tsa-genuine.veridict.zip",
                           tsa_roots=CORPUS / "tsa-roots" / "genuine-root.pem")
    assert report.verdict == "INVALID"
