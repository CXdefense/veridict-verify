"""The conformance corpus: every case gives its expected outcome; rebuilding is exact.

The first test needs only the verifier and the committed files, like a third party
would run it. The second rebuilds the corpus with the engine (a dev dependency here)
and requires the same bytes, so a format change cannot slip in unnoticed.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from veridict_verify.verifier import verify_bundle

CORPUS = Path(__file__).parent / "conformance"
CASES = json.loads((CORPUS / "cases.json").read_text(encoding="utf-8"))["cases"]
HAS_TIMESTAMPS = importlib.util.find_spec("rfc3161_client") is not None


def _options(case: dict) -> dict:
    options, kwargs = case["options"], {}
    if "trusted_keys" in options:
        kwargs["trusted_keys"] = {
            (CORPUS / "keys" / f"{name}.fingerprint").read_text("utf-8").strip()
            for name in options["trusted_keys"]
        }
    if "tsa_roots" in options:
        kwargs["tsa_roots"] = CORPUS / options["tsa_roots"]
    if "allow_warnings" in options:
        kwargs["allow_warnings"] = set(options["allow_warnings"])
    if options.get("forbid_ai_steps"):
        kwargs["forbid_ai_steps"] = True
    return kwargs


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_case_gives_the_expected_outcome(case):
    if "timestamps" in case["requires"] and not HAS_TIMESTAMPS:
        pytest.skip("needs veridict-verify[timestamps]")
    report = verify_bundle(CORPUS / case["bundle"], **_options(case))
    assert report.verdict == case["verdict"]
    assert sorted({f.code for f in report.errors}) == case["errors"]
    assert sorted({f.code for f in report.warnings}) == case["warnings"]


def test_corpus_covers_the_rules_that_matter():
    names = {c["name"] for c in CASES}
    assert {"stripped-signatures-pinned", "added-signer-pinned", "storage-path-outside",
            "duplicate-json-member", "unsafe-archive-member", "ai-step-forbidden",
            "tsa-smuggled-root", "valid-pinned-accepting-pending"} <= names
    assert len({c["bundle"] for c in CASES}) == len(list(CORPUS.glob("*.veridict.zip")))


def test_corpus_archives_carry_nothing_os_specific():
    """The two things that made Windows and Linux builds differ (found by CI on #12)."""
    import zipfile

    for bundle in sorted(CORPUS.glob("*.veridict.zip")):
        with zipfile.ZipFile(bundle) as zf:
            for info in zf.infolist():
                assert info.create_system == 3, (bundle.name, info.filename)
                if info.filename.endswith((".json", ".jsonl")):
                    assert b"\r" not in zf.read(info.filename), (bundle.name, info.filename)


def test_rebuilding_the_corpus_gives_the_same_bytes(tmp_path):
    pytest.importorskip("veridict")
    from veridict.testing.conformance import build_corpus

    build_corpus(tmp_path)
    committed = sorted(p.relative_to(CORPUS).as_posix() for p in CORPUS.rglob("*") if p.is_file())
    rebuilt = sorted(p.relative_to(tmp_path).as_posix()
                     for p in tmp_path.rglob("*") if p.is_file())
    assert rebuilt == committed
    for rel in committed:
        assert (tmp_path / rel).read_bytes() == (CORPUS / rel).read_bytes(), (
            f"{rel} differs; regenerate with scripts/make_conformance_fixtures.py"
        )
