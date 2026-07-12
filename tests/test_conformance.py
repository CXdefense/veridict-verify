"""Conformance tests anyone can run without the VERIDICT engine.

The fixtures in tests/fixtures/ were produced by the engine once (see the
engine repository's scripts/make_conformance_fixtures.py) and committed here.
Each tampered variant mutates exactly one thing; the verifier must catch all
of them from the published bundle format alone.
"""

from pathlib import Path

import pytest

from veridict_verify.verifier import verify_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def test_valid_bundle_passes():
    report = verify_bundle(FIXTURES / "valid.veridict.zip")
    # Pending timestamps are expected on an offline-produced fixture.
    assert report.verdict in ("VALID", "VALID WITH WARNINGS")
    assert not report.errors


def test_tampered_artifact_object_is_invalid():
    report = verify_bundle(FIXTURES / "tampered-object.veridict.zip")
    assert report.verdict == "INVALID"
    assert any("do not match sha256" in f.message for f in report.errors)


def test_forged_log_record_is_invalid():
    report = verify_bundle(FIXTURES / "forged-record.veridict.zip")
    assert report.verdict == "INVALID"
    assert any("body hash mismatch" in f.message for f in report.errors)


def test_deleted_log_record_is_invalid():
    report = verify_bundle(FIXTURES / "deleted-record.veridict.zip")
    assert report.verdict == "INVALID"


def test_forged_manifest_chain_head_is_invalid():
    report = verify_bundle(FIXTURES / "forged-manifest-head.veridict.zip")
    assert report.verdict == "INVALID"
    assert any("manifest_hash" in f.message for f in report.errors)
    assert any("chain_head" in f.message for f in report.errors)


def test_swapped_public_key_is_invalid():
    report = verify_bundle(FIXTURES / "swapped-public-key.veridict.zip")
    assert report.verdict == "INVALID"
    assert any(
        "key id mismatch" in f.message or "signature does not verify" in f.message
        for f in report.errors
    )


@pytest.mark.parametrize(
    "fixture",
    [
        "tampered-object.veridict.zip",
        "forged-record.veridict.zip",
        "deleted-record.veridict.zip",
        "forged-manifest-head.veridict.zip",
        "swapped-public-key.veridict.zip",
    ],
)
def test_every_tampered_fixture_reports_at_least_one_error(fixture):
    report = verify_bundle(FIXTURES / fixture)
    assert report.verdict == "INVALID"
    assert report.errors
