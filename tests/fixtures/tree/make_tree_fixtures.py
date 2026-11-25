"""Build the --check-tree fixtures in this folder with the VERIDICT engine.

    python tests/fixtures/tree/make_tree_fixtures.py tests/fixtures/tree

Run it with a Python that has the VERIDICT engine installed (the private engine
repository: `uv sync --all-packages --frozen`, then `uv run python ...`). The
verifier tests only read the committed output, so nobody needs the engine to run them.

It writes:

- case/                  three synthetic text files (the folder that was sealed)
- seal.veridict.zip      `veridict-seal seal case`: a folder-inventory/1 artifact
- import.veridict.zip    `veridict-seal import case`: a level-two import whose only
                         inventory is a folder-inventory/2 artifact
- analyst.fingerprint    the signing key's fingerprint (key from a fixed seed)

The output is byte for byte the same on every run: the key comes from a fixed seed,
the engine's clock and ids are counters (as in the engine's conformance corpus), and
both ZIPs are rewritten stored with a fixed time.
"""

from __future__ import annotations

import contextlib
import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from veridict import folder_import, seal
from veridict.testing.conformance import deterministic_engine, keypair, normalize_zip

FILES = {
    "case-journal.txt": b"2026-01-02 synthetic case opened; two sources noted.\n",
    "evidence/page-capture.txt": b"Synthetic capture of example.org, test data only.\n",
    "notes/sources.txt": b"1. example.org (synthetic)\n2. example.net (synthetic)\n",
}


@contextlib.contextmanager
def fixed_clock():
    """The seal and import modules read the wall clock directly; give them a counter."""
    start = datetime(2026, 1, 2, tzinfo=UTC)
    ticks = {"n": 0}

    class _Clock:
        @staticmethod
        def now(tz=None):
            ticks["n"] += 1
            return start + timedelta(seconds=ticks["n"])

    saved = (seal.datetime, folder_import.datetime)
    seal.datetime = folder_import.datetime = _Clock
    try:
        yield
    finally:
        seal.datetime, folder_import.datetime = saved


def main(argv: list[str]) -> int:
    out = Path(argv[0] if argv else Path(__file__).parent).resolve()
    case = out / "case"
    shutil.rmtree(case, ignore_errors=True)
    for name, data in FILES.items():
        path = case / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    key = keypair("tree-fixture")
    with tempfile.TemporaryDirectory(prefix="vtree-") as tmp:
        work = Path(tmp)
        key_path = work / "analyst.pem"
        key.save(key_path)
        for command, label, target in (("seal", "tree-seal", "seal.veridict.zip"),
                                       ("import", "tree-import", "import.veridict.zip")):
            output = work / command
            with deterministic_engine(label), fixed_clock():
                code = seal.main([command, str(case), "--output", str(output),
                                  "--key", str(key_path)])
            if code:
                raise SystemExit(f"veridict-seal {command} failed with exit {code}")
            normalize_zip(output / "seal-00000001" / "case.veridict.zip", out / target)
            print(f"wrote {target}")
    (out / "analyst.fingerprint").write_text(key.fingerprint + "\n", encoding="utf-8",
                                              newline="\n")
    print(f"key {key.fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
