# `--check-tree` fixtures

Synthetic data for `tests/test_check_tree.py` and `scripts/check_tree_smoke.py`.
Nothing here comes from a real case.

| File | What it is |
|---|---|
| `case/` | the folder that was sealed: three short text files in three folders |
| `seal.veridict.zip` | `veridict-seal seal case`: an offline folder seal whose inventory is a `folder-inventory/1` Artifact |
| `import.veridict.zip` | `veridict-seal import case`: a level-two import (an `enrolled/1` case) whose only inventory is a `folder-inventory/2` Artifact |
| `analyst.fingerprint` | the fingerprint of the key that signed both bundles |
| `make_tree_fixtures.py` | the script that made all of the above |

Expected results with the key pinned (`--trusted-key $(cat analyst.fingerprint)`):

| Folder given to `--check-tree` | Verdict | Codes |
|---|---|---|
| a copy of `case/` | `VALID WITH WARNINGS` (exit 2) | `tree.matched` (info, "3 files matched"), `timestamps.pending` (warning: sealed offline) |
| a copy with one file edited, one added and one removed | `INVALID` (exit 1) | `tree.mismatch` x3: `changed:`, `added:`, `missing:` |

`import.veridict.zip` has no `folder-inventory/1` Artifact, so it also tests that the
verifier falls back to the last `folder-inventory/2` Artifact, as
`docs/bundle-format.md` describes. 0.3.0 had no fallback and no `tree.py` module.

## How it was made

With the VERIDICT engine repository at commit `ac9136a` (its `main` at the time),
after `uv sync --all-packages --frozen`, from this repository's root:

```bash
<engine>/.venv/Scripts/python tests/fixtures/tree/make_tree_fixtures.py tests/fixtures/tree
```

The script writes `case/`, runs the engine's `veridict-seal seal` and
`veridict-seal import` on it in-process, and rewrites both ZIPs stored with a fixed
time. The key comes from a fixed seed and the engine's clock and ids are counters, so
two runs give the same bytes (`seal.veridict.zip` SHA-256 `0502b5d4…`,
`import.veridict.zip` `96e1da53…`). The tests only read the committed files; they do
not need the engine.

All files are byte-exact: `.gitattributes` marks `tests/fixtures/**` `-text`, so Git
never changes their line endings. The inventory hashes cover the files in `case/`
exactly, LF line endings included.
