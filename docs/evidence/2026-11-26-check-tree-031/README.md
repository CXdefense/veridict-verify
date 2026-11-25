# Evidence: `--check-tree` in 0.3.0 and 0.3.1

`veridict-verify` 0.3.0 on PyPI does not contain `veridict_verify/tree.py`, which
`verifier.py` imports when `--check-tree` is given. 0.3.1 ships the module (copied
unchanged from the development verifier) and the three-line `folder-inventory/2`
fallback that a level-two import needs.

| File | What it shows |
|---|---|
| `01-030-check-tree-crash.png` | 0.3.0 installed from PyPI: the package has four modules and no `tree.py`; `--check-tree` stops with `ModuleNotFoundError` and exit 1 on the conformance bundle and on a real folder seal; `--json` prints nothing; `scripts/check_tree_smoke.py` fails all 5 checks |
| `02-030-plus-tree-py-only.png` | 0.3.0 with only `tree.py` copied into site-packages: the folder seal matches, but the level-two import is `INVALID` with `tree.inventory_count`, because 0.3.0 looks only for `folder-inventory/1` |
| `03-031-check-tree-results.png` | the 0.3.1 wheel built with `uv build`, in a clean venv with `[timestamps]`: a bundle without an inventory gives `tree.inventory_count` (exit 1, valid `--json`, nothing on stderr); the folder seal and the level-two import match their folder (`tree.matched`, exit 2 for pending timestamps); an edited folder gives `changed:`, `added:` and `missing:` (`tree.mismatch`, exit 1) |
| `04-031-release-gate.png` | the 0.3.1 wheel with and without `[timestamps]`: `check_tree_smoke.py` 5 of 5, conformance 20 of 20 (without the extra: 16 ok, 4 skipped), the whole test suite |
| `05-new-tests-030-vs-031.png` | `tests/test_check_tree.py` and `tests/test_package_imports.py` against the installed 0.3.0 (11 fail) and the installed 0.3.1 wheel (13 pass) |

All bundles and folders are synthetic (`tests/conformance/`, `tests/fixtures/tree/`).
Each screenshot is real command output on Windows 11, Python 3.12, rendered as text
in a terminal style under a one-line caption. Edits to the text: local paths are
shortened to `<scratch>`, temporary folders appear as `<temp>/...` and the pinned
fingerprint in commands as `<fp>`; verifier reports are cut to their finding lines
and verdict; tracebacks are cut to their last frame; after the first artifact, the
pair of pending-timestamp lines per artifact is replaced by a count.
