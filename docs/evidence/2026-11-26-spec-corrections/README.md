# Evidence: bundle format corrected against the M2 code, 2026-11-26

An independent check of the spec against the engine and the development verifier found
twelve places where `docs/bundle-format.md` said something the code does not do, and
one unclear passage (obligation 12). The engine's copy of the spec has been corrected,
and this copy follows it. Where the code falls short of what the format intends, the
spec now says what the code does, and a new **Known gaps** subsection under **Verifier
versions** lists each gap and its effect on a recipient. The code fixes are tracked for
the engine owner. Nothing in this package changes, and neither does its version.

| File | What it shows |
|---|---|
| `01-public-mirror.png` | This copy equals the engine's corrected spec except in three places, which point to files in the engine repository |
| `02-main-corrections.png` | Rule 4 on step agents, the blank delivery reference, obligations 12 (`grantedWithMods` is refused) and 14, and the pinned-key paragraph |
| `03-verifier-versions.png` | Which rows of the version table the check scripts tested and which come from reading the code; the `--check-tree` cell for 0.3.0 |
| `04-known-gaps.png` | The new **Known gaps** subsection |
| `05-tests.png` | This package's tests and every conformance case, on this branch |

The other corrections (manifest rows, times, the `contradicts` and `supersedes` edge
types, the `human/` prefix, register rows, inventory bytes and `--check-tree`) are in
the same diff. Each screenshot is plain-text output in a terminal style under a
one-line caption (Edge via Playwright). The text was not edited, except that
screenshot 1 leaves out the engine-side lines of the comparison.
