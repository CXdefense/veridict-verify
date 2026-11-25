# Evidence: bundle format after M2, 2026-11-25

`docs/bundle-format.md` now describes the `enrolled/1` signer profile,
`manifest.signers`, deliveries, level-two folder imports and the timestamp
`egress_ref`, and has a **Verifier versions** table. The numbers match the
screenshots kept with the engine; only the three that matter to users of this
package are copied here.

| File | What it shows |
|---|---|
| `07-rule-matrix.png` | One re-signed break per rule on a synthetic case with two analysts and a system key, checked by the development verifier ("main") and by `veridict-verify` 0.3.0 from PyPI, with and without a pinned key |
| `09-check-tree-030-crash.png` | `--check-tree` on a level-two import: the development verifier matches the folder; 0.3.0 stops with `ModuleNotFoundError: No module named 'veridict_verify.tree'` |
| `11-public-mirror.png` | This copy of the spec is identical to the engine's, apart from two references to files that exist only in the engine repository |

The data is synthetic. Each screenshot is plain-text output in a terminal style
under a one-line caption. The text was not edited, with three exceptions: a local
temporary path in `09` is shortened to `<temp folder>` (the caption says so), and
pinned fingerprints appear as `<analyst A>` and `<import key>`.
