"""Every module the package imports, lazy imports included, is shipped with it.

0.3.0 imported veridict_verify.tree inside a function, and the module was never
packaged; nothing imported it at load time, so the wheel passed every check and
--check-tree crashed for users. This test reads the installed package's source,
collects every import of a veridict_verify module wherever it appears, and imports
each one. Run against an installed wheel, it fails if a module is missing.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import veridict_verify

PACKAGE = "veridict_verify"
INSTALLED = Path(veridict_verify.__file__).resolve().parent
SOURCE = Path(__file__).resolve().parents[1] / "src" / PACKAGE


def _internal_imports(package_dir: Path) -> dict[str, set[str]]:
    """Map each imported veridict_verify module (or module attribute) to its importers."""
    found: dict[str, set[str]] = {}
    for py in sorted(package_dir.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [a.name for a in node.names if a.name.split(".")[0] == PACKAGE]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # relative: from .x import y / from . import x
                    base = ".".join([PACKAGE, node.module] if node.module else [PACKAGE])
                elif node.module and node.module.split(".")[0] == PACKAGE:
                    base = node.module
                else:
                    continue
                targets = [base] + [f"{base}:{a.name}" for a in node.names]
            for target in targets:
                found.setdefault(target, set()).add(f"{py.name}:{node.lineno}")
    return found


def test_every_internal_import_resolves():
    imports = _internal_imports(INSTALLED)
    # The scan must see the lazy import inside _verify_tree, or it proves nothing.
    assert "veridict_verify.tree" in imports, sorted(imports)
    missing = []
    for target, where in sorted(imports.items()):
        module, _, name = target.partition(":")
        try:
            loaded = importlib.import_module(module)
            if name and not hasattr(loaded, name):
                importlib.import_module(f"{module}.{name}")
        except ImportError as exc:
            missing.append(f"{target} (imported at {', '.join(sorted(where))}): {exc}")
    assert not missing, f"installed from {INSTALLED}:\n" + "\n".join(missing)


def test_installed_package_has_every_source_module():
    if not SOURCE.is_dir() or SOURCE == INSTALLED:
        return  # running from an sdist without src/, or from the source tree itself
    source = {p.name for p in SOURCE.glob("*.py")}
    installed = {p.name for p in INSTALLED.glob("*.py")}
    assert source <= installed, f"not installed: {sorted(source - installed)}"
