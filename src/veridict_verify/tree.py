"""Independently reconcile a signed checksum inventory with a local folder."""
import hashlib
import os
import re
import stat
import unicodedata
from pathlib import Path


def compare_tree(data: bytes, directory: Path) -> tuple[int, list[str]]:
    expected = {}
    lines = data.decode("utf-8").split("\n")
    if lines.pop() != "":
        raise ValueError("checksum inventory must end with LF")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError("invalid checksum inventory")
        digest, name = match.groups()
        if name in expected or any(p in ("", ".", "..") for p in name.split("/")):
            raise ValueError("duplicate or invalid inventory path")
        expected[name] = digest
    if list(expected) != sorted(expected):
        raise ValueError("inventory paths are not sorted")
    directory = Path(directory)
    issues = []
    matched = 0
    seen = set()

    def local(path):
        s = path.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x441400:
            raise ValueError("link or offline entry in comparison folder")
        return s

    def visit(folder):
        nonlocal matched
        for path in folder.iterdir():
            name = path.relative_to(directory).as_posix()
            key = unicodedata.normalize("NFC", name).casefold()
            if key in seen:
                raise ValueError("ambiguous path in comparison folder")
            seen.add(key)
            s = local(path)
            if stat.S_ISDIR(s.st_mode):
                visit(path)
            elif not stat.S_ISREG(s.st_mode):
                raise ValueError("unsupported entry in comparison folder")
            elif path.name.startswith("~$") or path.name.lower() in {"thumbs.db", "desktop.ini", ".ds_store"}:
                continue
            elif name not in expected:
                issues.append(f"added: {name}")
            else:
                with path.open("rb") as stream:
                    if not os.path.samestat(s, os.fstat(stream.fileno())):
                        raise ValueError("file changed during comparison")
                    actual = hashlib.file_digest(stream, "sha256").hexdigest()
                after = path.lstat()
                if (not os.path.samestat(s, after) or s.st_mtime_ns != after.st_mtime_ns
                        or s.st_size != after.st_size):
                    raise ValueError("file changed during comparison")
                if actual == expected.pop(name):
                    matched += 1
                else:
                    issues.append(f"changed: {name}")
    local(directory)
    visit(directory)
    issues.extend(f"missing: {name}" for name in sorted(expected))
    return matched, issues
