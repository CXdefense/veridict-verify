# Verify a VERIDICT bundle in five minutes

You do not need an account, the engine, or trust in the producer — only Python 3.11+.

## 1. Install the standalone verifier

```bash
pip install veridict-verify
```

Optional (RFC-3161 token parsing):

```bash
pip install 'veridict-verify[timestamps]'
```

## 2. Get the demo bundle

Use `examples/demo.veridict.zip` from this repository, or download it from the
GitHub release assets (optionally with `demo.fingerprint`).

## 3. Verify

```bash
veridict-verify demo.veridict.zip
```

Expected: `VALID` or `VALID WITH WARNINGS` (warnings are normal for pending
timestamps on offline demos). Exit code `0` or `2`.

Pin the investigator fingerprint if you received it out-of-band:

```bash
veridict-verify demo.veridict.zip --trusted-key demo.fingerprint
# or:
veridict-verify demo.veridict.zip --trusted-key <64-hex-fingerprint>
```

## 4. Tamper once (prove the verifier notices)

Unzip, flip one byte in any `objects/sha256/...` file, re-zip, and re-verify:

```bash
mkdir scratch && cd scratch
unzip ../demo.veridict.zip
# flip the first byte of the first object (PowerShell / Python — pick one)
python -c "from pathlib import Path; p=next(Path('objects').rglob('*'));
data=bytearray(p.read_bytes()); data[0]^=0xFF; p.write_bytes(data); print(p)"
cd ..
python -c "import zipfile, pathlib; z=zipfile.ZipFile('tampered.veridict.zip','w');
root=pathlib.Path('scratch');
[z.write(p, p.relative_to(root).as_posix()) for p in root.rglob('*') if p.is_file()]; z.close()"
veridict-verify tampered.veridict.zip
```

Expected: `INVALID` with an artifacts error about sha256 mismatch. Exit code `1`.

## What you just proved

The bundle's claim chain is independently re-checkable: hashes, signatures,
citations, and corroboration ceilings do not depend on the producing machine.
