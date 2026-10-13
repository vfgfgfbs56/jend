#!/usr/bin/env python3
from __future__ import annotations
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = ROOT / "PROJECT-MANIFEST.sha256"
expected = {}
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    digest, rel = raw.split("  ", 1)
    if rel in expected:
        raise SystemExit(f"duplicate manifest entry: {rel}")
    expected[rel] = digest

def is_generated_or_vcs(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if not rel.parts:
        return False
    if rel.parts[0] in {".git", "target", ".jend-dev-secrets"}:
        return True
    # Finder creates these automatically on macOS; they are never source inputs.
    if rel.name == ".DS_Store":
        return True
    # Allow test logs created by `... | tee first-test.log` at repository root.
    if len(rel.parts) == 1 and rel.suffix == ".log":
        return True
    if rel.as_posix() in {"Cargo.lock", "resolved-metadata.json"}:
        return True
    if "__pycache__" in rel.parts:
        return True
    return False

actual_files = {
    p.relative_to(ROOT).as_posix(): p
    for p in ROOT.rglob("*")
    if p.is_file() and p != manifest and not is_generated_or_vcs(p)
}
missing = sorted(set(expected) - set(actual_files))
extra = sorted(set(actual_files) - set(expected))
if missing or extra:
    raise SystemExit(f"manifest inventory mismatch: missing={missing} extra={extra}")

for rel, path in actual_files.items():
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected[rel]:
        raise SystemExit(f"manifest digest mismatch: {rel}")

print(f"project manifest PASS: {len(actual_files)} files")
