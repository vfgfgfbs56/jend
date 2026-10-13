#!/usr/bin/env python3
"""Require an up-to-date root handoff document in every substantive Jend PR.

PR diffs are validated using immutable base/head SHAs injected by GitHub
Actions. Running locally without both SHAs verifies the root document's
minimum structure but does not pretend to have checked a pull request.
Never executes untrusted diff output as shell commands.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "JEND-PROJECT-CONTEXT.md"
MANIFEST = ROOT / "PROJECT-MANIFEST.sha256"

REQUIRED_HEADINGS = (
    "## 1. Что мы строим",
    "## 2. Архитектура",
    "## 3. Подтверждено",
    "## 4. GitHub PR stack",
    "## 5. Очередь задач",
    "## 6. Когда именно заканчиваем backend и переходим к frontend?",
    "## 7. Как ОБЯЗАТЕЛЬНО поддерживать этот файл актуальным",
)

def main() -> int:
    if not DOC.is_file() or not MANIFEST.is_file():
        print("Jend context gate: root continuity file or integrity manifest missing", file=sys.stderr)
        return 1
    text = DOC.read_text(encoding="utf-8")
    missing = [title for title in REQUIRED_HEADINGS if title not in text]
    if missing or len(text) < 4000:
        print("Jend context gate: missing roadmap/architecture sections " + repr(missing), file=sys.stderr)
        return 1

    base = os.environ.get("JEND_PR_BASE_SHA", "")
    head = os.environ.get("JEND_PR_HEAD_SHA", "")
    if not base and not head:
        print("Jend root project context structural check: PASS (no PR diff context)")
        return 0
    if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{40}", head):
        print("Jend context gate: invalid or incomplete PR SHA context", file=sys.stderr)
        return 1

    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "diff", "--name-only", "--diff-filter=ACMR",
             base, head, "--"],
            text=True, capture_output=True, check=True, timeout=20,
        )
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as error:
        print("Jend context gate: unable to compare actual PR commit range:", error, file=sys.stderr)
        return 1

    changed = {p.strip() for p in result.stdout.splitlines() if p.strip()}
    substantive = changed - {DOC.name, MANIFEST.name}
    if substantive and DOC.name not in changed:
        print(
            "Jend context gate: substantive PR changed files, but "
            "JEND-PROJECT-CONTEXT.md was not updated. Update progress, "
            "verified results, blockers and next milestone in the same PR.",
            file=sys.stderr,
        )
        return 1
    if DOC.name in changed and MANIFEST.name not in changed:
        print("Jend context gate: changed context without updating SHA256 manifest", file=sys.stderr)
        return 1
    print("Jend root project context updated with substantive PR: PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
