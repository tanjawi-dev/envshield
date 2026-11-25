import os
import stat
from pathlib import Path


PRE_COMMIT_SCRIPT = """#!/bin/sh
# EnvShield Pre-Commit Secret Scanner Hook
echo "🛡️  Running EnvShield pre-commit secret check..."

python -m envshield.cli scan .
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "❌ EnvShield detected potential secrets or unignored sensitive files!"
    echo "Commit rejected to protect repository security."
    exit 1
fi

exit 0
"""


def install_pre_commit_hook(repo_root: str = ".") -> bool:
    """Installs the pre-commit hook in the .git repository hooks directory."""
    root = Path(repo_root).resolve()
    git_dir = root / ".git"

    if not git_dir.exists():
        raise FileNotFoundError(f"No .git directory found at '{root}'. Run 'git init' first.")

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_file = hooks_dir / "pre-commit"
    with open(hook_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(PRE_COMMIT_SCRIPT)

    # Ensure hook is marked executable
    try:
        current_permissions = hook_file.stat().st_mode
        hook_file.chmod(current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    return True
