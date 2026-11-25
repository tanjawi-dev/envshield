import os
import shutil
import stat
from pathlib import Path
from typing import Tuple


HOOK_SIGNATURE = "# EnvShield Pre-Commit Secret Scanner Hook"

PRE_COMMIT_SCRIPT = f"""#!/bin/sh
{HOOK_SIGNATURE}
# Automatically scans staged Git changes for leaked secrets and unignored credentials.

echo "🛡️  Running EnvShield staged secret scanner..."

python -m envshield.cli scan --staged
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo ""
    echo "❌ [EnvShield] Potential secrets or unignored sensitive files detected in staged changes!"
    echo "Commit has been blocked to protect repository security."
    echo ""
    echo "👉 To resolve:"
    echo "   1. Review flagged files and remove exposed credentials."
    echo "   2. If using an intentional placeholder, add it to your .envshield.json ignore list."
    echo "   3. (Note: Local Git hooks can be bypassed with 'git commit --no-verify' if absolutely required)."
    echo ""
    exit 1
fi

exit 0
"""


def get_git_hooks_dir(repo_root: str = ".") -> Path:
    root = Path(repo_root).resolve()
    git_dir = root / ".git"

    # Support git worktrees or submodules where .git is a file
    if git_dir.is_file():
        try:
            with open(git_dir, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content.startswith("gitdir:"):
                    actual_git_dir = Path(content.split("gitdir:", 1)[1].strip())
                    if not actual_git_dir.is_absolute():
                        actual_git_dir = (root / actual_git_dir).resolve()
                    git_dir = actual_git_dir
        except OSError:
            pass

    if not git_dir.exists():
        raise FileNotFoundError(f"No .git directory found at '{root}'. Run 'git init' first.")

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    return hooks_dir


def install_pre_commit_hook(repo_root: str = ".", force: bool = False) -> Tuple[bool, str]:
    """
    Safely installs the EnvShield pre-commit hook in .git/hooks/pre-commit.
    Preserves and backs up existing foreign hooks if force=True.
    """
    hooks_dir = get_git_hooks_dir(repo_root)
    hook_file = hooks_dir / "pre-commit"
    backup_file = hooks_dir / "pre-commit.envshield.bak"

    if hook_file.exists():
        content = ""
        try:
            with open(hook_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            pass

        if HOOK_SIGNATURE in content:
            # Already our hook, update it cleanly
            pass
        elif not force:
            return (
                False,
                f"Existing pre-commit hook found at '{hook_file}'. Use '--force' to backup existing hook and replace.",
            )
        else:
            # Backup foreign hook
            shutil.copy2(hook_file, backup_file)

    with open(hook_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(PRE_COMMIT_SCRIPT)

    # Ensure executable permissions on POSIX systems
    try:
        current_mode = hook_file.stat().st_mode
        hook_file.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    msg = f"Successfully installed EnvShield pre-commit hook at '{hook_file}'."
    if backup_file.exists() and force:
        msg += f" (Existing hook backed up to '{backup_file.name}')"

    return True, msg


def uninstall_pre_commit_hook(repo_root: str = ".") -> Tuple[bool, str]:
    """
    Uninstalls the EnvShield pre-commit hook and restores any previous backup hook.
    """
    hooks_dir = get_git_hooks_dir(repo_root)
    hook_file = hooks_dir / "pre-commit"
    backup_file = hooks_dir / "pre-commit.envshield.bak"

    if not hook_file.exists():
        return False, f"No pre-commit hook found at '{hook_file}'."

    content = ""
    try:
        with open(hook_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        pass

    if HOOK_SIGNATURE not in content:
        return False, f"The hook at '{hook_file}' was not created by EnvShield. Aborting uninstallation."

    hook_file.unlink()

    restored = False
    if backup_file.exists():
        shutil.move(str(backup_file), str(hook_file))
        restored = True

    if restored:
        return True, "EnvShield hook uninstalled and previous backup hook restored successfully."
    return True, "EnvShield hook uninstalled successfully."
