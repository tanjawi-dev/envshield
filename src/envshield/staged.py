import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from envshield.rules import (
    DEFAULT_IGNORE_DIRS,
    DEFAULT_IGNORE_EXTENSIONS,
    DEFAULT_RULES,
    SENSITIVE_FILE_PATTERNS,
    Rule,
)
from envshield.scanner import Finding, ScanResult, SensitiveFileAlert, mask_secret, sanitize_line


def is_git_repository(path: Path) -> bool:
    """Verifies if the given path is inside an active git repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0 and res.stdout.strip() == "true"
    except (subprocess.SubprocessError, OSError):
        return False


def get_git_repo_root(path: Path) -> Optional[Path]:
    """Gets the top-level root directory of the Git working tree."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return Path(res.stdout.strip()).resolve()
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def get_staged_entries(repo_root: Path) -> List[Tuple[str, str]]:
    """
    Parses staged files from the Git index using 'git diff --cached --name-status -z'.
    Handles spaces, quotes, and renames accurately.
    Returns list of (status, file_path_relative_to_repo_root).
    """
    try:
        # Check if HEAD exists, or compare against empty tree
        cmd = ["git", "diff", "--cached", "--name-status", "-z"]
        res = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, timeout=10)
        if res.returncode != 0:
            return []

        raw_parts = res.stdout.split(b"\x00")
        entries: List[Tuple[str, str]] = []
        i = 0
        while i < len(raw_parts):
            if not raw_parts[i]:
                break
            status = raw_parts[i].decode("utf-8", errors="replace")
            i += 1
            if i >= len(raw_parts) or not raw_parts[i]:
                break

            if status.startswith("R") or status.startswith("C"):
                # Renames/copies output: status, old_path, new_path
                _old_path = raw_parts[i].decode("utf-8", errors="replace")
                i += 1
                if i < len(raw_parts) and raw_parts[i]:
                    new_path = raw_parts[i].decode("utf-8", errors="replace")
                    entries.append((status[0], new_path))
                    i += 1
            else:
                path_str = raw_parts[i].decode("utf-8", errors="replace")
                entries.append((status, path_str))
                i += 1

        return entries
    except (subprocess.SubprocessError, OSError):
        return []


def get_staged_content(repo_root: Path, relative_path: str) -> Optional[bytes]:
    """
    Retrieves the exact staged blob content from Git index for the file.
    Does NOT read the uncommitted working directory file.
    """
    try:
        # Format :path gets staged version (stage 0)
        clean_path = relative_path.replace("\\", "/")
        cmd = ["git", "show", f":{clean_path}"]
        res = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, timeout=10)
        if res.returncode == 0:
            return res.stdout
    except (subprocess.SubprocessError, OSError):
        pass
    return None


class StagedScanner:
    """Scans content staged in the Git index before it gets committed."""

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        entropy_threshold: float = 4.3,
        max_file_size_bytes: int = 10 * 1024 * 1024,
    ):
        self.rules = rules or DEFAULT_RULES
        self.entropy_threshold = entropy_threshold
        self.max_file_size_bytes = max_file_size_bytes

    def scan_staged(self, repo_path: str = ".") -> ScanResult:
        start_time = time.time()
        result = ScanResult()
        path_obj = Path(repo_path).resolve()

        repo_root = get_git_repo_root(path_obj)
        if not repo_root:
            raise FileNotFoundError(f"Not a git repository: {repo_path}")

        staged_entries = get_staged_entries(repo_root)

        for status, rel_path in staged_entries:
            # Skip deleted files (they won't be in the commit)
            if status == "D":
                continue

            path_parts = rel_path.replace("\\", "/").split("/")
            if any(part in DEFAULT_IGNORE_DIRS for part in path_parts):
                continue

            ext = Path(rel_path).suffix.lower()
            if ext in DEFAULT_IGNORE_EXTENSIONS:
                continue

            # Check if filename is sensitive (e.g. .env or id_rsa staged!)
            filename = Path(rel_path).name
            for pat in SENSITIVE_FILE_PATTERNS:
                if pat.match(filename):
                    result.sensitive_files.append(
                        SensitiveFileAlert(
                            file_path=rel_path,
                            reason="Sensitive credential or environment file is staged for commit",
                            is_git_ignored=False,
                        )
                    )
                    break

            content_bytes = get_staged_content(repo_root, rel_path)
            if content_bytes is None:
                continue

            if len(content_bytes) > self.max_file_size_bytes:
                continue

            if b"\x00" in content_bytes[:1024]:
                # Binary file in stage, skip line scanning
                continue

            result.scanned_files_count += 1
            text = content_bytes.decode("utf-8", errors="replace")
            lines = text.splitlines()

            for line_no, line in enumerate(lines, start=1):
                result.scanned_lines_count += 1
                line_clean = line.strip()
                if not line_clean or line_clean.startswith(("#", "//", "/*", "*")):
                    continue

                line_matches = []
                for rule in self.rules:
                    for match in rule.pattern.finditer(line):
                        secret_value = match.group(1) if match.groups() else match.group(0)

                        if rule.entropy_check:
                            from envshield.entropy import is_high_entropy
                            from envshield.rules import PLACEHOLDER_EXCLUSIONS

                            if secret_value.lower() in PLACEHOLDER_EXCLUSIONS:
                                continue
                            if not is_high_entropy(secret_value, threshold=self.entropy_threshold):
                                continue

                        line_matches.append((rule, secret_value, mask_secret(secret_value)))

                if line_matches:
                    clean_snippet = sanitize_line(line_clean, [(s, m) for _, s, m in line_matches])
                    for rule, secret_value, masked_val in line_matches:
                        result.findings.append(
                            Finding(
                                file_path=rel_path,
                                line_number=line_no,
                                rule_name=rule.name,
                                severity=rule.severity,
                                masked_value=masked_val,
                                snippet=clean_snippet[:120],
                            )
                        )

        result.duration_seconds = round(time.time() - start_time, 3)
        return result
