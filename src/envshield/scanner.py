import fnmatch
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from envshield.entropy import is_high_entropy
from envshield.rules import (
    DEFAULT_IGNORE_DIRS,
    DEFAULT_IGNORE_EXTENSIONS,
    DEFAULT_RULES,
    SENSITIVE_FILE_PATTERNS,
    Rule,
)


@dataclass
class Finding:
    file_path: str
    line_number: int
    rule_name: str
    severity: str
    masked_value: str
    snippet: str


@dataclass
class SensitiveFileAlert:
    file_path: str
    reason: str
    is_git_ignored: bool


@dataclass
class ScanResult:
    scanned_files_count: int = 0
    scanned_lines_count: int = 0
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    sensitive_files: List[SensitiveFileAlert] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return len(self.findings) > 0 or any(not alert.is_git_ignored for alert in self.sensitive_files)


def mask_secret(secret: str) -> str:
    """Masks secret values to protect them from exposure in logs."""
    if len(secret) <= 8:
        return "*" * len(secret)

    # Preserve recognizable token prefix while masking the rest
    for prefix in ("sk-proj-", "sk_live_", "rk_live_", "sk-", "ghp_", "gho_", "github_pat_", "AKIA", "AIza", "xoxb-", "xoxp-"):
        if secret.startswith(prefix) and len(secret) > len(prefix) + 4:
            return f"{prefix}****{secret[-4:]}"

    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_middle = "*" * max(4, len(secret) - prefix_len - suffix_len)
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"


def is_binary_file(path: Path) -> bool:
    """Detects if a file is binary by looking for null bytes in the first kilobyte."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except OSError:
        return True


def load_gitignore_patterns(root_dir: Path) -> List[str]:
    """Reads .gitignore patterns if available in the directory."""
    gitignore_file = root_dir / ".gitignore"
    patterns: List[str] = []
    if gitignore_file.exists():
        try:
            with open(gitignore_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except OSError:
            pass
    return patterns


def is_ignored_by_patterns(relative_path: str, patterns: List[str]) -> bool:
    """Checks if a path matches any gitignore or custom pattern."""
    norm_path = relative_path.replace("\\", "/")
    for pattern in patterns:
        clean_pat = pattern.rstrip("/")
        if fnmatch.fnmatch(norm_path, clean_pat) or fnmatch.fnmatch(os.path.basename(norm_path), clean_pat):
            return True
        if norm_path.startswith(clean_pat + "/") or fnmatch.fnmatch(norm_path, f"*{clean_pat}*"):
            return True
    return False


class Scanner:
    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        ignore_dirs: Optional[Set[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
        entropy_threshold: float = 4.3,
    ):
        self.rules = rules or DEFAULT_RULES
        self.ignore_dirs = set(DEFAULT_IGNORE_DIRS)
        if ignore_dirs:
            self.ignore_dirs.update(ignore_dirs)
        self.ignore_patterns = ignore_patterns or []
        self.entropy_threshold = entropy_threshold

    def scan_path(self, target_path: str) -> ScanResult:
        start_time = time.time()
        path_obj = Path(target_path).resolve()
        result = ScanResult()

        if not path_obj.exists():
            raise FileNotFoundError(f"Path does not exist: {target_path}")

        gitignore_patterns = []
        if path_obj.is_dir():
            gitignore_patterns = load_gitignore_patterns(path_obj)
        elif path_obj.parent.exists():
            gitignore_patterns = load_gitignore_patterns(path_obj.parent)

        all_ignore_patterns = self.ignore_patterns + gitignore_patterns

        if path_obj.is_file():
            self._scan_file(path_obj, path_obj.parent, all_ignore_patterns, result)
        else:
            self._walk_and_scan(path_obj, all_ignore_patterns, result)

        result.duration_seconds = round(time.time() - start_time, 3)
        return result

    def _walk_and_scan(self, root_dir: Path, ignore_patterns: List[str], result: ScanResult) -> None:
        for current_root, dirs, files in os.walk(root_dir):
            current_path = Path(current_root)

            # Filter out ignored directories in-place to avoid descending
            dirs[:] = [
                d
                for d in dirs
                if d not in self.ignore_dirs
                and not is_ignored_by_patterns(str((current_path / d).relative_to(root_dir)), ignore_patterns)
            ]

            for file_name in files:
                file_path = current_path / file_name
                ext = file_path.suffix.lower()

                if ext in DEFAULT_IGNORE_EXTENSIONS:
                    continue

                rel_path = str(file_path.relative_to(root_dir))
                if is_ignored_by_patterns(rel_path, ignore_patterns):
                    continue

                self._check_sensitive_filename(file_path, rel_path, ignore_patterns, result)
                self._scan_file(file_path, root_dir, ignore_patterns, result)

    def _check_sensitive_filename(
        self, file_path: Path, rel_path: str, ignore_patterns: List[str], result: ScanResult
    ) -> None:
        filename = file_path.name
        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.match(filename):
                is_ignored = is_ignored_by_patterns(rel_path, ignore_patterns)
                result.sensitive_files.append(
                    SensitiveFileAlert(
                        file_path=rel_path,
                        reason="Potentially sensitive configuration or key file",
                        is_git_ignored=is_ignored,
                    )
                )
                break

    def _scan_file(
        self, file_path: Path, base_dir: Path, ignore_patterns: List[str], result: ScanResult
    ) -> None:
        if is_binary_file(file_path):
            return

        result.scanned_files_count += 1
        rel_path = str(file_path.relative_to(base_dir)) if file_path.is_relative_to(base_dir) else str(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, start=1):
                    result.scanned_lines_count += 1
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith(("#", "//", "/*", "*")):
                        continue

                    for rule in self.rules:
                        match = rule.pattern.search(line)
                        if not match:
                            continue

                        secret_value = match.group(1) if match.groups() else match.group(0)

                        if rule.entropy_check and not is_high_entropy(secret_value, threshold=self.entropy_threshold):
                            continue

                        masked_secret_val = mask_secret(secret_value)
                        masked_snippet = line_clean.replace(secret_value, masked_secret_val)[:120]
                        result.findings.append(
                            Finding(
                                file_path=rel_path,
                                line_number=line_no,
                                rule_name=rule.name,
                                severity=rule.severity,
                                masked_value=masked_secret_val,
                                snippet=masked_snippet,
                            )
                        )
        except (OSError, UnicodeDecodeError):
            pass
