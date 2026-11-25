import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

from envshield.entropy import is_high_entropy
from envshield.ignore import GitIgnoreManager
from envshield.rules import (
    DEFAULT_IGNORE_DIRS,
    DEFAULT_IGNORE_EXTENSIONS,
    DEFAULT_RULES,
    PLACEHOLDER_EXCLUSIONS,
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
    skipped_large_files: List[str] = field(default_factory=list)
    skipped_unreadable_files: List[str] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return len(self.findings) > 0 or any(not alert.is_git_ignored for alert in self.sensitive_files)


def mask_secret(secret: str) -> str:
    """
    Masks secret values to protect them from exposure in logs, terminal, and reports.
    Preserves recognizable prefixes while concealing the bulk of the secret.
    """
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)

    known_prefixes = (
        "sk-proj-",
        "sk-admin-",
        "sk-svcacct-",
        "sk_live_",
        "rk_live_",
        "pk_live_",
        "sk-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "AKIA",
        "ASIA",
        "ABIA",
        "ACCA",
        "AIza",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
    )
    for prefix in known_prefixes:
        if secret.startswith(prefix) and len(secret) > len(prefix) + 4:
            return f"{prefix}****{secret[-4:]}"

    prefix_len = min(4, max(1, len(secret) // 4))
    suffix_len = min(4, max(1, len(secret) // 4))
    masked_middle = "****"
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"


def sanitize_line(line: str, secrets_to_mask: List[Tuple[str, str]]) -> str:
    """
    Sanitizes an entire line by replacing all detected raw secrets with their masked counterparts.
    Sorts by secret length in descending order to prevent substring replacement collisions.
    """
    sanitized = line
    sorted_pairs = sorted(secrets_to_mask, key=lambda pair: len(pair[0]), reverse=True)
    for raw_sec, masked_sec in sorted_pairs:
        if raw_sec in sanitized:
            sanitized = sanitized.replace(raw_sec, masked_sec)
    return sanitized


def is_binary_file(path: Path) -> bool:
    """Detects if a file is binary by looking for null bytes in the first kilobyte."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


class Scanner:
    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        ignore_dirs: Optional[Set[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
        entropy_threshold: float = 4.3,
        max_file_size_bytes: int = 10 * 1024 * 1024,  # 10 MB limit
    ):
        self.rules = rules or DEFAULT_RULES
        self.ignore_dirs = set(DEFAULT_IGNORE_DIRS)
        if ignore_dirs:
            self.ignore_dirs.update(ignore_dirs)
        self.ignore_patterns = ignore_patterns or []
        self.entropy_threshold = entropy_threshold
        self.max_file_size_bytes = max_file_size_bytes

    def scan_path(self, target_path: str) -> ScanResult:
        start_time = time.time()
        path_obj = Path(target_path).resolve()
        result = ScanResult()

        if not path_obj.exists():
            raise FileNotFoundError(f"Path does not exist: {target_path}")

        root_dir = path_obj if path_obj.is_dir() else path_obj.parent
        gitignore_manager = GitIgnoreManager(
            root_dir=root_dir,
            ignore_dirs=self.ignore_dirs,
            custom_patterns=self.ignore_patterns,
        )

        if path_obj.is_file():
            self._scan_file(path_obj, path_obj.parent, gitignore_manager, result)
        else:
            self._walk_and_scan(path_obj, gitignore_manager, result)

        result.duration_seconds = round(time.time() - start_time, 3)
        return result

    def _walk_and_scan(
        self, root_dir: Path, gitignore_manager: GitIgnoreManager, result: ScanResult
    ) -> None:
        resolved_root = root_dir.resolve()

        for current_root, dirs, files in os.walk(resolved_root, followlinks=False):
            current_path = Path(current_root)

            # Prevent descending into symlinked directories outside target root
            if current_path.is_symlink():
                try:
                    if not current_path.resolve().is_relative_to(resolved_root):
                        dirs[:] = []
                        continue
                except (ValueError, OSError):
                    dirs[:] = []
                    continue

            # Filter out ignored directories in-place to avoid descending
            filtered_dirs = []
            for d in dirs:
                dir_path = current_path / d
                if d in self.ignore_dirs:
                    continue
                if gitignore_manager.is_ignored(dir_path, is_dir=True):
                    continue
                filtered_dirs.append(d)
            dirs[:] = filtered_dirs

            for file_name in files:
                file_path = current_path / file_name
                ext = file_path.suffix.lower()

                if ext in DEFAULT_IGNORE_EXTENSIONS:
                    continue

                if gitignore_manager.is_ignored(file_path, is_dir=False):
                    continue

                self._check_sensitive_filename(file_path, resolved_root, gitignore_manager, result)
                self._scan_file(file_path, resolved_root, gitignore_manager, result)

    def _check_sensitive_filename(
        self, file_path: Path, base_dir: Path, gitignore_manager: GitIgnoreManager, result: ScanResult
    ) -> None:
        filename = file_path.name
        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.match(filename):
                try:
                    rel_path = str(file_path.relative_to(base_dir)).replace("\\", "/")
                except ValueError:
                    rel_path = str(file_path)

                is_ignored = gitignore_manager.is_ignored(file_path, is_dir=False)
                result.sensitive_files.append(
                    SensitiveFileAlert(
                        file_path=rel_path,
                        reason="Potentially sensitive configuration or key file",
                        is_git_ignored=is_ignored,
                    )
                )
                break

    def _scan_file(
        self, file_path: Path, base_dir: Path, gitignore_manager: GitIgnoreManager, result: ScanResult
    ) -> None:
        # Check if symlink points outside base_dir
        if file_path.is_symlink():
            try:
                resolved_target = file_path.resolve()
                if not resolved_target.is_relative_to(base_dir.resolve()):
                    return
            except (ValueError, OSError):
                return

        # Check file size limit
        try:
            stat_info = file_path.stat()
            if stat_info.st_size > self.max_file_size_bytes:
                result.skipped_large_files.append(str(file_path))
                return
        except (OSError, PermissionError):
            result.skipped_unreadable_files.append(str(file_path))
            return

        if is_binary_file(file_path):
            return

        result.scanned_files_count += 1
        try:
            rel_path = str(file_path.relative_to(base_dir)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, start=1):
                    result.scanned_lines_count += 1
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith(("#", "//", "/*", "*")):
                        continue

                    # Guard against excessive line length (e.g. minified bundles)
                    if len(line) > 10000:
                        line_to_scan = line[:10000]
                    else:
                        line_to_scan = line

                    line_matches = []
                    for rule in self.rules:
                        for match in rule.pattern.finditer(line_to_scan):
                            secret_value = match.group(1) if match.groups() else match.group(0)

                            if rule.entropy_check:
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
        except (OSError, PermissionError, UnicodeDecodeError):
            result.skipped_unreadable_files.append(rel_path)
