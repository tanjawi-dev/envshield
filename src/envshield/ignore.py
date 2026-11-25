import fnmatch
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class GitIgnoreRule:
    def __init__(self, raw_pattern: str, base_dir: Path):
        self.raw_pattern = raw_pattern
        self.base_dir = base_dir.resolve()
        self.is_negation = False
        self.dir_only = False
        self.anchored = False
        self.pattern = ""

        self._parse()

    def _parse(self) -> None:
        pat = self.raw_pattern.strip()
        if pat.startswith("!"):
            self.is_negation = True
            pat = pat[1:].strip()

        if pat.endswith("/"):
            self.dir_only = True
            pat = pat.rstrip("/")

        # If pattern has leading slash, it is anchored to base_dir
        if pat.startswith("/"):
            self.anchored = True
            pat = pat.lstrip("/")
        elif "/" in pat:
            # If slash appears anywhere in the middle, it's also anchored relative to base_dir
            self.anchored = True

        self.pattern = pat

    def matches(self, target_path: Path, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False

        # Target must be inside or equal to base_dir
        try:
            rel = target_path.resolve().relative_to(self.base_dir)
        except ValueError:
            return False

        rel_str = str(rel).replace("\\", "/")
        if not rel_str or rel_str == ".":
            return False

        if self.anchored:
            return fnmatch.fnmatch(rel_str, self.pattern) or fnmatch.fnmatch(rel_str, f"{self.pattern}/*")

        # Unanchored pattern: matches either the relative path directly or any segment
        basename = target_path.name
        if fnmatch.fnmatch(basename, self.pattern):
            return True

        if fnmatch.fnmatch(rel_str, self.pattern) or fnmatch.fnmatch(rel_str, f"*/{self.pattern}"):
            return True

        # Check path prefixes for directory matching
        parts = rel_str.split("/")
        for part in parts:
            if fnmatch.fnmatch(part, self.pattern):
                return True

        return False


class GitIgnoreManager:
    """
    Manages loading and evaluating .gitignore files hierarchically,
    supporting nested .gitignores, negation patterns (!), directory-only patterns, and custom rules.
    """

    def __init__(
        self,
        root_dir: Path,
        ignore_dirs: Optional[Set[str]] = None,
        custom_patterns: Optional[List[str]] = None,
    ):
        self.root_dir = root_dir.resolve()
        self.ignore_dirs = set(ignore_dirs or set())
        self.custom_patterns = custom_patterns or []
        self._rules_by_dir: Dict[Path, List[GitIgnoreRule]] = {}
        self._custom_rules: List[GitIgnoreRule] = [
            GitIgnoreRule(pat, self.root_dir) for pat in self.custom_patterns if pat.strip()
        ]

        # Preload root .gitignore if present
        self.load_gitignore_in_dir(self.root_dir)

    def load_gitignore_in_dir(self, directory: Path) -> None:
        dir_obj = directory.resolve()
        if dir_obj in self._rules_by_dir:
            return

        rules: List[GitIgnoreRule] = []
        gitignore_path = dir_obj / ".gitignore"

        if gitignore_path.is_file():
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            rules.append(GitIgnoreRule(line, dir_obj))
            except OSError:
                pass

        self._rules_by_dir[dir_obj] = rules

    def is_ignored(self, path: Path, is_dir: bool = False) -> bool:
        resolved_path = path.resolve()

        # Check default hard ignore directories (e.g. .git, node_modules)
        for part in resolved_path.parts:
            if part in self.ignore_dirs:
                return True

        # Collect relevant directories from root to path's parent
        dirs_to_check: List[Path] = []
        cur: Optional[Path] = resolved_path if is_dir else resolved_path.parent
        while cur and cur != self.root_dir.parent:
            dirs_to_check.append(cur)
            if cur == self.root_dir:
                break
            cur = cur.parent

        dirs_to_check.reverse()

        # Load gitignores if not loaded yet
        for d in dirs_to_check:
            self.load_gitignore_in_dir(d)

        # Collect all rules in hierarchy order (top-level first, deeper overrides)
        all_rules: List[GitIgnoreRule] = list(self._custom_rules)
        for d in dirs_to_check:
            if d in self._rules_by_dir:
                all_rules.extend(self._rules_by_dir[d])

        # Evaluate rules in sequence: later rules can negate earlier rules
        ignored = False
        for rule in all_rules:
            if rule.matches(resolved_path, is_dir):
                ignored = not rule.is_negation

        return ignored
