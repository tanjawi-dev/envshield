# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - Target Release

### 🔒 Security Hardening
- **Zero-Exposure Multi-Secret Sanitization:** Fixed snippet generation to safely detect and mask multiple secrets across different rules or repeated patterns on the exact same line.
- **Placeholder Exclusions:** Added automatic filtering for obvious non-secret dummy values (e.g., `your_api_key_here`, `placeholder_key`) to eliminate false positives in generic assignments.
- **Shannon Entropy Refinement:** Integrated minimum character diversity checks to avoid false positives on low-variety repetitive strings.

### 🪝 Git Pre-Commit & Staging Engine
- **Staged Content Scanning (`--staged`):** Redesigned pre-commit scanning to inspect the actual Git index (`git show :path`) rather than uncommitted working directory files.
- **Safe Hook Management:** Added safety checks to prevent overwriting existing foreign Git hooks without explicit `--force`. Foreign hooks are automatically backed up to `pre-commit.envshield.bak`.
- **Hook Uninstallation:** Added `envshield uninstall-hook` to cleanly remove the hook and restore any backed up hooks.
- **Bypass Transparency:** Hook script output clearly documents how to resolve violations or bypass locally via `git commit --no-verify` if required.

### 📁 Ignore Compatibility & Filesystem Safety
- **Hierarchical GitIgnore Manager:** Implemented support for nested `.gitignore` files across directories, negation patterns (`!pattern`), and directory-specific trailing slash semantics (`dir/`).
- **Symlink Protection:** Added guards preventing symlink traversal outside the intended scan root directory.
- **Large File Protection:** Configurable maximum file size ceiling (default 10 MB) preventing memory exhaustion on massive logs or binary dumps.
- **Line Length Safety:** Bounded single-line scanning to prevent ReDoS on minified bundles.

### 💻 CLI & Developer Experience
- Added `check` subcommand as a first-class alias for `scan`.
- Added `version` subcommand.
- Added `-q` / `--quiet` mode for CI pipelines.
- Added `-v` / `--verbose` mode for diagnostic visibility without leaking secrets.
- Added `--max-size` parameter.

### 🧪 Test Suite & CI
- Expanded automated unit test suite to **41 tests** covering all detection patterns, false positives, git staging, hook installation/rollback, and ignore rules.
- Multi-OS GitHub Actions matrix testing Linux (`ubuntu-latest`), Windows (`windows-latest`), and macOS (`macos-latest`) across Python 3.10, 3.11, and 3.12.

---

## [0.1.1] - 2026-11-25
- Implemented default secret masking inside finding snippets.
- Expanded test suite to 27 tests covering false positives and binary files.
- Clarified zero external runtime dependencies in documentation.

---

## [0.1.0] - 2026-11-25
- Initial open-source release of EnvShield.
- Core regex rules and Shannon entropy calculator.
- Initial Git pre-commit hook installer and JSON export.
