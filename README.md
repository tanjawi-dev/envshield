# 🛡️ EnvShield

[![Tests](https://github.com/tanjawi-dev/envshield/actions/workflows/ci.yml/badge.svg)](https://github.com/tanjawi-dev/envshield/actions)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Zero Runtime Dependencies](https://img.shields.io/badge/runtime%20dependencies-zero-brightgreen)

> High-speed, zero-runtime-dependency secret scanner and Git pre-commit security tool for developers.

EnvShield protects codebases from accidental credential leaks by detecting exposed API keys, private certificates, database URIs, and unignored environment files (`.env`) before they are committed into Git history.

---

## 📸 CLI Output Preview

```text
$ envshield scan .

🛡️  EnvShield Security Scanner
============================================================

⚠️  CRITICAL: Unprotected Sensitive Files Detected
These files are sensitive and NOT properly ignored:
  • .env (Potentially sensitive configuration or key file)

🚨 SECRETS DETECTED

  [CRITICAL] OpenAI API Key
    Location: src/config.py:14
    Pattern:  sk-proj-****AbCd
    Snippet:  OPENAI_API_KEY = "sk-proj-****AbCd"

  [HIGH] AWS Access Key ID
    Location: deploy/settings.json:8
    Pattern:  AKIA****MPLE
    Snippet:  "access_key": "AKIA****MPLE"

------------------------------------------------------------
Files Scanned: 42 | Lines Scanned: 1,850 | Time: 0.042s
❌ Scan Failed: 3 security violation(s) identified!
```

---

## ✨ Features

- **⚡ Zero External Runtime Dependencies:** Runs exclusively on Python 3.10+ standard library. No third-party packages needed at runtime.
- **🪝 Staged Git Scanning (`--staged`):** Inspects actual Git index blobs (`git show :path`) rather than uncommitted working directory state.
- **🔒 Zero-Exposure Masking:** Automatically sanitizes every secret in terminal previews, snippets, and JSON reports—even when multiple secrets appear on the same line.
- **🔍 20+ Detection Rules:** Identifies tokens from OpenAI, GitHub, AWS, Google Cloud, Stripe, Slack, JWTs, private keys, and database connection URIs.
- **🎲 Shannon Entropy Analysis:** Evaluates token randomness with character diversity filtering to catch custom secrets while avoiding false positives on common placeholders.
- **📁 Advanced GitIgnore Engine:** Hierarchical support for nested `.gitignore` files, negation patterns (`!pattern`), and directory-specific trailing slash semantics (`dir/`).
- **🛡️ Filesystem & ReDoS Safety:** Includes symlink boundary enforcement, bounded line processing, and a configurable 10 MB file size limit.
- **🔄 Safe Hook Management:** One-command hook installer (`install-hook`) with automatic backup of foreign hooks, `--force` flag, and clean uninstallation (`uninstall-hook`).
- **📊 CI/CD Ready:** Rich terminal output, quiet mode (`-q`), verbose diagnostics (`-v`), and structured JSON export.

---

## 🚀 Quick Start

### Option A: Direct Execution (Zero Installation)

Run directly with any Python 3.10+ environment without installing any packages:

```bash
git clone https://github.com/tanjawi-dev/envshield.git
cd envshield
python -m envshield.cli scan .
```

### Option B: Local Installation

Install the CLI entrypoint globally or within a virtual environment:

```bash
pip install -e .
envshield scan .
```

---

## 💻 Commands & Usage

### 1. Scan Working Directory
```bash
envshield scan .
# Or use the convenient shortcut:
envshield check .
```

### 2. Scan Staged Git Changes Only
Scan only the exact modifications staged for the next commit:
```bash
envshield scan --staged
```

### 3. CI/CD & Automation (JSON & Quiet Mode)
Export a structured JSON report or suppress non-essential banners in CI pipelines:
```bash
# JSON export
envshield scan . --format json > security-report.json

# Quiet mode (exits with code 1 if violations found, code 0 if clean)
envshield scan . --quiet
```

### 4. Git Pre-Commit Hook Management
Protect your repository by installing the automated staged pre-commit hook:
```bash
# Safely install the pre-commit hook (preserves existing foreign hooks with a warning)
envshield install-hook

# Force installation (automatically backs up foreign hook to pre-commit.envshield.bak)
envshield install-hook --force

# Cleanly uninstall hook (automatically restores any previous backup hook)
envshield uninstall-hook
```

*Note: In rare situations where a local commit must proceed without running the hook, Git provides the native bypass flag: `git commit --no-verify`.*

### 5. CLI Options & Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--staged` | Scans staged Git index blobs instead of working tree | `False` |
| `--format` | Output report format (`text` or `json`) | `text` |
| `-q`, `--quiet` | Minimal output mode for automated scripts | `False` |
| `-v`, `--verbose` | Shows diagnostic details of skipped files | `False` |
| `--entropy` | Shannon entropy threshold for generic secrets | `4.3` |
| `--max-size` | Maximum file size to scan in MB | `10` |
| `--no-color` | Disables ANSI colors in terminal | `False` |
| `--exit-zero` | Always exit with code 0 even if secrets are found | `False` |
| `--ignore-dir` | Additional directory to ignore (repeatable) | `[]` |
| `--ignore-pattern` | Additional glob pattern to ignore (repeatable) | `[]` |

---

## 🧪 Running Tests

EnvShield uses Python's standard `unittest` framework with zero external test runner dependencies:

```bash
python -m unittest discover -s tests -v
```

All 41 unit tests run in less than 4 seconds on any standard workstation.

---

## 🏗️ Architecture & Future Companions

EnvShield is designed with modular, decoupled interfaces:
- `envshield.scanner`: Core scanning engine and multi-secret sanitization.
- `envshield.staged`: Git index staging inspector.
- `envshield.ignore`: Hierarchical GitIgnore engine.
- `envshield.rules`: Regex rules and placeholder exclusions.
- `envshield.entropy`: Shannon entropy and diversity analysis.
- `envshield.hook`: Safe Git hook lifecycle manager.

This architecture ensures seamless future integration with planned companion tools:
- **DotEnvLint:** Specialized validation and hygiene for `.env` and `.env.example` templates.
- **HookGuard:** Multi-tool Git hook orchestration and enterprise policy enforcement.

---

## 🤝 Contributing & Security

- To report security vulnerabilities confidentially, please review our [SECURITY.md](SECURITY.md).
- To contribute new rules or improvements, please review our [CONTRIBUTING.md](CONTRIBUTING.md).
- See all release history in our [CHANGELOG.md](CHANGELOG.md).

---

## 📜 License

Distributed under the open-source **MIT License**. See [LICENSE](LICENSE) for details.
