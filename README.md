# 🛡️ EnvShield

[![Tests](https://github.com/tanjawi-dev/envshield/actions/workflows/ci.yml/badge.svg)](https://github.com/tanjawi-dev/envshield/actions)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)

> Lightweight, high-speed, zero-dependency secret scanner and pre-commit security tool for developers.

EnvShield scans your codebase for exposed credentials, API keys, private certificates, and unignored environment files (`.env`) before they leak into Git history.

---

## 📸 CLI Output Preview

```text
$ envshield scan .

🛡️  EnvShield Security Scanner
============================================================

⚠️  CRITICAL: Unprotected Sensitive Files Detected
These files exist on disk but are NOT included in .gitignore:
  • .env (Potentially sensitive configuration or key file)

🚨 SECRETS DETECTED

  [CRITICAL] OpenAI API Key
    Location: src/config.py:14
    Pattern:  sk-proj-****AbCd
    Snippet:  OPENAI_API_KEY = "sk-proj-abcdef1234567890abcdef1234567890"

  [HIGH] AWS Access Key ID
    Location: deploy/settings.json:8
    Pattern:  AKIA****************
    Snippet:  "access_key": "AKIAIOSFODNN7EXAMPLE"

------------------------------------------------------------
Files Scanned: 42 | Lines Scanned: 1,850 | Time: 0.042s
❌ Scan Failed: 3 security violation(s) identified!
```

---

## ✨ Features

- **⚡ Zero External Dependencies:** Operates exclusively using the Python 3 standard library.
- **🔍 20+ Detection Patterns:** Identifies tokens from OpenAI, GitHub, AWS, Google Cloud, Stripe, Slack, JWTs, and database URIs.
- **🎲 Shannon Entropy Analysis:** Evaluates token randomness to catch custom API keys and secret assignments while minimizing false positives.
- **📁 Sensitive File Protection:** Detects unignored `.env`, `.pem`, and certificate files that pose security risks.
- **🪝 One-Click Pre-Commit Hook:** Easily install a Git pre-commit hook with `envshield install-hook`.
- **📊 CI/CD Friendly:** Supports both styled terminal output and structured JSON export with appropriate exit codes.

---

## 🚀 Quick Start

### Installation

Clone the repository and install locally:

```bash
git clone https://github.com/tanjawi-dev/envshield.git
cd envshield
pip install -e .
```

Alternatively, run directly with Python:

```bash
python -m envshield.cli scan .
```

---

## 💻 Usage

### 1. Scan Current Project
```bash
envshield scan .
```

### 2. Export as JSON (for CI/CD pipelines)
```bash
envshield scan . --format json > report.json
```

### 3. Install Git Pre-Commit Hook
Prevent accidental commits containing secrets:
```bash
envshield install-hook
```

### 4. Custom Ignore Rules
```bash
envshield scan . --ignore-dir vendor --ignore-pattern "*.mock.json"
```

---

## 🧪 Running Tests

Run the test suite with Python's built-in test runner:

```bash
python -m unittest discover -s tests -v
```

---

## 🤝 Contributing

We welcome contributions! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for setup and pull request guidelines.

---

## 🔒 Security

For security vulnerability reporting, please see [SECURITY.md](SECURITY.md).

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
