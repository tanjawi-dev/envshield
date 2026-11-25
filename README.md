# 🛡️ EnvShield

> Lightweight, high-speed, zero-dependency secret scanner and pre-commit security tool for developers.

EnvShield scans your codebase for exposed credentials, API keys, private certificates, and unignored environment files (`.env`) before they leak into Git history.

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
git clone https://github.com/trygemini979-ai/envshield.git
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

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
