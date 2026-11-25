# Contributing to EnvShield

First off, thank you for considering contributing to EnvShield! Contributions from the open-source community help make software safer for everyone.

---

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/tanjawi-dev/envshield.git
   cd envshield
   ```

2. **Install the package in editable mode:**
   ```bash
   pip install -e .
   ```

3. **Verify the installation:**
   ```bash
   envshield --version
   ```

---

## 🧪 Running Tests

EnvShield uses Python's standard `unittest` framework. Before creating a pull request, verify that all tests pass:

```bash
python -m unittest discover -s tests -v
```

If you add a new detection rule or feature, remember to add corresponding test cases under the `tests/` directory.

---

## 📐 Design Principles

- **Zero External Runtime Dependencies:** EnvShield must run exclusively using the Python standard library. Do not add external third-party dependencies to runtime dependencies.
- **Fast Execution:** File scanning and regex matching should remain lightweight and high-speed.
- **Privacy & Safety:** Never log or display plain-text credentials in outputs; always use `mask_secret()`.

---

## 🚀 Submitting a Pull Request

1. Create a feature branch (`git checkout -b feat/new-secret-pattern`).
2. Make your changes with clear, descriptive commit messages.
3. Ensure all tests pass (`python -m unittest discover -s tests -v`).
4. Push to your fork and submit a Pull Request against the `main` branch.
5. Provide a summary of the additions or bug fixes in the PR description.
