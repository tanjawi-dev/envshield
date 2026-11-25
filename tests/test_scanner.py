import tempfile
import unittest
from pathlib import Path

from envshield.scanner import Scanner, mask_secret


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_mask_secret(self):
        self.assertEqual(mask_secret("1234"), "****")
        masked = mask_secret("sk-proj-1234567890abcdef")
        self.assertTrue(masked.startswith("sk-p"))
        self.assertTrue(masked.endswith("cdef"))
        self.assertIn("****", masked)

    def test_detect_openai_token(self):
        code_file = self.base_path / "app.py"
        code_file.write_text('api_token = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "OpenAI API Key")
        self.assertEqual(result.findings[0].severity, "CRITICAL")
        self.assertTrue(result.has_violations)

    def test_detect_github_token(self):
        code_file = self.base_path / "config.js"
        code_file.write_text('const gh = "ghp_123456789012345678901234567890123456";\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "GitHub Personal Access Token")

    def test_detect_aws_keys(self):
        code_file = self.base_path / "deploy.sh"
        code_file.write_text('export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "AWS Access Key ID")

    def test_detect_database_uri(self):
        code_file = self.base_path / "db.py"
        code_file.write_text('URI = "postgres://admin:SuperSecretPassword123@db.prod.internal:5432/main"\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "Database Connection String")

    def test_unignored_env_file_alert(self):
        env_file = self.base_path / ".env"
        env_file.write_text("DEBUG=True\n", encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertTrue(result.has_violations)
        self.assertEqual(len(result.sensitive_files), 1)
        self.assertFalse(result.sensitive_files[0].is_git_ignored)

    def test_ignored_env_file_passes_unignored_check(self):
        gitignore = self.base_path / ".gitignore"
        gitignore.write_text(".env\n", encoding="utf-8")

        env_file = self.base_path / ".env"
        env_file.write_text("DEBUG=True\n", encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        # It's ignored by .gitignore, so it shouldn't produce violations if no secrets inside
        unignored = [f for f in result.sensitive_files if not f.is_git_ignored]
        self.assertEqual(len(unignored), 0)


if __name__ == "__main__":
    unittest.main()
