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

    def test_mask_secret_standard(self):
        self.assertEqual(mask_secret("1234"), "****")
        masked = mask_secret("sk-proj-1234567890abcdef")
        self.assertEqual(masked, "sk-proj-****cdef")
        self.assertNotIn("1234567890", masked)

    def test_mask_secret_other_prefixes(self):
        gh_masked = mask_secret("ghp_123456789012345678901234567890123456")
        self.assertTrue(gh_masked.startswith("ghp_****"))
        self.assertTrue(gh_masked.endswith("3456"))

        aws_masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(aws_masked.startswith("AKIA****"))
        self.assertTrue(aws_masked.endswith("MPLE"))

    def test_snippet_is_masked_in_findings(self):
        raw_secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        code_file = self.base_path / "app.py"
        code_file.write_text(f'OPENAI_KEY = "{raw_secret}"\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        # Ensure the raw secret is nowhere in snippet or masked_value
        self.assertNotIn(raw_secret, finding.snippet)
        self.assertNotIn(raw_secret, finding.masked_value)
        self.assertIn("sk-proj-****7890", finding.snippet)
        self.assertIn("sk-proj-****7890", finding.masked_value)

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

    def test_false_positives_filtering(self):
        clean_file = self.base_path / "normal_code.py"
        clean_file.write_text(
            '''
            # This is a comment about api_key = "1234"
            def calculate_total(api_key="placeholder"):
                base_url = "https://api.openai.com/v1/models"
                sample_token = "simple-short"
                regular_words = "the quick brown fox jumps over the lazy dog"
                dummy_hash = "00000000000000000000000000000000"
                return base_url
            ''',
            encoding="utf-8",
        )

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 0)
        self.assertFalse(result.has_violations)

    def test_binary_file_skipped(self):
        binary_file = self.base_path / "image.bin"
        # Binary content with null bytes and an embedded token string
        content = b"\x00\x01\x02\x03\xff\xfe" + b"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" + b"\x00\x00"
        binary_file.write_bytes(content)

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        # Binary files should be skipped from line analysis
        self.assertEqual(len(result.findings), 0)

    def test_large_file_scanning(self):
        large_file = self.base_path / "large_data.py"
        # Generate 6,000 lines of regular code
        lines = [f'data_entry_{i} = "clean_value_number_{i}"\n' for i in range(6000)]
        large_file.write_text("".join(lines), encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(result.scanned_files_count, 1)
        self.assertGreaterEqual(result.scanned_lines_count, 6000)
        self.assertEqual(len(result.findings), 0)
        self.assertLess(result.duration_seconds, 2.0)

    def test_directory_exclusion(self):
        # Create an ignored directory (e.g., node_modules or custom vendor)
        ignored_dir = self.base_path / "node_modules" / "leaky_pkg"
        ignored_dir.mkdir(parents=True)
        leaked_file = ignored_dir / "index.js"
        leaked_file.write_text('const secret = "ghp_123456789012345678901234567890123456";\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        # Because node_modules is in DEFAULT_IGNORE_DIRS, nothing should be reported
        self.assertEqual(len(result.findings), 0)

    def test_custom_ignore_dir(self):
        custom_dir = self.base_path / "vendor"
        custom_dir.mkdir()
        leaked_file = custom_dir / "lib.py"
        leaked_file.write_text('KEY = "AIzaSyD-1234567890123456789012345678901"\n', encoding="utf-8")

        scanner = Scanner(ignore_dirs={"vendor"})
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 0)

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

        unignored = [f for f in result.sensitive_files if not f.is_git_ignored]
        self.assertEqual(len(unignored), 0)


if __name__ == "__main__":
    unittest.main()
