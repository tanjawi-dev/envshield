import os
import tempfile
import unittest
from pathlib import Path

from envshield.scanner import Scanner, mask_secret, sanitize_line


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
        self.assertEqual(gh_masked, "ghp_****3456")

        aws_masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(aws_masked, "AKIA****MPLE")

        slack_masked = mask_secret("xoxb-TEST-MOCK-TOKEN-VALUE-4321")
        self.assertEqual(slack_masked, "xoxb-****4321")

    def test_sanitize_multiple_secrets_on_same_line(self):
        token_a = "ghp_FIRST_SECRET_TOKEN_123456789012"
        token_b = "ghp_SECOND_SECRET_TOKEN_98765432109"
        line = f"config(key='{token_a}', backup='{token_b}')"

        sanitized = sanitize_line(
            line,
            [
                (token_a, mask_secret(token_a)),
                (token_b, mask_secret(token_b)),
            ],
        )

        self.assertNotIn(token_a, sanitized)
        self.assertNotIn(token_b, sanitized)
        self.assertIn("ghp_****9012", sanitized)
        self.assertIn("ghp_****2109", sanitized)

    def test_scanner_detects_and_masks_multiple_secrets_same_line(self):
        token1 = "ghp_111122223333444455556666777788889999"
        token2 = "AKIAIOSFODNN7EXAMPLE"
        code_file = self.base_path / "multi.py"
        code_file.write_text(f'KEYS = ["{token1}", "{token2}"]\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 2)
        # Neither raw secret should be in ANY snippet or masked_value
        for finding in result.findings:
            self.assertNotIn(token1, finding.snippet)
            self.assertNotIn(token2, finding.snippet)
            self.assertNotIn(token1, finding.masked_value)
            self.assertNotIn(token2, finding.masked_value)

    def test_detect_openai_token(self):
        code_file = self.base_path / "app.py"
        token = "sk-proj-FAKETOKEN1234567890abcdefghijklmnopqrstuvwxyz"
        code_file.write_text(f'api_token = "{token}"\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "OpenAI API Key")
        self.assertEqual(result.findings[0].severity, "CRITICAL")
        self.assertNotIn(token, result.findings[0].snippet)

    def test_detect_github_token(self):
        code_file = self.base_path / "config.js"
        token = "ghp_111122223333444455556666777788889999"
        code_file.write_text(f'const gh = "{token}";\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "GitHub Personal Access Token")

    def test_detect_aws_keys(self):
        code_file = self.base_path / "deploy.sh"
        token = "AKIAIOSFODNN7EXAMPLE"
        code_file.write_text(f'export AWS_ACCESS_KEY_ID="{token}"\n', encoding="utf-8")

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

    def test_detect_private_key_header(self):
        code_file = self.base_path / "cert.py"
        code_file.write_text('KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA..."\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "Private Encryption Key")

    def test_detect_jwt(self):
        code_file = self.base_path / "auth.py"
        # Deterministic fake JWT format
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        code_file.write_text(f'TOKEN = "{fake_jwt}"\n', encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "JSON Web Token (JWT)")

    def test_false_positives_placeholder_exclusions(self):
        clean_file = self.base_path / "sample_config.py"
        clean_file.write_text(
            '''
            API_KEY = "your_api_key_here"
            AUTH_TOKEN = "insert_token_here"
            SECRET_KEY = "00000000000000000000000000000000"
            ''',
            encoding="utf-8",
        )

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 0)
        self.assertFalse(result.has_violations)

    def test_binary_file_skipped(self):
        binary_file = self.base_path / "image.png"
        content = b"\x00\x01\x02\x03\xff\xfe" + b"sk-proj-FAKETOKEN12345678901234567890" + b"\x00\x00"
        binary_file.write_bytes(content)

        scanner = Scanner()
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.findings), 0)

    def test_large_file_skip_and_recording(self):
        large_file = self.base_path / "huge.txt"
        # 2 MB file with scanner max_size set to 1 MB
        large_file.write_bytes(b"A" * (2 * 1024 * 1024))

        scanner = Scanner(max_file_size_bytes=1 * 1024 * 1024)
        result = scanner.scan_path(str(self.base_path))

        self.assertEqual(len(result.skipped_large_files), 1)
        self.assertEqual(result.scanned_files_count, 0)

    def test_symlink_pointing_outside_root_skipped(self):
        if not hasattr(os, "symlink"):
            return  # Skip on systems without symlink capability

        outside_dir = tempfile.TemporaryDirectory()
        try:
            secret_outside = Path(outside_dir.name) / "secret.py"
            secret_outside.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

            symlink_inside = self.base_path / "link_to_outside.py"
            try:
                symlink_inside.symlink_to(secret_outside)
            except OSError:
                return  # Skip if user doesn't have symlink privilege on Windows

            scanner = Scanner()
            result = scanner.scan_path(str(self.base_path))

            # External symlink target should be ignored
            self.assertEqual(len(result.findings), 0)
        finally:
            outside_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
