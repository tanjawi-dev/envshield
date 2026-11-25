import subprocess
import tempfile
import unittest
from pathlib import Path

from envshield.staged import StagedScanner, get_staged_content, get_staged_entries, is_git_repository


class TestStagedScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

        # Initialize real git repository for testing staged operations
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.base_path), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(self.base_path), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(self.base_path), capture_output=True, check=True)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_is_git_repository(self):
        self.assertTrue(is_git_repository(self.base_path))

    def test_staged_secret_detection(self):
        leak_file = self.base_path / "config.py"
        fake_token = "ghp_111122223333444455556666777788889999"
        leak_file.write_text(f'GITHUB_KEY = "{fake_token}"\n', encoding="utf-8")

        # Stage the file
        subprocess.run(["git", "add", "config.py"], cwd=str(self.base_path), capture_output=True, check=True)

        scanner = StagedScanner()
        result = scanner.scan_staged(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_name, "GitHub Personal Access Token")
        self.assertTrue(result.has_violations)
        self.assertNotIn(fake_token, result.findings[0].masked_value)

    def test_unstaged_edits_do_not_leak_into_staged_scan(self):
        clean_file = self.base_path / "app.py"
        clean_file.write_text('print("Clean staged content")\n', encoding="utf-8")

        # Stage clean content
        subprocess.run(["git", "add", "app.py"], cwd=str(self.base_path), capture_output=True, check=True)

        # Now modify working copy with an unstaged secret!
        fake_token = "ghp_UNSTAGED_MODIFICATION_TOKEN_123456"
        clean_file.write_text(f'print("Unstaged: {fake_token}")\n', encoding="utf-8")

        # Scanner should inspect ONLY staged blob, which is clean!
        scanner = StagedScanner()
        result = scanner.scan_staged(str(self.base_path))

        self.assertEqual(len(result.findings), 0)
        self.assertFalse(result.has_violations)

    def test_staged_filename_with_spaces(self):
        space_file = self.base_path / "my sensitive config.py"
        fake_token = "AKIAIOSFODNN7EXAMPLE"
        space_file.write_text(f'AWS_KEY = "{fake_token}"\n', encoding="utf-8")

        subprocess.run(["git", "add", "my sensitive config.py"], cwd=str(self.base_path), capture_output=True, check=True)

        scanner = StagedScanner()
        result = scanner.scan_staged(str(self.base_path))

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].file_path, "my sensitive config.py")


if __name__ == "__main__":
    unittest.main()
