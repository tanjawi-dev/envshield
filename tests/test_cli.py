import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from envshield.cli import main


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_cli_clean_scan(self):
        clean_file = self.base_path / "hello.py"
        clean_file.write_text('print("Hello, world!")\n', encoding="utf-8")

        exit_code = main(["scan", str(self.base_path), "--no-color"])
        self.assertEqual(exit_code, 0)

    def test_cli_check_command_alias(self):
        clean_file = self.base_path / "app.py"
        clean_file.write_text('print("Clean")\n', encoding="utf-8")

        exit_code = main(["check", str(self.base_path), "--no-color"])
        self.assertEqual(exit_code, 0)

    def test_cli_version_command(self):
        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            exit_code = main(["version"])
        self.assertEqual(exit_code, 0)
        self.assertIn("envshield", captured_stdout.getvalue())

    def test_cli_secret_detected_exit_1(self):
        leak_file = self.base_path / "leak.py"
        leak_file.write_text('KEY = "AIzaSyD-1234567890123456789012345678901"\n', encoding="utf-8")

        exit_code = main(["scan", str(self.base_path), "--no-color"])
        self.assertEqual(exit_code, 1)

    def test_cli_exit_zero_flag(self):
        leak_file = self.base_path / "leak.py"
        leak_file.write_text('KEY = "AIzaSyD-1234567890123456789012345678901"\n', encoding="utf-8")

        exit_code = main(["scan", str(self.base_path), "--exit-zero", "--no-color"])
        self.assertEqual(exit_code, 0)

    def test_cli_quiet_mode(self):
        leak_file = self.base_path / "leak.py"
        leak_file.write_text('KEY = "AIzaSyD-1234567890123456789012345678901"\n', encoding="utf-8")

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            exit_code = main(["scan", str(self.base_path), "--quiet", "--no-color"])

        self.assertEqual(exit_code, 1)
        output = captured_stdout.getvalue()
        # Should not have the full verbose banner
        self.assertNotIn("Location: leak.py", output)
        self.assertIn("Security violations detected", output)

    def test_cli_json_output_masks_secret(self):
        raw_token = "ghp_123456789012345678901234567890123456"
        leak_file = self.base_path / "secret.js"
        leak_file.write_text(f'const token = "{raw_token}";\n', encoding="utf-8")

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            exit_code = main(["scan", str(self.base_path), "--format", "json", "--exit-zero"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(captured_stdout.getvalue())
        self.assertEqual(len(payload["findings"]), 1)
        finding = payload["findings"][0]

        self.assertNotIn(raw_token, captured_stdout.getvalue())
        self.assertIn("ghp_****3456", finding["masked_secret"])
        self.assertIn("ghp_****3456", finding["snippet"])

    def test_cli_missing_path_returns_exit_2(self):
        captured_stderr = io.StringIO()
        with patch("sys.stderr", captured_stderr):
            exit_code = main(["scan", "/non/existent/path/for/envshield/test"])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
