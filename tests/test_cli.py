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

    def test_cli_json_output(self):
        clean_file = self.base_path / "index.js"
        clean_file.write_text('console.log("secure");\n', encoding="utf-8")

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            exit_code = main(["scan", str(self.base_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        output_str = captured_stdout.getvalue()
        payload = json.loads(output_str)
        self.assertTrue(payload["summary"]["clean"])
        self.assertEqual(payload["summary"]["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
