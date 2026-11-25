import tempfile
import unittest
from pathlib import Path

from envshield.hook import install_pre_commit_hook


class TestHook(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_install_hook_without_git_dir_raises(self):
        with self.assertRaises(FileNotFoundError):
            install_pre_commit_hook(str(self.base_path))

    def test_install_hook_success(self):
        git_dir = self.base_path / ".git"
        git_dir.mkdir()

        result = install_pre_commit_hook(str(self.base_path))
        self.assertTrue(result)

        hook_file = git_dir / "hooks" / "pre-commit"
        self.assertTrue(hook_file.exists())
        content = hook_file.read_text(encoding="utf-8")
        self.assertIn("envshield.cli", content)


if __name__ == "__main__":
    unittest.main()
