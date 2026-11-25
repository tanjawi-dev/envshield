import tempfile
import unittest
from pathlib import Path

from envshield.hook import install_pre_commit_hook, uninstall_pre_commit_hook


class TestHook(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_install_hook_without_git_dir_raises(self):
        with self.assertRaises(FileNotFoundError):
            install_pre_commit_hook(str(self.base_path))

    def test_install_hook_clean_success(self):
        git_dir = self.base_path / ".git"
        git_dir.mkdir()

        success, msg = install_pre_commit_hook(str(self.base_path))
        self.assertTrue(success)

        hook_file = git_dir / "hooks" / "pre-commit"
        self.assertTrue(hook_file.exists())
        content = hook_file.read_text(encoding="utf-8")
        self.assertIn("envshield.cli", content)
        self.assertIn("--staged", content)

    def test_foreign_hook_refusal_without_force(self):
        git_dir = self.base_path / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook_file = hooks_dir / "pre-commit"
        hook_file.write_text("#!/bin/sh\necho 'foreign hook'\n", encoding="utf-8")

        success, msg = install_pre_commit_hook(str(self.base_path), force=False)
        self.assertFalse(success)
        self.assertIn("--force", msg)

        # File content must remain unchanged
        self.assertEqual(hook_file.read_text(encoding="utf-8"), "#!/bin/sh\necho 'foreign hook'\n")

    def test_foreign_hook_backup_with_force(self):
        git_dir = self.base_path / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook_file = hooks_dir / "pre-commit"
        hook_file.write_text("#!/bin/sh\necho 'foreign hook'\n", encoding="utf-8")

        success, msg = install_pre_commit_hook(str(self.base_path), force=True)
        self.assertTrue(success)

        backup_file = hooks_dir / "pre-commit.envshield.bak"
        self.assertTrue(backup_file.exists())
        self.assertEqual(backup_file.read_text(encoding="utf-8"), "#!/bin/sh\necho 'foreign hook'\n")
        self.assertIn("envshield.cli", hook_file.read_text(encoding="utf-8"))

    def test_uninstall_hook_and_restore_backup(self):
        git_dir = self.base_path / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook_file = hooks_dir / "pre-commit"
        backup_file = hooks_dir / "pre-commit.envshield.bak"

        # Install EnvShield hook with an existing backup
        install_pre_commit_hook(str(self.base_path))
        backup_file.write_text("#!/bin/sh\necho 'restored hook'\n", encoding="utf-8")

        success, msg = uninstall_pre_commit_hook(str(self.base_path))
        self.assertTrue(success)
        self.assertFalse(backup_file.exists())
        self.assertTrue(hook_file.exists())
        self.assertEqual(hook_file.read_text(encoding="utf-8"), "#!/bin/sh\necho 'restored hook'\n")


if __name__ == "__main__":
    unittest.main()
