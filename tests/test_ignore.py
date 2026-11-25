import tempfile
import unittest
from pathlib import Path

from envshield.ignore import GitIgnoreManager, GitIgnoreRule


class TestGitIgnore(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_basic_ignore_pattern(self):
        gitignore = self.base_path / ".gitignore"
        gitignore.write_text("*.log\nnode_modules/\n", encoding="utf-8")

        mgr = GitIgnoreManager(self.base_path)

        log_file = self.base_path / "app.log"
        txt_file = self.base_path / "app.txt"
        nm_dir = self.base_path / "node_modules"

        self.assertTrue(mgr.is_ignored(log_file, is_dir=False))
        self.assertFalse(mgr.is_ignored(txt_file, is_dir=False))
        self.assertTrue(mgr.is_ignored(nm_dir, is_dir=True))

    def test_directory_only_pattern_does_not_match_file(self):
        gitignore = self.base_path / ".gitignore"
        gitignore.write_text("build/\n", encoding="utf-8")

        mgr = GitIgnoreManager(self.base_path)

        build_dir = self.base_path / "build"
        build_file = self.base_path / "build"

        self.assertTrue(mgr.is_ignored(build_dir, is_dir=True))
        self.assertFalse(mgr.is_ignored(build_file, is_dir=False))

    def test_negation_pattern(self):
        gitignore = self.base_path / ".gitignore"
        gitignore.write_text("*.env\n!important.env\n", encoding="utf-8")

        mgr = GitIgnoreManager(self.base_path)

        secret_env = self.base_path / ".env"
        important_env = self.base_path / "important.env"

        self.assertTrue(mgr.is_ignored(secret_env, is_dir=False))
        self.assertFalse(mgr.is_ignored(important_env, is_dir=False))

    def test_nested_gitignore(self):
        root_gitignore = self.base_path / ".gitignore"
        root_gitignore.write_text("*.tmp\n", encoding="utf-8")

        sub_dir = self.base_path / "subdir"
        sub_dir.mkdir()
        sub_gitignore = sub_dir / ".gitignore"
        sub_gitignore.write_text("*.subtmp\n!kept.subtmp\n", encoding="utf-8")

        mgr = GitIgnoreManager(self.base_path)

        root_tmp = self.base_path / "root.tmp"
        sub_tmp = sub_dir / "sub.subtmp"
        kept_subtmp = sub_dir / "kept.subtmp"

        self.assertTrue(mgr.is_ignored(root_tmp, is_dir=False))
        self.assertTrue(mgr.is_ignored(sub_tmp, is_dir=False))
        self.assertFalse(mgr.is_ignored(kept_subtmp, is_dir=False))


if __name__ == "__main__":
    unittest.main()
