"""Filesystem policy and no-follow open tests."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
import stat
from unittest.mock import patch

from security.path_guard import PathAccessError, PathGuard


class PathGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "allowed"
        self.root.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.protected = self.root / "credentials.txt"
        self.protected.write_text("private", encoding="utf-8")
        self.guard = PathGuard([self.root], [self.protected])

    def tearDown(self):
        self.temp.cleanup()

    def test_allowed_path_and_descriptor_read(self):
        target = self.root / "notes.txt"
        target.write_text("hello", encoding="utf-8")
        self.assertEqual(self.guard.validate(target), target)
        fd = self.guard.open_read(target)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "hello")

    def test_outside_path_rejected(self):
        target = self.outside / "notes.txt"
        target.write_text("x", encoding="utf-8")
        with self.assertRaises(PathAccessError):
            self.guard.validate(target)

    def test_traversal_attempt_rejected(self):
        with self.assertRaisesRegex(PathAccessError, "traversal"):
            self.guard.validate(self.root / ".." / "outside" / "notes.txt")

    def test_symlink_escape_rejected(self):
        outside_file = self.outside / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")
        link = self.root / "escape.txt"
        link.symlink_to(outside_file)
        with self.assertRaises(PathAccessError):
            self.guard.open_read(link)

    def test_nonexistent_write_destination_is_allowed_beneath_root(self):
        target = self.root / "new.txt"
        self.assertEqual(self.guard.validate(target, operation="write", must_exist=False), target)
        fd = self.guard.open_write(target)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("created safely")
        self.assertEqual(target.read_text(encoding="utf-8"), "created safely")

    def test_missing_destination_parent_rejected(self):
        with self.assertRaises(PathAccessError):
            self.guard.validate(self.root / "missing" / "file.txt", operation="write", must_exist=False)

    def test_protected_file_rejected(self):
        with self.assertRaisesRegex(PathAccessError, "protected"):
            self.guard.validate(self.protected)

    def test_sensitive_filename_is_denied_unless_policy_explicitly_allows_it(self):
        private_file = self.root / ".env"
        private_file.write_text("TOKEN=value", encoding="utf-8")
        with self.assertRaises(PathAccessError):
            self.guard.open_read(private_file)
        explicit = PathGuard([self.root], allow_protected=True)
        fd = explicit.open_read(private_file)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "TOKEN=value")

    def test_replaced_path_with_symlink_is_denied_before_open(self):
        target = self.root / "race.txt"
        target.write_text("safe", encoding="utf-8")
        self.guard.validate(target)
        target.unlink()
        target.symlink_to(self.outside / "secret.txt")
        with self.assertRaises(PathAccessError):
            self.guard.open_read(target)

    def test_file_replaced_after_validation_is_still_denied(self):
        target = self.root / "raced.txt"
        target.write_text("safe", encoding="utf-8")
        original_open_parent = PathGuard._open_directory_relative

        def replace_before_open(candidate, root):
            target.unlink()
            target.symlink_to(self.outside / "secret.txt")
            return original_open_parent(candidate, root)

        with patch.object(PathGuard, "_open_directory_relative", side_effect=replace_before_open):
            with self.assertRaises(PathAccessError):
                self.guard.open_read(target)

    def test_directory_iteration_uses_lstat_and_skips_symlink_targets(self):
        regular = self.root / "regular.txt"
        regular.write_text("content", encoding="utf-8")
        (self.root / "link.txt").symlink_to(self.outside / "secret.txt")
        entries = {entry.path.name: entry for entry in self.guard.iter_directory(self.root)}
        self.assertIn("regular.txt", entries)
        self.assertIn("link.txt", entries)
        self.assertTrue(stat.S_ISLNK(entries["link.txt"].mode))
        self.assertEqual(entries["regular.txt"].size, len("content"))

    def test_directory_symlink_is_rejected(self):
        (self.root / "outside-dir").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(PathAccessError):
            self.guard.open_directory(self.root / "outside-dir")

    def test_open_write_does_not_replace_existing_file(self):
        target = self.root / "existing.txt"
        target.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.guard.open_write(target)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_publish_file_is_atomic_no_overwrite_and_identity_bound(self):
        temporary = self.root / ".generated.tmp"
        target = self.root / "generated.txt"
        fd = self.guard.open_write(temporary)
        os.write(fd, b"complete")
        os.fsync(fd)
        identity = os.fstat(fd)
        os.close(fd)
        published = self.guard.publish_file(temporary, target, expected=identity)
        self.assertEqual(target.read_bytes(), b"complete")
        self.assertEqual((published.st_dev, published.st_ino), (identity.st_dev, identity.st_ino))
        self.assertFalse(temporary.exists())

        conflict_temp = self.root / ".conflict.tmp"
        fd = self.guard.open_write(conflict_temp)
        os.write(fd, b"replacement")
        identity = os.fstat(fd)
        os.close(fd)
        with self.assertRaises(FileExistsError):
            self.guard.publish_file(conflict_temp, target, expected=identity)
        self.assertEqual(target.read_bytes(), b"complete")
        self.assertTrue(conflict_temp.exists())


if __name__ == "__main__":
    unittest.main()
