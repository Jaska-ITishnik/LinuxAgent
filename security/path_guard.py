"""Deny-by-default path authorization with symlink-resistant file opening."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Iterator, Literal


class PathAccessError(PermissionError):
    """A requested filesystem operation is outside the configured policy."""


@dataclass(frozen=True)
class DirectoryEntry:
    """Metadata for a directory child observed without following symlinks."""

    path: Path
    mode: int
    size: int
    modified_time: float


class PathGuard:
    """Restrict file access to explicit roots and reject protected paths/symlinks."""

    _SENSITIVE_NAMES = frozenset({
        ".aws", ".docker", ".env", ".gnupg", ".kube", ".mozilla", ".netrc",
        ".npmrc", ".pki", ".pypirc", ".ssh", "bravesoftware", "chromium",
        "cookies", "cookies.sqlite", "credentials", "credentials.db",
        "credentials.json", "firefox", "google-chrome", "id_ed25519", "id_rsa",
        "key4.db", "logins.json", "login data", "microsoft-edge", "secrets",
    })

    def __init__(
        self,
        allowed_roots: tuple[Path, ...] | list[Path],
        protected_paths: tuple[Path, ...] | list[Path] = (),
        *,
        allow_protected: bool = False,
    ) -> None:
        self.allowed_roots = tuple(Path(root).expanduser().resolve(strict=True) for root in allowed_roots)
        self.protected_paths = tuple(Path(item).expanduser().resolve(strict=False) for item in protected_paths)
        self.allow_protected = allow_protected
        if not self.allowed_roots:
            raise ValueError("At least one explicitly allowed root is required")
        for root in self.allowed_roots:
            if not root.is_dir() or root == Path(root.anchor):
                raise ValueError("Allowed roots must be existing non-root directories")

    @staticmethod
    def _lexical_path(path: str | Path) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            raise PathAccessError("Path must be absolute")
        if ".." in candidate.parts:
            raise PathAccessError("Parent traversal is not allowed")
        return candidate

    def _root_for(self, candidate: Path) -> Path:
        for root in self.allowed_roots:
            if candidate == root or candidate.is_relative_to(root):
                return root
        raise PathAccessError("Path is outside configured allowed roots")

    def _check_protected(self, candidate: Path) -> None:
        if self.allow_protected:
            return
        for protected in self.protected_paths:
            if candidate == protected or candidate.is_relative_to(protected):
                raise PathAccessError("Path is protected by policy")
        if any(part.casefold() in self._SENSITIVE_NAMES for part in candidate.parts):
            raise PathAccessError("Path contains a protected sensitive location")

    @staticmethod
    def _reject_symlink_components(candidate: Path, root: Path) -> None:
        relative = candidate.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            try:
                if current.is_symlink():
                    raise PathAccessError("Symlinks are not allowed for guarded file access")
            except OSError as exc:
                raise PathAccessError("Cannot inspect requested path") from exc

    def validate(
        self,
        path: str | Path,
        *,
        operation: Literal["read", "write", "list"] = "read",
        must_exist: bool = True,
    ) -> Path:
        if operation not in {"read", "write", "list"}:
            raise ValueError("Unsupported filesystem operation")
        lexical = self._lexical_path(path)
        root = self._root_for(lexical)
        self._check_protected(lexical)
        self._reject_symlink_components(lexical, root)
        if must_exist:
            try:
                target = lexical.resolve(strict=True)
            except OSError as exc:
                raise PathAccessError("Requested path does not exist or cannot be accessed") from exc
            if target != lexical:
                raise PathAccessError("Path resolution changed the requested target")
            if operation == "read" and not target.is_file():
                raise PathAccessError("Read target must be a regular file")
            if operation == "list" and not target.is_dir():
                raise PathAccessError("List target must be a directory")
        else:
            parent = lexical.parent
            try:
                resolved_parent = parent.resolve(strict=True)
            except OSError as exc:
                raise PathAccessError("Destination parent must exist") from exc
            if resolved_parent != parent or not parent.is_dir():
                raise PathAccessError("Destination parent is not a safe directory")
        self._root_for(lexical)
        self._check_protected(lexical)
        return lexical

    def open_read(self, path: str | Path) -> int:
        """Open a regular file beneath an allowed root without following symlinks."""
        candidate = self.validate(path, operation="read", must_exist=True)
        root = self._root_for(candidate)
        return self._open_relative(candidate, root, os.O_RDONLY)

    def open_write(self, path: str | Path, *, mode: int = 0o600) -> int:
        """Create a new file beneath an allowed root without replacing existing files."""
        candidate = self.validate(path, operation="write", must_exist=candidate_exists(path))
        root = self._root_for(candidate)
        return self._open_relative(candidate, root, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)

    def open_parent_directory(self, path: str | Path) -> tuple[int, str]:
        """Return a no-follow parent directory descriptor and final path component."""
        candidate = self.validate(path, operation="write", must_exist=False)
        if candidate.name in {"", ".", ".."}:
            raise PathAccessError("Destination must identify a child entry")
        root = self._root_for(candidate)
        return self._open_directory_relative(candidate.parent, root), candidate.name

    def unlink_file(self, path: str | Path, *, expected: os.stat_result | None = None) -> None:
        """Unlink only a regular file beneath an allowed root, optionally by inode identity."""
        parent_fd, name = self.open_parent_directory(path)
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise PathAccessError("Only regular files can be removed by this operation")
            if expected is not None and (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
                raise PathAccessError("File changed before the operation could complete")
            os.unlink(name, dir_fd=parent_fd)
        except OSError as exc:
            if isinstance(exc, PathAccessError):
                raise
            raise PathAccessError("Safe file removal failed") from exc
        finally:
            os.close(parent_fd)

    def publish_file(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        expected: os.stat_result,
    ) -> os.stat_result:
        """Atomically publish a same-directory regular file without replacing a target."""
        source_path = self.validate(source, operation="read", must_exist=True)
        destination_path = self.validate(destination, operation="write", must_exist=False)
        if source_path.parent != destination_path.parent or source_path.name == destination_path.name:
            raise PathAccessError("Atomic publication requires distinct names in the same directory")
        root = self._root_for(source_path)
        if self._root_for(destination_path) != root:
            raise PathAccessError("Atomic publication must remain beneath one allowed root")
        parent_fd = self._open_directory_relative(source_path.parent, root)
        try:
            source_info = os.stat(source_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(source_info.st_mode)
                or (source_info.st_dev, source_info.st_ino) != (expected.st_dev, expected.st_ino)
            ):
                raise PathAccessError("Temporary file changed before publication")
            os.link(
                source_path.name,
                destination_path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            published = os.stat(destination_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(published.st_mode)
                or (published.st_dev, published.st_ino) != (expected.st_dev, expected.st_ino)
            ):
                raise PathAccessError("Published file identity did not match its temporary source")
            try:
                os.unlink(source_path.name, dir_fd=parent_fd)
            except OSError as exc:
                raise PathAccessError("File was published but its temporary name could not be removed") from exc
            return published
        except FileExistsError:
            raise
        except PathAccessError:
            raise
        except OSError as exc:
            raise PathAccessError("Atomic file publication failed") from exc
        finally:
            os.close(parent_fd)

    def create_directory(self, path: str | Path, *, mode: int = 0o700) -> None:
        """Create one authorized directory entry without replacing an existing entry."""
        parent_fd, name = self.open_parent_directory(path)
        try:
            os.mkdir(name, mode=mode, dir_fd=parent_fd)
        except FileExistsError:
            raise
        except OSError as exc:
            raise PathAccessError("Safe directory creation failed") from exc
        finally:
            os.close(parent_fd)

    def remove_directory(self, path: str | Path) -> None:
        """Remove an empty directory entry beneath an allowed root."""
        candidate = self.validate(path, operation="list", must_exist=True)
        if candidate in self.allowed_roots:
            raise PathAccessError("An allowed root cannot be removed")
        root = self._root_for(candidate)
        parent_fd = self._open_directory_relative(candidate.parent, root)
        try:
            info = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise PathAccessError("Only directories can be removed by this operation")
            os.rmdir(candidate.name, dir_fd=parent_fd)
        except OSError as exc:
            if isinstance(exc, PathAccessError):
                raise
            raise PathAccessError("Safe directory removal failed") from exc
        finally:
            os.close(parent_fd)

    def open_directory(self, path: str | Path) -> int:
        """Open an authorized directory by walking from its root without following links."""
        candidate = self.validate(path, operation="list", must_exist=True)
        root = self._root_for(candidate)
        return self._open_directory_relative(candidate, root)

    def iter_directory(self, path: str | Path) -> Iterator[DirectoryEntry]:
        """Yield direct children and lstat metadata from an authorized directory handle."""
        directory_fd = self.open_directory(path)
        try:
            try:
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise PathAccessError("Cannot inspect directory entries") from exc
                        yield DirectoryEntry(
                            path=Path(path) / entry.name,
                            mode=info.st_mode,
                            size=info.st_size,
                            modified_time=info.st_mtime,
                        )
            except OSError as exc:
                raise PathAccessError("Cannot list requested directory") from exc
        finally:
            os.close(directory_fd)

    @staticmethod
    def _open_relative(candidate: Path, root: Path, flags: int, mode: int = 0o600) -> int:
        parts = candidate.relative_to(root).parts
        if not parts:
            raise PathAccessError("A root directory is not a file target")
        directory_fd = PathGuard._open_directory_relative(candidate.parent, root)
        try:
            fd = os.open(parts[-1], flags | os.O_CLOEXEC | os.O_NOFOLLOW, mode, dir_fd=directory_fd)
            stat_result = os.fstat(fd)
            if not stat.S_ISREG(stat_result.st_mode):
                os.close(fd)
                raise PathAccessError("Target must be a regular file")
            return fd
        except FileExistsError:
            raise
        except OSError as exc:
            raise PathAccessError("Safe file open failed") from exc
        finally:
            os.close(directory_fd)

    @staticmethod
    def _open_directory_relative(candidate: Path, root: Path) -> int:
        parts = (*root.parts[1:], *candidate.relative_to(root).parts)
        directory_fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for part in parts:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                os.close(directory_fd)
                directory_fd = next_fd
            result = directory_fd
            directory_fd = -1
            return result
        except OSError as exc:
            raise PathAccessError("Safe directory open failed") from exc
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)


def candidate_exists(path: str | Path) -> bool:
    """Check lexical existence without following symlinks."""
    return Path(path).expanduser().exists() or Path(path).expanduser().is_symlink()
