"""Filesystem helpers with explicit, auditable semantics.

Two properties matter here and are relied on across components:

1. **Atomic writes.** Content is written to a temporary file in the destination
   directory, fsync-ed, then ``os.replace``-d over the target. A crash never
   leaves a half-written state file behind.
2. **Explicit conflict detection.** Nothing here ever silently overwrites a
   file the caller did not authorise; :func:`write_new` refuses outright and
   :func:`write_guarded` compares against an expected digest.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any

from opencode_toolkit.core.errors import ConflictError, StorageError

_CHUNK: int = 1 << 16
#: Directories that are never scanned or packaged by default.
DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".eggs",
        "*.egg-info",
        ".idea",
        ".vscode",
        ".opencode",
        "site-packages",
    }
)

#: Binary and media file suffixes that scanning skips outright.
BINARY_SUFFIXES: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".tiff",
        ".pdf",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".tar",
        ".whl",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".bin",
        ".class",
        ".jar",
        ".pyc",
        ".pyo",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".sqlite",
        ".db",
        ".parquet",
        ".arrow",
        ".pt",
        ".pth",
        ".onnx",
        ".safetensors",
        ".lock",
    }
)


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*.

    Args:
        data: bytes: Raw content to hash.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of the file at *path*.

    Args:
        path: Path: File to read; read in chunks so large files do not have to
            fit in memory.

    Raises:
        StorageError: The file cannot be opened or read.
    """
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
    except OSError as exc:
        raise StorageError(
            f"cannot read {path}: {exc.strerror or exc}",
            details={"path": str(path)},
        ) from exc
    return digest.hexdigest()


def is_binary_suffix(path: Path) -> bool:
    """Return ``True`` when *path* has a known binary suffix.

    Args:
        path: Path: Only the suffix is inspected; the file need not exist and
            the match is case-insensitive against :data:`BINARY_SUFFIXES`.
    """
    return path.suffix.lower() in BINARY_SUFFIXES


def looks_binary(data: bytes, *, probe: int = 4096) -> bool:
    """Heuristically decide whether *data* is binary (NUL byte in the probe).

    Args:
        data: bytes: Prefix of the content to classify.
        probe: int: Number of leading bytes examined, in bytes. A value of
            ``0`` inspects nothing and always reports ``False``.
    """
    return b"\x00" in data[:probe]


def ensure_dir(path: Path, *, mode: int = 0o700) -> Path:
    """Create *path* (and parents) if needed and return it.

    A directory this call creates is given *mode* explicitly rather than
    inheriting the umask. A directory holding secrets needs the narrow mode as
    well as its files: ``0600`` on the files inside protects their contents, but a
    world-readable directory still reveals how many snapshots exist and which
    blobs they reference.

    Args:
        path: Path: Directory to create; an existing directory is not an error.
        mode: int: Permission bits for a directory created here. An existing
            directory is left alone: narrowing one would be surprising, and
            widening one would be a security regression.

    Raises:
        StorageError: The directory cannot be created.
    """
    existed = path.is_dir()
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not existed and os.name != "nt":
            path.chmod(mode)
    except OSError as exc:
        raise StorageError(
            f"cannot create directory {path}: {exc.strerror or exc}",
            details={"path": str(path)},
        ) from exc
    return path


def _fsync_dir(directory: Path) -> None:
    # Directory fsync is what makes the rename itself durable. Not available on
    # Windows; the rename is still atomic there, only the durability guarantee
    # is weaker, which is documented rather than silently ignored.
    if os.name == "nt":  # pragma: no cover - platform specific
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - some filesystems refuse this
        pass
    finally:
        os.close(fd)


@contextmanager
def atomic_write(
    path: Path,
    *,
    encoding: str = "utf-8",
    mode: int = 0o644,
    newline: str = "\n",
) -> Iterator[IO[Any]]:
    """Write to *path* atomically; the target is replaced only on success.

    The yielded handle writes into a temporary file in the destination
    directory; the target is replaced only after the block exits without
    raising, and the temporary file is removed if it does.

    Args:
        path: Path: Destination file; parent directories are created if needed.
        encoding: str: Text encoding used to write the handle.
        mode: int: Permission bits applied to the file before it replaces the
            target, e.g. ``0o600`` for owner-only state.
        newline: str: Newline translation passed to :func:`open`; the default
            ``"\n"`` writes newlines unchanged on every platform.

    Yields:
        IO[Any]: An open text handle bound to the temporary file.
    """
    ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(stat.S_IMODE(mode))
        tmp_path.replace(path)
        _fsync_dir(path.parent)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def write_bytes_atomic(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Atomically write raw *data* to *path*.

    Args:
        path: Path: Destination file; parent directories are created if needed.
        data: bytes: Bytes written verbatim.
        mode: int: Permission bits applied before the file replaces the target.

    Raises:
        StorageError: The content cannot be written or replaced.
    """
    ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(stat.S_IMODE(mode))
        tmp_path.replace(path)
        _fsync_dir(path.parent)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def write_text_atomic(path: Path, text: str, *, mode: int = 0o644) -> None:
    """Atomically write *text* to *path* with normalised newlines.

    Args:
        path: Path: Destination file; parent directories are created if needed.
        text: str: Text content written in one call.
        mode: int: Permission bits applied before the file replaces the target.
    """
    with atomic_write(path, mode=mode) as handle:
        handle.write(text)


def write_new(path: Path, text: str, *, mode: int = 0o644) -> None:
    """Create *path* with *text*; never overwrites an existing file.

    Raises :class:`ConflictError` instead of clobbering user content.

    Args:
        path: Path: File to create; it must not already exist.
        text: str: Text content for the new file.
        mode: int: Permission bits applied to the created file.

    Raises:
        ConflictError: *path* already exists.
    """
    if path.exists():
        raise ConflictError(
            f"refusing to overwrite existing file: {path}",
            conflicts=[str(path)],
            hint="choose another destination or remove the file explicitly",
        )
    write_text_atomic(path, text, mode=mode)


def write_guarded(path: Path, text: str, *, expected_sha256: str, mode: int = 0o644) -> None:
    """Overwrite *path* only if its current digest equals *expected_sha256*.

    ``expected_sha256`` of ``"absent"`` requires the file to not exist. This is
    the mechanism behind every "never silently overwrite" guarantee: the caller
    must prove it knows what is currently on disk.

    Args:
        path: Path: File to overwrite once the digest check passes.
        text: str: Replacement content written atomically.
        expected_sha256: str: Lowercase hex digest the file must currently
            have, or the literal ``"absent"`` to require that it does not exist.
        mode: int: Permission bits applied before the file replaces the target.

    Raises:
        ConflictError: The file is missing, or its digest differs from
            *expected_sha256*.
    """
    if expected_sha256 == "absent":
        if path.exists():
            raise ConflictError(
                f"expected {path} to be absent but it exists",
                conflicts=[str(path)],
                hint="run with --force only if replacing this file is intended",
            )
    elif not path.exists():
        raise ConflictError(
            f"expected {path} to exist but it is missing",
            conflicts=[str(path)],
        )
    elif sha256_file(path) != expected_sha256:
        raise ConflictError(
            f"{path} changed on disk since it was read",
            conflicts=[str(path)],
            hint="re-run the command so it re-reads the current state",
        )
    write_text_atomic(path, text, mode=mode)


def iter_files(
    root: Path,
    *,
    exclude_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS,
    follow_symlinks: bool = False,
    max_file_bytes: int = 4 * 1024 * 1024,
) -> Iterator[Path]:
    """Yield every regular file under *root*, honouring the exclusion set.

    Symlinked directories are not descended into by default, which keeps a scan
    from escaping the tree it was pointed at.

    Args:
        root: Path: Directory to walk; resolved before the walk begins.
        exclude_dirs: Iterable[str]: Directory names pruned from the walk at
            every depth. Defaults to :data:`DEFAULT_EXCLUDED_DIRS`.
        follow_symlinks: bool: When ``False``, symlinks are skipped entirely
            and directories are never followed. When ``True``, symlinked files
            are yielded but symlinked directories are still not descended into.
        max_file_bytes: int: Largest file size included, in bytes; bigger files
            are skipped. Raise it to scan content this toolkit would normally
            exclude.

    Yields:
        Path: Each matching file, in a deterministic directory-then-name order.
    """
    excluded = set(exclude_dirs)
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        current = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in excluded)
        for name in sorted(filenames):
            candidate = current / name
            try:
                stat_result = candidate.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(stat_result.st_mode):
                if not follow_symlinks:
                    continue
                if candidate.is_dir():
                    continue
            if stat.S_ISREG(stat_result.st_mode) and stat_result.st_size <= max_file_bytes:
                yield candidate


def relative_paths(root: Path, paths: Iterable[Path]) -> list[str]:
    """Return *paths* as sorted POSIX-style strings relative to *root*.

    Args:
        root: Path: Directory the results are made relative to; resolved first.
        paths: Iterable[Path]: Paths to convert. One outside *root* contributes
            its own POSIX string rather than being dropped.
    """
    resolved_root = root.resolve()
    result = []
    for path in paths:
        try:
            result.append(path.resolve().relative_to(resolved_root).as_posix())
        except ValueError:
            result.append(path.as_posix())
    return sorted(result)


def copy_into(source: Path, destination: Path, *, mode: int | None = None) -> None:
    """Copy *source* to *destination* atomically, preserving nothing but content.

    Args:
        source: Path: File to read; permissions and timestamps are not carried
            over.
        destination: Path: File to write; parent directories are created if
            needed and an existing destination is replaced.
        mode: int | None: Permission bits for the copy, defaulting to ``0o644``
            when ``None``.

    Raises:
        StorageError: The source cannot be read.
    """
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise StorageError(
            f"cannot read {source}: {exc.strerror or exc}",
            details={"path": str(source)},
        ) from exc
    write_bytes_atomic(destination, data, mode=mode if mode is not None else 0o644)
