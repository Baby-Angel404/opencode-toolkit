"""Read provenance out of a git checkout.

One helper, because two call sites needed the same answer and the second copy
would have needed its own lint exemption for calling ``git`` by name. An
unavailable git is not an error: a source tarball has no ``.git``, and provenance
that cannot be read is simply absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def head_commit(root: Path, *, timeout: int = 15) -> str:
    """Return the commit *root* is checked out at, or ``""`` when unknown.

    Args:
        root: Path: Path: Path: Path: Directory to run ``git rev-parse`` in.
        timeout: int: int: int: int: Seconds to wait before giving up.

    Returns:
    """
    # Resolved to an absolute path rather than left as a bare "git": it is what
    # the subprocess actually runs, and it makes the lookup explicit instead of
    # relying on whatever PATH happens to hold.
    git = shutil.which("git")
    if git is None:
        return ""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [git, "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()
