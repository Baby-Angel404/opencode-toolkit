"""Unified OpenCode engineering toolkit.

Six independently versionable components behind a single CLI:

* :mod:`opencode_toolkit.security_audit` -- multi-language security auditing
* :mod:`opencode_toolkit.workflow_sync` -- encrypted workflow snapshots and sync
* :mod:`opencode_toolkit.snippet_verified` -- verified production snippet registry
* :mod:`opencode_toolkit.orchestrator` -- multi-agent task orchestration
* :mod:`opencode_toolkit.offline_pack` -- verifiable offline package builder
* :mod:`opencode_toolkit.live_docs` -- documentation drift detection

The runtime has **no third-party dependencies**. Everything is implemented on the
Python standard library, which keeps clean-checkout installs deterministic and
keeps the offline pack free of third-party redistribution questions.
"""

from __future__ import annotations

from opencode_toolkit.core.version import Version, __version__, parse_version

__all__ = ["Version", "__version__", "parse_version"]
