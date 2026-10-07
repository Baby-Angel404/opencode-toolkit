"""Publishing to external platforms.

Two rules govern this package, and both are enforced in code rather than in
documentation prose:

1. **Publishing cannot bypass validation.** Every entry point calls
   :meth:`opencode_toolkit.release.gate.GateResult.publish_permitted` first and
   refuses on anything other than ``PASS``. A blocked gate produces an exit code
   of ``1`` and no network call is attempted.

2. **Missing credentials produce ``SKIP``, never a fake success.** When a token
   is absent the command reports ``SKIP PUBLISH`` and names the exact environment
   variable or GitHub secret required. It never attempts an unauthenticated
   upload and never reports success.

Platform classification is also decided honestly. This project is a *code
repository*, not a model or a dataset, so Hugging Face publishing is
``NOT_APPLICABLE`` unless an operator explicitly opts into a Space. See
:mod:`opencode_toolkit.publishing.classify`.
"""

from __future__ import annotations

from opencode_toolkit.publishing.artifacts import (
    EXCLUDED_PATTERNS,
    SecretScanReport,
    clean_publish_directory,
    scan_for_secrets,
)
from opencode_toolkit.publishing.classify import Classification, classify_project
from opencode_toolkit.publishing.huggingface import (
    HuggingFacePublisher,
    HuggingFaceResult,
    validate_space_metadata,
)
from opencode_toolkit.publishing.kaggle import (
    KagglePublisher,
    KaggleResult,
    validate_dataset_metadata,
)

__all__ = [
    "EXCLUDED_PATTERNS",
    "Classification",
    "HuggingFacePublisher",
    "HuggingFaceResult",
    "KagglePublisher",
    "KaggleResult",
    "SecretScanReport",
    "classify_project",
    "clean_publish_directory",
    "scan_for_secrets",
    "validate_dataset_metadata",
    "validate_space_metadata",
]
