"""Dependency licensing policy.

The toolkit has **no runtime third-party dependencies**, so a default pack
bundles only first-party code. When ``include_dependencies`` is enabled the
builder consults this table for each development dependency.

The table is curated, not scraped, and every entry records where the licence text
lives so an operator can check it themselves. A dependency that is not listed is
**not** bundled and is reported as excluded with the reason ``license_unknown``.
That is the conservative behaviour the specification requires: the pack must not
claim a dependency is redistributable unless that has been established.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

#: Reason codes used in exclusion records.
EXCLUDED_UNKNOWN: Final = "license_unknown"
EXCLUDED_RESTRICTED: Final = "license_forbids_redistribution"
EXCLUDED_ATTRIBUTION_REQUIRED: Final = "attribution_not_included"
EXCLUDED_NOT_INSTALLED: Final = "dependency_not_installed"


@dataclass(frozen=True, slots=True)
class LicenseRecord:
    """What is known about one dependency's licence."""

    name: str
    spdx: str
    redistribution: str
    attribution_required: bool
    #: Where the authoritative licence text can be read.
    reference: str
    #: Whether this project has verified the licence. Unverified entries are
    #: never bundled, regardless of the other fields.
    verified: bool = True

    @property
    def may_redistribute(self) -> bool:
        """``True`` only for a verified record whose licence permits bundling.

        An unverified record is never redistributable: an unknown licence is
        treated as "do not ship", not "probably fine".
        """
        return self.verified and self.redistribution in {
            "permitted",
            "permitted-with-attribution",
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the licence record as JSON-serialisable data."""
        return {
            "name": self.name,
            "spdx": self.spdx,
            "redistribution": self.redistribution,
            "attribution_required": self.attribution_required,
            "reference": self.reference,
            "verified": self.verified,
            "may_redistribute": self.may_redistribute,
        }


LICENSE_POLICY: Final[dict[str, LicenseRecord]] = {
    record.name: record
    for record in (
        LicenseRecord(
            name="pytest",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/pytest-dev/pytest/blob/main/LICENSE",
        ),
        LicenseRecord(
            name="pytest-cov",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/pytest-dev/pytest-cov/blob/master/LICENSE",
        ),
        LicenseRecord(
            name="ruff",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/astral-sh/ruff/blob/main/LICENSE",
        ),
        LicenseRecord(
            name="mypy",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/python/mypy/blob/master/LICENSE",
        ),
        LicenseRecord(
            name="build",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/pypa/build/blob/main/LICENSE",
        ),
        LicenseRecord(
            name="pip-audit",
            spdx="Apache-2.0",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/pypa/pip-audit/blob/main/LICENSE",
        ),
        LicenseRecord(
            name="setuptools",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/pypa/setuptools/blob/main/LICENSE",
        ),
        LicenseRecord(
            name="pip",
            spdx="MIT",
            redistribution="permitted",
            attribution_required=True,
            reference="https://github.com/pypa/pip/blob/main/LICENSE",
        ),
        # Present as a reminder that restrictive licences are a real category:
        # none of the toolkit's own dependencies are here, and adding one would
        # require shipping its licence text and reviewing the obligation.
        LicenseRecord(
            name="example-restricted-dependency",
            spdx="LicenseRef-Proprietary",
            redistribution="forbidden",
            attribution_required=True,
            reference="n/a",
            verified=True,
        ),
    )
}

#: Human-readable statement embedded in every manifest.
ATTRIBUTION_NOTICE = (
    "This pack contains first-party code from opencode-toolkit (Apache-2.0). "
    "Third-party components are bundled only when their licence permits "
    "redistribution, as recorded per entry in the manifest's 'licenses' section. "
    "Components with an unknown or restrictive licence are excluded and listed "
    "in 'excluded' with a reason."
)


@dataclass(frozen=True, slots=True)
class RedistributionDecision:
    """Outcome of evaluating one dependency."""

    name: str
    bundled: bool
    reason: str
    spdx: str | None = None
    reference: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the bundling decision and why it was reached."""
        return {
            "name": self.name,
            "bundled": self.bundled,
            "reason": self.reason,
            "spdx": self.spdx,
            "reference": self.reference,
        }


def licence_for(name: str) -> LicenseRecord | None:
    """Return the curated record for *name*, or ``None`` when unknown.

    Args:
        name: str: Package name to look up. It is matched case-insensitively
            with underscores folded to hyphens, so ``my_pkg`` and ``my-pkg``
            resolve identically. An unlisted name returns ``None``, which the
            caller must treat as *do not bundle* rather than as permissive.
    """
    normalised = name.strip().lower().replace("_", "-")
    return LICENSE_POLICY.get(normalised)


def redistribution_decision(
    name: str,
    *,
    installed: bool = False,
    include_attribution: bool = True,
) -> RedistributionDecision:
    """Decide whether *name* may be bundled into a pack.

    Args:
        name: str: Package name, resolved through :func:`licence_for`. Anything
            without a curated record is excluded, never assumed permissive.
        installed: bool: Whether the package is actually present. A redistributable
            licence does not make an absent package bundleable.
        include_attribution: bool: Whether the pack will carry the required
            attribution text. Setting it false excludes components whose licence
            requires attribution rather than bundling them uncredited.
    """
    record = licence_for(name)
    if record is None:
        return RedistributionDecision(
            name=name,
            bundled=False,
            reason=EXCLUDED_UNKNOWN,
            spdx=None,
            reference=None,
        )
    if not record.may_redistribute:
        return RedistributionDecision(
            name=name,
            bundled=False,
            reason=EXCLUDED_RESTRICTED,
            spdx=record.spdx,
            reference=record.reference,
        )
    if record.attribution_required and not include_attribution:
        return RedistributionDecision(
            name=name,
            bundled=False,
            reason=EXCLUDED_ATTRIBUTION_REQUIRED,
            spdx=record.spdx,
            reference=record.reference,
        )
    if not installed:
        return RedistributionDecision(
            name=name,
            bundled=False,
            reason=EXCLUDED_NOT_INSTALLED,
            spdx=record.spdx,
            reference=record.reference,
        )
    return RedistributionDecision(
        name=name,
        bundled=True,
        reason="licence permits redistribution",
        spdx=record.spdx,
        reference=record.reference,
    )


def distribution_licence() -> dict[str, Any]:
    """Return the project's own licence declaration for the manifest."""
    return {
        "project": "opencode-toolkit",
        "spdx": "Apache-2.0",
        "verified": True,
        "reference": "https://www.apache.org/licenses/LICENSE-2.0",
        "notice": ATTRIBUTION_NOTICE,
    }


def third_party_notice(records: list[LicenseRecord]) -> str:
    """Render the third-party attribution block included in every pack.

    Args:
        records: list[LicenseRecord]: Records for bundled components. They are
            sorted by lower-cased name so the text is byte-identical across runs
            for the same input; an empty list renders a fixed "no components"
            sentence instead of an empty heading.
    """
    if not records:
        return "No third-party components are bundled in this pack."
    lines = ["Third-party components bundled in this pack:", ""]
    for record in sorted(records, key=lambda item: item.name.lower()):
        lines.append(f"* {record.name} -- {record.spdx} -- {record.reference}")
    lines.extend(
        [
            "",
            "Each licence permits redistribution; see the reference for the full text.",
        ]
    )
    return "\n".join(lines)
