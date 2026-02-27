"""Sigma rule conformance and quality validation.

Ensures all rules pass ``sigma check -e -i`` (strict mode) and that
stable rules meet SigmaHQ's required/recommended field conventions.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import RULES_DIR

# ---------------------------------------------------------------------------
# Test 1: sigma check strict mode
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("sigma") is None,
    reason="sigma-cli not installed",
)
def test_all_rules_pass_sigma_check() -> None:
    """Every rule must pass ``sigma check -e -i`` (fail on errors AND issues)."""
    result = subprocess.run(
        ["sigma", "check", "-e", "-i", str(RULES_DIR)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"sigma check failed (exit {result.returncode}).\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test 2: required fields for stable rules
# ---------------------------------------------------------------------------

REQUIRED_STABLE_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "level",
    "falsepositives",
}


def test_stable_rules_have_required_fields(
    stable_rules: list[tuple[Path, dict]],
) -> None:
    """Stable rules must include all SigmaHQ required/recommended fields."""
    failures: list[str] = []
    for path, data in stable_rules:
        missing = REQUIRED_STABLE_FIELDS - set(data.keys())
        if missing:
            failures.append(f"{path.name}: missing {sorted(missing)}")

    assert not failures, "Stable rules missing required fields:\n" + "\n".join(
        failures
    )


# ---------------------------------------------------------------------------
# Test 3: stable rules must cite references
# ---------------------------------------------------------------------------


def test_stable_rules_have_references(
    stable_rules: list[tuple[Path, dict]],
) -> None:
    """Stable rules should cite at least one ATT&CK or academic reference."""
    failures: list[str] = []
    for path, data in stable_rules:
        refs = data.get("references")
        if not refs or not isinstance(refs, list) or len(refs) == 0:
            failures.append(path.name)

    assert not failures, "Stable rules without references:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# Test 4: condition ↔ detection key cross-reference
# ---------------------------------------------------------------------------

# Matches bare identifiers in a Sigma condition (selection names / filter names).
# Excludes keywords: and, or, not, all, 1/any of them, of, them.
_SIGMA_KEYWORDS = frozenset(
    {"and", "or", "not", "all", "of", "them", "1", "none"}
)
_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\*)?)")


def _extract_condition_names(condition: str) -> set[str]:
    """Extract selection/filter identifiers from a Sigma condition string.

    Handles wildcard patterns like ``selection_*`` used in
    ``1 of selection_*`` expressions.
    """
    tokens = _IDENT_RE.findall(condition)
    return {t for t in tokens if t.lower() not in _SIGMA_KEYWORDS}


def test_detection_condition_references_exist(
    parsed_rules: list[tuple[Path, dict]],
) -> None:
    """Every identifier in ``condition`` must exist as a key in ``detection``."""
    failures: list[str] = []
    for path, data in parsed_rules:
        detection = data.get("detection", {})
        condition = detection.get("condition", "")
        cond_names: set[str]
        if isinstance(condition, str):
            cond_names = _extract_condition_names(condition)
        else:
            # Multi-line condition (list) — combine
            cond_names = set()
            for line in condition:
                cond_names |= _extract_condition_names(str(line))

        detection_keys = {k for k in detection if k != "condition"}
        # Handle wildcard references like "selection_*" via "… of selection_*"
        # For each condition name, check either exact match or wildcard prefix
        for name in cond_names:
            if name in detection_keys:
                continue
            # Check if it's a wildcard pattern used with "of"
            if name.endswith("*"):
                prefix = name[:-1]
                if any(k.startswith(prefix) for k in detection_keys):
                    continue
            failures.append(
                f"{path.name}: condition references '{name}' "
                f"but detection keys are {sorted(detection_keys)}"
            )

    assert not failures, (
        "Condition ↔ detection mismatches:\n" + "\n".join(failures)
    )


# ---------------------------------------------------------------------------
# Test 5: unique rule IDs
# ---------------------------------------------------------------------------


def test_rule_ids_are_unique(
    parsed_rules: list[tuple[Path, dict]],
) -> None:
    """Every rule must have a globally unique UUID ``id``."""
    seen: dict[str, str] = {}
    duplicates: list[str] = []

    for path, data in parsed_rules:
        rule_id = data.get("id", "")
        if rule_id in seen:
            duplicates.append(
                f"id={rule_id} in both {seen[rule_id]} and {path.name}"
            )
        else:
            seen[rule_id] = path.name

    assert not duplicates, "Duplicate rule IDs:\n" + "\n".join(duplicates)


# ---------------------------------------------------------------------------
# Test 6: no underscore tactic tags (regression guard)
# ---------------------------------------------------------------------------

_UNDERSCORE_TACTIC_RE = re.compile(r"^attack\.\w+_\w+$")


def test_no_underscore_tactic_tags(
    parsed_rules: list[tuple[Path, dict]],
) -> None:
    """Tags must not use underscores in ATT&CK tactic names (use hyphens)."""
    failures: list[str] = []
    for path, data in parsed_rules:
        tags = data.get("tags", [])
        for tag in tags:
            # Only flag tactic-level tags (not technique IDs like attack.t1234)
            if _UNDERSCORE_TACTIC_RE.match(tag) and not re.match(
                r"^attack\.t\d+", tag, re.IGNORECASE
            ):
                failures.append(f"{path.name}: tag '{tag}' uses underscores")

    assert not failures, (
        "Tags with underscores in tactic names:\n" + "\n".join(failures)
    )
