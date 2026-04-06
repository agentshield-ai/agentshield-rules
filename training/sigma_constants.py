"""Shared constants and helpers for Sigma rule processing.

Used by both the GRPO reward function and the conformance test suite.
"""

from __future__ import annotations

import re

REQUIRED_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "level",
}

REQUIRED_STABLE_FIELDS = REQUIRED_FIELDS | {
    "author",
    "date",
    "falsepositives",
}

VALID_STATUSES = {"stable", "test", "experimental"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_PRODUCTS = {"ai_agent", "openclaw"}
VALID_CATEGORIES = {"agent_events", "mcp_events"}

SIGMA_CONDITION_KEYWORDS = frozenset(
    {"and", "or", "not", "all", "of", "them", "1", "none"}
)

MITRE_TACTICS = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "command-and-control",
    "resource-development",
    "reconnaissance",
    "impact",
}

IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\*)?)")
UNDERSCORE_TACTIC_RE = re.compile(r"^attack\.\w+_\w+$")
TECHNIQUE_RE = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^attack\.([a-z-]+)$")


def extract_condition_names(condition: str) -> set[str]:
    """Extract selection/filter identifiers from a Sigma condition string.

    Handles wildcard patterns like ``selection_*`` used in
    ``1 of selection_*`` expressions.
    """
    tokens = IDENT_RE.findall(condition)
    return {t for t in tokens if t.lower() not in SIGMA_CONDITION_KEYWORDS}
