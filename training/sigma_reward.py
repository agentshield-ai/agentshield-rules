"""Reward function for GRPO training of a Sigma rule generator.

Scores a generated Sigma rule on a 0.0–1.0 scale across three dimensions:
  1. Syntactic validity   (0.0–0.30) — Is it parseable, well-formed YAML/Sigma?
  2. Semantic correctness  (0.0–0.40) — Does the detection logic make sense?
  3. Quality & conventions (0.0–0.30) — Does it follow AgentShield style?

The component weights are tuned for GRPO: early training is dominated by
syntax (easy to fix), then semantic and quality signals take over.

Usage::

    from training.sigma_reward import score_rule

    reward = score_rule(generated_yaml_string, prompt_text)
    # reward is a float in [0.0, 1.0]
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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
_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\*)?)")

# MITRE ATT&CK tactic names (hyphenated form)
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

_UNDERSCORE_TACTIC_RE = re.compile(r"^attack\.\w+_\w+$")
_TECHNIQUE_RE = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)
_TACTIC_RE = re.compile(r"^attack\.([a-z-]+)$")


# ---------------------------------------------------------------------------
# Helper: extract condition identifiers (mirrors conftest logic)
# ---------------------------------------------------------------------------


def _extract_condition_names(condition: str) -> set[str]:
    tokens = _IDENT_RE.findall(condition)
    return {t for t in tokens if t.lower() not in SIGMA_CONDITION_KEYWORDS}


# ---------------------------------------------------------------------------
# Component scorers
# ---------------------------------------------------------------------------


def _score_syntax(data: dict | None, raw: str) -> tuple[float, dict[str, Any]]:
    """Score syntactic validity (max 0.30).

    Breakdown:
      - 0.05: valid YAML
      - 0.05: parses to a dict (not a list, string, etc.)
      - 0.05: has all required base fields
      - 0.05: valid UUID in ``id``
      - 0.05: ``status`` is a known value
      - 0.05: ``level`` is a known value
    """
    details: dict[str, Any] = {}
    score = 0.0

    # Valid YAML
    if data is None:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            details["yaml_parse"] = False
            return 0.0, details
    details["yaml_parse"] = True
    score += 0.05

    # Must be a dict
    if not isinstance(data, dict):
        details["is_dict"] = False
        return score, details
    details["is_dict"] = True
    score += 0.05

    # Required base fields
    present = REQUIRED_FIELDS & set(data.keys())
    field_ratio = len(present) / len(REQUIRED_FIELDS)
    field_score = 0.05 * field_ratio
    score += field_score
    details["required_fields_ratio"] = field_ratio
    details["missing_fields"] = sorted(REQUIRED_FIELDS - set(data.keys()))

    # Valid UUID
    rule_id = data.get("id", "")
    try:
        uuid.UUID(str(rule_id))
        score += 0.05
        details["valid_uuid"] = True
    except (ValueError, AttributeError):
        details["valid_uuid"] = False

    # Valid status
    status = data.get("status", "")
    if status in VALID_STATUSES:
        score += 0.05
        details["valid_status"] = True
    else:
        details["valid_status"] = False

    # Valid level
    level = data.get("level", "")
    if level in VALID_LEVELS:
        score += 0.05
        details["valid_level"] = True
    else:
        details["valid_level"] = False

    return score, details


def _score_semantics(data: dict) -> tuple[float, dict[str, Any]]:
    """Score semantic correctness (max 0.40).

    Breakdown:
      - 0.08: logsource has valid product + category
      - 0.10: detection block exists and has at least one selection
      - 0.10: condition references only existing detection keys
      - 0.06: tags include at least one valid MITRE tactic
      - 0.06: tags include at least one valid MITRE technique
    """
    details: dict[str, Any] = {}
    score = 0.0

    # -- Logsource --
    logsource = data.get("logsource", {})
    if isinstance(logsource, dict):
        product = logsource.get("product", "")
        category = logsource.get("category", "")
        if product in VALID_PRODUCTS:
            score += 0.04
            details["valid_product"] = True
        else:
            details["valid_product"] = False
        if category in VALID_CATEGORIES:
            score += 0.04
            details["valid_category"] = True
        else:
            details["valid_category"] = False
    else:
        details["valid_product"] = False
        details["valid_category"] = False

    # -- Detection block --
    detection = data.get("detection", {})
    if isinstance(detection, dict) and "condition" in detection:
        selection_keys = {k for k in detection if k != "condition"}
        if selection_keys:
            score += 0.10
            details["has_selections"] = True
            details["selection_count"] = len(selection_keys)
        else:
            details["has_selections"] = False
            details["selection_count"] = 0

        # -- Condition cross-reference --
        condition = detection["condition"]
        if isinstance(condition, list):
            condition = " ".join(str(c) for c in condition)
        condition = str(condition)

        cond_names = _extract_condition_names(condition)
        mismatches = []
        for name in cond_names:
            if name in selection_keys:
                continue
            if name.endswith("*"):
                prefix = name[:-1]
                if any(k.startswith(prefix) for k in selection_keys):
                    continue
            mismatches.append(name)

        if not mismatches:
            score += 0.10
            details["condition_valid"] = True
        else:
            # Partial credit: fraction of references that resolve
            if cond_names:
                valid_ratio = 1.0 - len(mismatches) / len(cond_names)
                score += 0.10 * max(valid_ratio, 0.0)
            details["condition_valid"] = False
            details["condition_mismatches"] = mismatches
    else:
        details["has_selections"] = False
        details["condition_valid"] = False

    # -- MITRE tags --
    tags = data.get("tags", [])
    if isinstance(tags, list):
        has_tactic = False
        has_technique = False
        underscore_tactics = []

        for tag in tags:
            tag_str = str(tag)
            tactic_m = _TACTIC_RE.match(tag_str)
            if tactic_m and tactic_m.group(1) in MITRE_TACTICS:
                has_tactic = True
            if _TECHNIQUE_RE.match(tag_str):
                has_technique = True
            if _UNDERSCORE_TACTIC_RE.match(tag_str) and not _TECHNIQUE_RE.match(
                tag_str
            ):
                underscore_tactics.append(tag_str)

        if has_tactic:
            score += 0.06
        if has_technique:
            score += 0.06
        # Penalty for underscore tactics (should be hyphens)
        if underscore_tactics:
            score -= 0.03 * min(len(underscore_tactics), 2)

        details["has_tactic_tag"] = has_tactic
        details["has_technique_tag"] = has_technique
        details["underscore_tactics"] = underscore_tactics
    else:
        details["has_tactic_tag"] = False
        details["has_technique_tag"] = False

    return max(score, 0.0), details


def _score_quality(data: dict, prompt: str) -> tuple[float, dict[str, Any]]:
    """Score quality and convention adherence (max 0.30).

    Breakdown:
      - 0.05: title is non-empty and reasonable length (5-120 chars)
      - 0.05: description is non-empty and substantive (>20 chars)
      - 0.05: has falsepositives section (list with entries)
      - 0.05: has references (list with entries)
      - 0.05: detection has multiple selection blocks (specificity)
      - 0.05: author field is present
    """
    details: dict[str, Any] = {}
    score = 0.0

    # -- Title --
    title = data.get("title", "")
    if isinstance(title, str) and 5 <= len(title) <= 120:
        score += 0.05
        details["good_title"] = True
    else:
        details["good_title"] = False

    # -- Description --
    desc = data.get("description", "")
    if isinstance(desc, str) and len(desc.strip()) > 20:
        score += 0.05
        details["good_description"] = True
    else:
        details["good_description"] = False

    # -- Falsepositives --
    fps = data.get("falsepositives", [])
    if isinstance(fps, list) and len(fps) > 0 and all(fps):
        score += 0.05
        details["has_falsepositives"] = True
    else:
        details["has_falsepositives"] = False

    # -- References --
    refs = data.get("references", [])
    if isinstance(refs, list) and len(refs) > 0:
        score += 0.05
        details["has_references"] = True
    else:
        details["has_references"] = False

    # -- Detection specificity (multiple selections) --
    detection = data.get("detection", {})
    if isinstance(detection, dict):
        selection_keys = [k for k in detection if k != "condition"]
        if len(selection_keys) >= 2:
            score += 0.05
            details["multiple_selections"] = True
        else:
            details["multiple_selections"] = False
    else:
        details["multiple_selections"] = False

    # -- Author --
    author = data.get("author", "")
    if isinstance(author, str) and len(author.strip()) > 0:
        score += 0.05
        details["has_author"] = True
    else:
        details["has_author"] = False

    return score, details


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_rule(
    generated_yaml: str,
    prompt: str = "",
    *,
    return_details: bool = False,
) -> float | tuple[float, dict[str, Any]]:
    """Score a generated Sigma rule on a 0.0–1.0 scale.

    Parameters
    ----------
    generated_yaml:
        The raw YAML string produced by the model.
    prompt:
        The original threat description / generation prompt (used for
        relevance scoring in the quality component).
    return_details:
        If True, return ``(score, details_dict)`` instead of just the score.

    Returns
    -------
    float or (float, dict)
        The total reward in [0.0, 1.0], optionally with a breakdown.
    """
    details: dict[str, Any] = {}

    # Attempt parse
    data: dict | None = None
    try:
        data = yaml.safe_load(generated_yaml)
    except yaml.YAMLError:
        data = None

    # Syntax (0.00 – 0.30)
    syntax_score, syntax_details = _score_syntax(data, generated_yaml)
    details["syntax"] = syntax_details
    details["syntax_score"] = round(syntax_score, 4)

    # If we can't even parse it, short-circuit
    if data is None or not isinstance(data, dict):
        total = syntax_score
        details["semantic_score"] = 0.0
        details["quality_score"] = 0.0
        details["total"] = round(total, 4)
        if return_details:
            return total, details
        return total

    # Semantics (0.00 – 0.40)
    semantic_score, semantic_details = _score_semantics(data)
    details["semantics"] = semantic_details
    details["semantic_score"] = round(semantic_score, 4)

    # Quality (0.00 – 0.30)
    quality_score, quality_details = _score_quality(data, prompt)
    details["quality"] = quality_details
    details["quality_score"] = round(quality_score, 4)

    total = syntax_score + semantic_score + quality_score
    # Clamp to [0, 1]
    total = max(0.0, min(1.0, total))
    details["total"] = round(total, 4)

    if return_details:
        return total, details
    return total


def score_batch(
    generated_rules: list[str],
    prompts: list[str] | None = None,
) -> list[float]:
    """Score a batch of generated rules. Convenience for GRPO training loops.

    Parameters
    ----------
    generated_rules:
        List of raw YAML strings.
    prompts:
        Optional list of prompts (same length). If None, empty strings used.

    Returns
    -------
    list[float]
        Rewards in [0.0, 1.0] for each rule.
    """
    if prompts is None:
        prompts = [""] * len(generated_rules)
    return [score_rule(r, p) for r, p in zip(generated_rules, prompts)]
