"""Reward function for GRPO training of a Sigma rule generator.

Scores a generated Sigma rule on a 0.0–1.0 scale across three dimensions:
  1. Syntactic validity   (0.0–0.30) — Is it parseable, well-formed YAML/Sigma?
  2. Semantic correctness  (0.0–0.40) — Does the detection logic make sense?
  3. Quality & conventions (0.0–0.30) — Does it follow AgentShield style?

The component weights are tuned for GRPO: early training is dominated by
syntax (easy to fix), then semantic and quality signals take over.

Usage::

    from training.sigma_reward import score_rule

    reward = score_rule(generated_yaml_string)
    # reward is a float in [0.0, 1.0]
"""

from __future__ import annotations

import uuid
from typing import Any

import yaml

from training.sigma_constants import (
    IDENT_RE,
    MITRE_TACTICS,
    REQUIRED_FIELDS,
    SIGMA_CONDITION_KEYWORDS,
    TACTIC_RE,
    TECHNIQUE_RE,
    UNDERSCORE_TACTIC_RE,
    VALID_CATEGORIES,
    VALID_LEVELS,
    VALID_PRODUCTS,
    VALID_STATUSES,
    extract_condition_names,
)


# ---------------------------------------------------------------------------
# Component scorers
# ---------------------------------------------------------------------------


def _score_syntax(data: dict | None) -> tuple[float, dict[str, Any] | None]:
    """Score syntactic validity (max 0.30).

    Returns (score, details_or_None). Details are only built when
    the caller requests them (see ``score_rule``).
    """
    score = 0.0

    if data is None:
        return 0.0, None

    score += 0.05  # valid YAML

    if not isinstance(data, dict):
        return score, None

    score += 0.05  # is a dict

    # Required base fields
    present = REQUIRED_FIELDS & set(data.keys())
    score += 0.05 * len(present) / len(REQUIRED_FIELDS)

    # Valid UUID
    rule_id = data.get("id", "")
    try:
        uuid.UUID(str(rule_id))
        score += 0.05
    except (ValueError, AttributeError):
        pass

    # Valid status
    if data.get("status", "") in VALID_STATUSES:
        score += 0.05

    # Valid level
    if data.get("level", "") in VALID_LEVELS:
        score += 0.05

    return score, None


def _score_semantics(data: dict, selection_keys: set[str]) -> tuple[float, dict[str, Any] | None]:
    """Score semantic correctness (max 0.40)."""
    score = 0.0

    # Logsource
    logsource = data.get("logsource", {})
    if isinstance(logsource, dict):
        if logsource.get("product", "") in VALID_PRODUCTS:
            score += 0.04
        if logsource.get("category", "") in VALID_CATEGORIES:
            score += 0.04

    # Detection selections
    detection = data.get("detection", {})
    if isinstance(detection, dict) and "condition" in detection:
        if selection_keys:
            score += 0.10

        # Condition cross-reference
        condition = detection["condition"]
        if isinstance(condition, list):
            condition = " ".join(str(c) for c in condition)
        condition = str(condition)

        cond_names = extract_condition_names(condition)
        if cond_names:
            mismatches = []
            for name in cond_names:
                if name in selection_keys:
                    continue
                if name.endswith("*"):
                    prefix = name[:-1]
                    if any(k.startswith(prefix) for k in selection_keys):
                        continue
                mismatches.append(name)

            valid_ratio = 1.0 - len(mismatches) / len(cond_names)
            score += 0.10 * max(valid_ratio, 0.0)

    # MITRE tags
    tags = data.get("tags", [])
    if isinstance(tags, list):
        has_tactic = False
        has_technique = False
        underscore_count = 0

        for tag in tags:
            tag_str = str(tag)
            tactic_m = TACTIC_RE.match(tag_str)
            if tactic_m and tactic_m.group(1) in MITRE_TACTICS:
                has_tactic = True
            if TECHNIQUE_RE.match(tag_str):
                has_technique = True
            if UNDERSCORE_TACTIC_RE.match(tag_str) and not TECHNIQUE_RE.match(tag_str):
                underscore_count += 1

        if has_tactic:
            score += 0.06
        if has_technique:
            score += 0.06
        if underscore_count:
            score -= 0.03 * min(underscore_count, 2)

    return max(score, 0.0), None


def _score_quality(data: dict, selection_keys: set[str]) -> tuple[float, dict[str, Any] | None]:
    """Score quality and convention adherence (max 0.30)."""
    score = 0.0

    title = data.get("title", "")
    if isinstance(title, str) and 5 <= len(title) <= 120:
        score += 0.05

    desc = data.get("description", "")
    if isinstance(desc, str) and len(desc.strip()) > 20:
        score += 0.05

    fps = data.get("falsepositives", [])
    if isinstance(fps, list) and len(fps) > 0 and all(fps):
        score += 0.05

    refs = data.get("references", [])
    if isinstance(refs, list) and len(refs) > 0:
        score += 0.05

    if len(selection_keys) >= 2:
        score += 0.05

    author = data.get("author", "")
    if isinstance(author, str) and len(author.strip()) > 0:
        score += 0.05

    return score, None


# ---------------------------------------------------------------------------
# Detail builders (only called when return_details=True)
# ---------------------------------------------------------------------------


def _build_syntax_details(data: dict | None) -> dict[str, Any]:
    details: dict[str, Any] = {}

    if data is None:
        details["yaml_parse"] = False
        return details
    details["yaml_parse"] = True

    if not isinstance(data, dict):
        details["is_dict"] = False
        return details
    details["is_dict"] = True

    present = REQUIRED_FIELDS & set(data.keys())
    details["required_fields_ratio"] = len(present) / len(REQUIRED_FIELDS)
    details["missing_fields"] = sorted(REQUIRED_FIELDS - set(data.keys()))

    rule_id = data.get("id", "")
    try:
        uuid.UUID(str(rule_id))
        details["valid_uuid"] = True
    except (ValueError, AttributeError):
        details["valid_uuid"] = False

    details["valid_status"] = data.get("status", "") in VALID_STATUSES
    details["valid_level"] = data.get("level", "") in VALID_LEVELS

    return details


def _build_semantic_details(data: dict, selection_keys: set[str]) -> dict[str, Any]:
    details: dict[str, Any] = {}

    logsource = data.get("logsource", {})
    if isinstance(logsource, dict):
        details["valid_product"] = logsource.get("product", "") in VALID_PRODUCTS
        details["valid_category"] = logsource.get("category", "") in VALID_CATEGORIES
    else:
        details["valid_product"] = False
        details["valid_category"] = False

    detection = data.get("detection", {})
    if isinstance(detection, dict) and "condition" in detection:
        details["has_selections"] = bool(selection_keys)
        details["selection_count"] = len(selection_keys)

        condition = detection["condition"]
        if isinstance(condition, list):
            condition = " ".join(str(c) for c in condition)
        condition = str(condition)

        cond_names = extract_condition_names(condition)
        mismatches = []
        for name in cond_names:
            if name in selection_keys:
                continue
            if name.endswith("*"):
                prefix = name[:-1]
                if any(k.startswith(prefix) for k in selection_keys):
                    continue
            mismatches.append(name)

        details["condition_valid"] = not mismatches
        if mismatches:
            details["condition_mismatches"] = mismatches
    else:
        details["has_selections"] = False
        details["condition_valid"] = False

    tags = data.get("tags", [])
    if isinstance(tags, list):
        underscore_tactics = [
            str(t) for t in tags
            if UNDERSCORE_TACTIC_RE.match(str(t)) and not TECHNIQUE_RE.match(str(t))
        ]
        details["has_tactic_tag"] = any(
            (m := TACTIC_RE.match(str(t))) and m.group(1) in MITRE_TACTICS
            for t in tags
        )
        details["has_technique_tag"] = any(TECHNIQUE_RE.match(str(t)) for t in tags)
        details["underscore_tactics"] = underscore_tactics
    else:
        details["has_tactic_tag"] = False
        details["has_technique_tag"] = False

    return details


def _build_quality_details(data: dict, selection_keys: set[str]) -> dict[str, Any]:
    title = data.get("title", "")
    desc = data.get("description", "")
    fps = data.get("falsepositives", [])
    refs = data.get("references", [])
    author = data.get("author", "")

    return {
        "good_title": isinstance(title, str) and 5 <= len(title) <= 120,
        "good_description": isinstance(desc, str) and len(desc.strip()) > 20,
        "has_falsepositives": isinstance(fps, list) and len(fps) > 0 and all(fps),
        "has_references": isinstance(refs, list) and len(refs) > 0,
        "multiple_selections": len(selection_keys) >= 2,
        "has_author": isinstance(author, str) and len(author.strip()) > 0,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _get_selection_keys(data: dict) -> set[str]:
    """Extract detection selection keys once, shared across scorers."""
    detection = data.get("detection", {})
    if isinstance(detection, dict):
        return {k for k in detection if k != "condition"}
    return set()


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
        The original threat description / generation prompt. Reserved for
        future relevance scoring; currently unused.
    return_details:
        If True, return ``(score, details_dict)`` instead of just the score.

    Returns
    -------
    float or (float, dict)
        The total reward in [0.0, 1.0], optionally with a breakdown.
    """
    # Parse once
    data: dict | None = None
    try:
        data = yaml.safe_load(generated_yaml)
    except yaml.YAMLError:
        data = None

    # Syntax (0.00 – 0.30)
    syntax_score, _ = _score_syntax(data)

    # Short-circuit if unparseable
    if data is None or not isinstance(data, dict):
        total = syntax_score
        if return_details:
            details = {
                "syntax": _build_syntax_details(data),
                "syntax_score": round(syntax_score, 4),
                "semantic_score": 0.0,
                "quality_score": 0.0,
                "total": round(total, 4),
            }
            return total, details
        return total

    # Compute selection keys once, shared by semantics and quality
    selection_keys = _get_selection_keys(data)

    # Semantics (0.00 – 0.40)
    semantic_score, _ = _score_semantics(data, selection_keys)

    # Quality (0.00 – 0.30)
    quality_score, _ = _score_quality(data, selection_keys)

    total = max(0.0, min(1.0, syntax_score + semantic_score + quality_score))

    if return_details:
        details = {
            "syntax": _build_syntax_details(data),
            "syntax_score": round(syntax_score, 4),
            "semantics": _build_semantic_details(data, selection_keys),
            "semantic_score": round(semantic_score, 4),
            "quality": _build_quality_details(data, selection_keys),
            "quality_score": round(quality_score, 4),
            "total": round(total, 4),
        }
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
