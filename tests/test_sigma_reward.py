"""Tests for the GRPO reward function."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from training.sigma_reward import score_batch, score_rule

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "ai_agent"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PERFECT_RULE = """\
title: Direct Prompt Injection Attempt
id: eddcdc94-698c-577f-900d-28b1b5491a80
status: stable
description: |
  Detects direct prompt injection attempts in AI agent inputs containing
  common jailbreak phrases, system override commands, and policy manipulation.
references:
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
  - https://attack.mitre.org/techniques/T1190/
author: AgentShield
date: "2026-02-16"
tags:
  - attack.initial-access
  - attack.t1190
  - attack.defense-evasion
  - attack.t1027
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection_jailbreak:
    event_type: user_input
    message|contains:
      - 'ignore previous instructions'
      - 'system override'
  selection_encoded:
    event_type: user_input
    message|contains:
      - 'aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=='
  condition: selection_jailbreak or selection_encoded
falsepositives:
  - Legitimate AI safety research discussions
level: critical
"""

MINIMAL_VALID_RULE = """\
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
status: test
description: A minimal test rule for validation.
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection:
    event_type: user_input
  condition: selection
level: medium
"""

BROKEN_YAML = """\
title: Bad Rule
id: not-a-uuid
  status: broken
  [invalid yaml
"""

MISSING_FIELDS_RULE = """\
title: Incomplete Rule
description: Missing many fields.
"""

UNDERSCORE_TAGS_RULE = """\
title: Bad Tag Rule
id: 12345678-1234-1234-1234-123456789abc
status: test
description: Rule with underscore tactic tags.
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection:
    event_type: user_input
  condition: selection
level: medium
"""

BAD_CONDITION_RULE = """\
title: Broken Condition Rule
id: 12345678-1234-1234-1234-123456789abc
status: test
description: Rule where condition references nonexistent keys.
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection_a:
    event_type: user_input
  condition: selection_a or selection_b or selection_c
level: medium
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScoreRule:
    def test_perfect_rule_scores_high(self):
        score = score_rule(PERFECT_RULE)
        assert score >= 0.85, f"Perfect rule should score >=0.85, got {score}"

    def test_broken_yaml_scores_zero(self):
        score = score_rule(BROKEN_YAML)
        assert score == 0.0, f"Broken YAML should score 0.0, got {score}"

    def test_empty_string_scores_zero(self):
        score = score_rule("")
        # Empty string parses as None in YAML
        assert score <= 0.05

    def test_minimal_rule_scores_moderate(self):
        score = score_rule(MINIMAL_VALID_RULE)
        assert 0.40 <= score <= 0.80, (
            f"Minimal valid rule should score 0.40-0.80, got {score}"
        )

    def test_missing_fields_scores_low(self):
        score = score_rule(MISSING_FIELDS_RULE)
        assert score < 0.30, f"Missing-fields rule should score <0.30, got {score}"

    def test_underscore_tags_penalized(self):
        score_bad = score_rule(UNDERSCORE_TAGS_RULE)
        # Fix the tags and compare
        fixed = UNDERSCORE_TAGS_RULE.replace("initial_access", "initial-access")
        score_good = score_rule(fixed)
        assert score_good > score_bad, (
            f"Hyphenated tags ({score_good}) should score higher than "
            f"underscored ({score_bad})"
        )

    def test_bad_condition_partial_credit(self):
        score, details = score_rule(BAD_CONDITION_RULE, return_details=True)
        assert not details["semantics"]["condition_valid"]
        assert len(details["semantics"]["condition_mismatches"]) == 2
        # Should still get partial credit for selection_a being valid
        assert details["semantic_score"] > 0.0

    def test_return_details(self):
        score, details = score_rule(PERFECT_RULE, return_details=True)
        assert isinstance(details, dict)
        assert "syntax_score" in details
        assert "semantic_score" in details
        assert "quality_score" in details
        assert "total" in details
        assert details["total"] == round(score, 4)

    def test_score_bounded_zero_one(self):
        for rule_str in [PERFECT_RULE, MINIMAL_VALID_RULE, BROKEN_YAML, ""]:
            score = score_rule(rule_str)
            assert 0.0 <= score <= 1.0, f"Score {score} out of bounds"


class TestScoreBatch:
    def test_batch_matches_individual(self):
        rules = [PERFECT_RULE, MINIMAL_VALID_RULE, BROKEN_YAML]
        batch_scores = score_batch(rules)
        individual_scores = [score_rule(r) for r in rules]
        assert batch_scores == individual_scores

    def test_batch_with_prompts(self):
        rules = [PERFECT_RULE, MINIMAL_VALID_RULE]
        prompts = ["Detect prompt injection", "Test rule"]
        scores = score_batch(rules, prompts)
        assert len(scores) == 2
        assert all(0.0 <= s <= 1.0 for s in scores)


class TestAgainstExistingRules:
    """Validate that our existing 45 rules score well."""

    @pytest.fixture(scope="class")
    def rule_files(self) -> list[Path]:
        files = sorted(RULES_DIR.glob("*.yml"))
        assert files, f"No rules found in {RULES_DIR}"
        return files

    def test_all_existing_rules_score_above_threshold(self, rule_files):
        failures = []
        for path in rule_files:
            raw = path.read_text(encoding="utf-8")
            score, details = score_rule(raw, return_details=True)
            if score < 0.50:
                failures.append(
                    f"{path.name}: score={score:.3f} "
                    f"(syntax={details['syntax_score']}, "
                    f"semantic={details['semantic_score']}, "
                    f"quality={details['quality_score']})"
                )
        assert not failures, (
            f"{len(failures)} rules scored below 0.50:\n" + "\n".join(failures)
        )

    def test_stable_rules_score_higher(self, rule_files):
        stable_scores = []
        other_scores = []
        for path in rule_files:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
            score = score_rule(raw)
            if data.get("status") == "stable":
                stable_scores.append(score)
            else:
                other_scores.append(score)

        if stable_scores and other_scores:
            avg_stable = sum(stable_scores) / len(stable_scores)
            avg_other = sum(other_scores) / len(other_scores)
            assert avg_stable >= avg_other, (
                f"Stable rules (avg={avg_stable:.3f}) should score >= "
                f"non-stable (avg={avg_other:.3f})"
            )
