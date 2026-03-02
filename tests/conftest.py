"""Shared fixtures for Sigma rule conformance tests."""

from pathlib import Path

import pytest
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "ai_agent"


def _load_rule(path: Path) -> dict:
    """Load and parse a single Sigma rule YAML file."""
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def rule_files() -> list[Path]:
    """Return all .yml rule files under rules/ai_agent/."""
    files = sorted(RULES_DIR.glob("*.yml"))
    assert files, f"No .yml files found in {RULES_DIR}"
    return files


@pytest.fixture(scope="session")
def parsed_rules(rule_files: list[Path]) -> list[tuple[Path, dict]]:
    """Return (path, parsed_dict) pairs for every rule."""
    results = []
    for path in rule_files:
        data = _load_rule(path)
        results.append((path, data))
    return results


@pytest.fixture(scope="session")
def stable_rules(parsed_rules: list[tuple[Path, dict]]) -> list[tuple[Path, dict]]:
    """Return only rules with status: stable."""
    return [(p, d) for p, d in parsed_rules if d.get("status") == "stable"]
