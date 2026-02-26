# AgentShield Sigma Rules

## What is This Repository?

This repository contains detection rules that help identify when an AI agent is being attacked or manipulated. Think of it as a library of "threat signatures" -- each rule describes a pattern that, when matched against an agent's log data, signals that something suspicious may be happening.

[AgentShield](https://github.com/agentshield-ai/agentshield) is an open-source security layer for AI agents. It monitors agent behaviour in real time and uses these Sigma rules to detect adversarial attacks such as prompt injection, data theft, tool poisoning, and privilege escalation -- before they cause harm.

## What Are Sigma Rules?

Sigma is an open standard used across the cybersecurity industry for writing detection rules. If antivirus signatures tell your computer "this file is malicious", Sigma rules tell your security platform "this pattern of activity in the logs is suspicious".

A Sigma rule is a short YAML file that says: *"If you see **this pattern** in the logs, raise an alert."* For example, a simplified rule might look like:

```
IF the log event is a user_input
AND the message contains "ignore previous instructions"
THEN raise a critical alert for prompt injection
```

Because Sigma is a vendor-neutral standard, these rules work with any Sigma-compatible detection engine -- not just AgentShield. This means security teams can integrate them into their existing tooling without vendor lock-in.

## What Threats Do These Rules Detect?

### Prompt Injection

When someone tries to override an agent's instructions -- either directly (typing "ignore previous instructions") or indirectly (hiding instructions in documents the agent reads).

### Data Theft and Exfiltration

When an agent is tricked into sending sensitive data to an attacker -- via HTTP uploads, DNS tunnelling, hidden markdown images, or steganographic techniques.

### Tool Manipulation and Poisoning

When malicious metadata is hidden in MCP tool descriptions, or tools change their behaviour after being trusted ("rug pull" attacks).

### Credential Theft

When an agent accesses sensitive files like SSH keys, API tokens, cloud credentials, or environment variables containing secrets.

### Privilege Escalation

When an agent tries to gain more access than intended -- via sudo, container escapes, cloud IAM manipulation, or system file tampering.

### Persistence

When an attacker tries to maintain long-term access -- through cron jobs, shell profile modifications, launch agents, or poisoning agent memory.

### Remote Code Execution

When an agent is tricked into downloading and running malicious scripts, establishing reverse shells, or executing obfuscated commands.

### Reconnaissance

When an agent performs network scanning or DNS enumeration to map out a target environment.

### Configuration Tampering

When an agent modifies security-sensitive configuration files to weaken defences -- auto-approve settings, MCP configs, or AI assistant rule files.

### Supply Chain Attacks

When packages or skills are installed from untrusted sources -- direct URLs, GitHub repos, or tarball archives.

## Directory Structure

```
rules/
└── ai_agent/
    ├── ai_agent_prompt_injection_direct.yml
    ├── ai_agent_credential_access.yml
    ├── ai_agent_mcp_tool_poisoning.yml
    └── ... (all rules in one flat directory)
```

Rules are organised by product (`ai_agent`) following [SigmaHQ](https://github.com/SigmaHQ/sigma) conventions. The specific threat category for each rule is captured in the rule's YAML metadata (via MITRE ATT&CK tags and the `logsource` fields), not the directory structure. This flat layout keeps the repository simple and avoids ambiguity when a rule spans multiple attack categories.

## How to Use These Rules

### With AgentShield Engine

```bash
# Clone the rules repository
git clone https://github.com/agentshield-ai/sigma-ai.git

# Use with AgentShield engine
agentshield serve -rules ./sigma-ai/rules -port 8432

# Validate rules
agentshield rules validate -path ./sigma-ai/rules
```

### With General Sigma Tooling

These rules follow the standard Sigma format and can be used with any Sigma-compatible tool:

```bash
# Validate with sigma-cli
sigma check rules/

# Convert to other formats
sigma convert -t <target> rules/ai_agent/
```

## Understanding a Rule

Below is a fully annotated example showing the anatomy of a Sigma rule. Every field is explained in plain English.

```yaml
title: Direct Prompt Injection Attempt          # Human-readable name
id: eddcdc94-698c-577f-900d-28b1b5491a80         # Unique identifier (UUID v5)
related:                                         # Links to related rules
  - id: agent-prompt-injection-direct-001        # Previous ID this replaces
    type: obsoletes
status: stable                                   # Maturity level (see below)
description: |                                   # What this rule detects
  Detects direct prompt injection attempts in AI agent inputs containing
  common jailbreak phrases, system override commands, and policy manipulation
  structures. These patterns indicate attempts to compromise agent behavior
  through malicious instructions.
references:                                      # Further reading
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
author: AgentShield                              # Who wrote this rule
date: "2026-02-16"                               # When it was first written
modified: "2026-02-24"                           # When it was last changed
tags:                                            # MITRE ATT&CK mappings
  - attack.initial_access
  - attack.t1190
logsource:                                       # What log format to expect
  product: ai_agent
  category: agent_events
detection:                                       # The matching logic
  selection_jailbreak_keywords:
    event_type: user_input
    message|contains:
      - 'ignore previous instructions'
      - 'developer mode'
  condition: selection_jailbreak_keywords
falsepositives:                                  # Known benign triggers
  - Legitimate AI safety research
level: critical                                  # Severity (critical/high/medium/low)
```

Here is what each section does:

- **title / id** -- A human-readable name and a globally unique identifier. The UUID ensures rules can be cross-referenced unambiguously across different systems.
- **related** -- Links this rule to others it replaces, extends, or is similar to. Useful for tracking rule lineage as detection logic evolves.
- **status** -- The maturity level of the rule (see [Rule Maturity Levels](#rule-maturity-levels) below).
- **description** -- A prose explanation of what the rule detects and why it matters.
- **references** -- Links to research papers, blog posts, or standards that informed the rule.
- **author / date / modified** -- Provenance metadata: who wrote the rule and when.
- **tags** -- Maps the detection to the [MITRE ATT&CK](https://attack.mitre.org/) framework, linking it to known adversary tactics and techniques.
- **logsource** -- Tells the detection engine what type of log data this rule applies to. Here, `product: ai_agent` with `category: agent_events` means it targets AI agent event logs.
- **detection** -- The core matching logic. Each `selection_*` block defines a set of conditions, and the `condition` field combines them using boolean logic (`and`, `or`, `not`).
- **falsepositives** -- Documents realistic scenarios where the rule might fire on benign activity, helping analysts triage alerts.
- **level** -- The severity of the alert: `critical`, `high`, `medium`, or `low`.

## Rule Maturity Levels

| Level | Meaning |
|-------|---------|
| **stable** | Uses only standard Sigma syntax. Detection logic is well-established and field-tested. Ready for production use. |
| **test** | Detection logic is sound but uses custom extension fields (like `time_window` or `cross_plugin_data_flow`) that require the AgentShield engine. May need adaptation for other platforms. |
| **experimental** | Heavily depends on non-standard fields or relies on workarounds for engine limitations. Expect changes as the detection engine evolves. |

## Custom Extensions

Some rules use fields beyond the standard Sigma specification. These fields require the AgentShield detection engine and are clearly marked with inline comments in each rule.

### Temporal Correlation

- `time_window` -- Time window for correlating sequential events (e.g. `'60s'`)
- `time_between` -- Maximum time between two related events

### Behavioural Analysis

- `cross_plugin_data_flow` -- Detects data flowing between different plugins
- `suspicious_data_pattern` -- Flags suspicious data patterns identified by the engine
- `actual_behavior_matches_description` -- Verifies if a tool's actual behaviour matches its description

### Content Analysis

- `description_similarity_score` -- Similarity score between tool descriptions
- `description_length_ratio` -- Ratio of new description length to original
- `byte_size_to_visible_char_ratio` -- Detects hidden content via byte/character ratio mismatch
- `visibility_analysis` -- Analyses content for hidden text

### Network Analysis

- `query_length` -- DNS query string length
- `subdomain_count` -- Number of subdomains in a DNS query
- `domain_entropy` -- Shannon entropy of domain names

### Context Tracking

- `destination_discovered_recently` -- Whether the target host was recently discovered
- `sensitive_files` -- Whether the operation involves sensitive files
- `parent_agent_context` -- The context of the parent agent
- `hosts_count` -- Number of hosts involved in an operation
- `credential_source` -- Origin of credentials being used

### File Analysis

- `size_increase_ratio` -- Ratio of file size change after modification

Rules using these fields are marked as `test` or `experimental` status to indicate they need engine-specific support.

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Research the attack** -- Understand how the attack manifests in AI agent logs
2. **Follow the Sigma format** -- Use the field ordering shown in "Understanding a Rule"
3. **Test thoroughly** -- Validate against both malicious and benign samples
4. **Document false positives** -- Include realistic scenarios that could trigger the rule
5. **Map to MITRE ATT&CK** -- Add appropriate technique tags
6. **Choose appropriate status** -- Start with `test` or `experimental` for new rules

### File Naming

- Format: `ai_agent_<description>.yml`
- Use lowercase with underscores
- Place all rules in `rules/ai_agent/`

### Submission Process

1. Fork this repository
2. Create a feature branch (`git checkout -b feat/new-detection-rule`)
3. Add your rule following the conventions above
4. Test and validate your rule
5. Open a Pull Request with a description and test results

## Known Limitations

- **Custom field support** -- Rules marked as `test` or `experimental` use custom extension fields that require the AgentShield detection engine. Standard Sigma tools will ignore these fields.
- **`not` modifier** -- A small number of rules use the `not` modifier which may not be supported by all Sigma engines. These rules include alternative detection logic as a workaround.
- **Temporal correlation** -- Rules that detect sequences of events (e.g. "web browse then execute") require an engine capable of stateful, temporal correlation.
- **Behavioural verification** -- Some rules check whether a tool's actual behaviour matches its description. This requires runtime instrumentation beyond simple log matching.

## Licence

Apache 2.0 -- See [LICENSE](LICENSE) file for details.

## Related Projects

- **[AgentShield](https://github.com/agentshield-ai/agentshield)** -- Main project and OpenClaw plugin
- **[AgentShield Engine](https://github.com/agentshield-ai/agentshield-engine)** -- Go detection engine
- **[Sigma](https://github.com/SigmaHQ/sigma)** -- Original Sigma project and specification
- **[MITRE ATT&CK](https://attack.mitre.org/)** -- Threat taxonomy used for rule tagging
- **[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** -- LLM security risks

---

**Detection rules for AI agent security -- keeping your agents safe from adversarial attacks.**
