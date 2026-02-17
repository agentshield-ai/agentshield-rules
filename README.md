# AgentShield Sigma Rules

A comprehensive collection of Sigma detection rules specifically designed for AI agent security monitoring and threat detection.

## Overview

This repository contains **36 Sigma rules** organized across **12 MITRE ATT&CK categories**, providing comprehensive coverage for AI agent threat detection. These rules cover various attack vectors against AI agents including prompt injection, tool poisoning, credential theft, data exfiltration, privilege escalation, and defense evasion techniques.

The rules are designed for use with the [AgentShield detection engine](https://github.com/agentshield-ai/agentshield-engine) but are compatible with any Sigma-based detection system.

## Rule Statistics

- **Total Rules**: 36
- **Categories**: 12 MITRE ATT&CK tactics  
- **Format**: Standard Sigma YAML
- **Maintenance**: Actively maintained with regular updates

### Rules by Category

| Category | Rule Count | Description |
|----------|------------|-------------|
| **Defense Evasion** | 8 | Memory poisoning, config manipulation, shell modification |
| **Exfiltration** | 5 | DNS tunneling, HTTP exfil, steganography, network uploads |
| **Privilege Escalation** | 4 | Container escape, IAM escalation, system file tampering |
| **Credential Access** | 3 | SSH keys, cloud credentials, environment files |
| **Execution** | 3 | Remote code execution, dangerous commands, session spawn |
| **Persistence** | 3 | Backdoors, rule tampering, MCP manipulation |
| **Prompt Injection** | 3 | Direct jailbreaks, indirect manipulation, tool outputs |
| **Tool Poisoning** | 2 | MCP manipulation, skill tampering, rug pulls |
| **Discovery** | 2 | Network reconnaissance, DNS enumeration |
| **Collection** | 1 | Suspicious file operations to sensitive paths |
| **Initial Access** | 1 | Untrusted package/skill installation |
| **Lateral Movement** | 1 | Agent pivoting and lateral movement |

## Complete Rule Reference

| Rule ID | Title | Category | Severity | Description |
|---------|-------|----------|----------|-------------|
| openclaw-suspicious-file-write-001 | OpenClaw Suspicious File Write to Sensitive Paths | collection | high | Detects OpenClaw file operations targeting sensitive system paths |
| agent-cloud-metadata-access-001 | Cloud Metadata Endpoint Access | credential_access | critical | Detects attempts to access cloud metadata endpoints for credentials |
| agent-credential-access-001 | Credential File Access Attempt | credential_access | high | Detects access to sensitive credential files and environment configs |
| openclaw-credential-access-001 | OpenClaw Credential File Access | credential_access | high | Detects OpenClaw operations accessing SSH keys, certificates, tokens |
| agent-config-autoapprove-001 | Auto-Approve Configuration Changes | defense_evasion | critical | Detects modifications enabling automatic approval of dangerous actions |
| agent-context-poisoning-001 | RAG and Context Manipulation | defense_evasion | high | Detects context poisoning attacks with embedded malicious instructions |
| agent-encoded-payload-001 | Encoded or Obfuscated Command Execution | defense_evasion | high | Detects base64-encoded payloads and obfuscated shell commands |
| agent-env-manip-001 | Environment Variable Manipulation | defense_evasion | high | Detects PATH hijacking, LD_PRELOAD injection, environment tampering |
| agent-mcp-config-manipulation-001 | MCP Configuration File Tampering | defense_evasion | critical | Detects unauthorized modifications to MCP configuration files |
| agent-memory-poisoning-001 | SpAIware-Style Memory Manipulation | defense_evasion | critical | Detects SpAIware-style attacks manipulating AI agent memory |
| agent-shell-config-001 | Shell Configuration Modification | defense_evasion | high | Detects malicious writes to shell startup files (.bashrc, .zshrc) |
| openclaw-memory-poisoning-001 | OpenClaw Memory File Manipulation | defense_evasion | critical | Detects malicious modifications to OpenClaw workspace context files |
| agent-dns-tunnel-001 | Potential DNS Tunneling or Encoded Data Transfer | discovery | medium | Detects DNS-based data exfiltration and tunneling patterns |
| agent-network-recon-001 | Network Reconnaissance Activity | discovery | high | Detects network scanning and reconnaissance activities |
| agent-rce-injection-001 | Remote Code Execution via Piped Script Download | execution | critical | Detects attempts to download and execute remote scripts |
| openclaw-dangerous-exec-001 | OpenClaw Remote Code Execution via Piped Script Download | execution | critical | Detects OpenClaw tool calls downloading and executing remote scripts |
| openclaw-session-spawn-abuse-001 | OpenClaw Suspicious Session Spawn Activity | execution | medium | Detects suspicious OpenClaw session spawning patterns |
| agent-data-exfil-001 | Data Exfiltration via HTTP | exfiltration | critical | Detects data uploads to external URLs via HTTP POST/PUT |
| agent-exfil-via-dns-001 | Enhanced DNS Exfiltration | exfiltration | high | Detects DNS-based data exfiltration and tunneling techniques |
| agent-prompt-injection-exfil-001 | Markdown Image Exfiltration Pattern | exfiltration | critical | Detects data exfiltration via markdown image syntax with encoded URLs |
| agent-steganographic-exfil-001 | Steganographic Data Hiding | exfiltration | high | Detects use of steganographic tools for covert data hiding |
| openclaw-network-exfiltration-001 | OpenClaw Data Exfiltration via Network Upload | exfiltration | medium | Detects OpenClaw operations uploading data to external servers |
| agent-untrusted-skill-install-001 | Untrusted Package or Skill Installation | initial_access | high | Detects installation of packages/skills from untrusted sources |
| agent-lateral-movement-001 | Agent Lateral Movement and Pivoting | lateral_movement | critical | Detects lateral movement patterns where agents pivot to other systems |
| agent-persistence-001 | Persistence Mechanism Installation | persistence | high | Detects attempts to establish persistence through various mechanisms |
| agent-rules-file-backdoor-001 | Hidden Unicode in AI Rule Files | persistence | high | Detects hidden Unicode characters in AI assistant rule files |
| openclaw-mcp-manipulation-001 | OpenClaw MCP Configuration Tampering | persistence | critical | Detects unauthorized modifications to OpenClaw MCP configurations |
| agent-cloud-iam-escalation-001 | Cloud IAM Privilege Escalation | privilege_escalation | critical | Detects cloud IAM operations leading to privilege escalation |
| agent-container-escape-001 | Container Escape Attempt | privilege_escalation | critical | Detects Docker/container escape techniques and attempts |
| agent-privesc-001 | Privilege Escalation Attempt | privilege_escalation | high | Detects sudo usage, setuid changes, ownership modifications |
| agent-sys-tamper-001 | System File Modification | privilege_escalation | critical | Detects writes to critical system directories and binaries |
| agent-prompt-injection-direct-001 | Direct Prompt Injection Attempt | prompt_injection | critical | Detects direct prompt injection with jailbreak phrases |
| agent-prompt-injection-indirect-001 | Indirect Prompt Injection in Retrieved Content | prompt_injection | high | Detects indirect prompt injection markers in retrieved content |
| openclaw-prompt-injection-001 | OpenClaw Prompt Injection in Tool Outputs | prompt_injection | critical | Detects prompt injection attempts within OpenClaw tool responses |
| agent-mcp-rug-pull-001 | MCP Tool Description Changes (Rug Pull) | tool_poisoning | medium | Detects changes in MCP tool descriptions between loads |
| agent-mcp-tool-poisoning-001 | Suspicious MCP Tool Descriptions | tool_poisoning | high | Detects MCP tools with system-level instructions or manipulative content |

## Usage with AgentShield Engine

These rules are optimized for the AgentShield detection engine:

```bash
# Clone the rules repository
git clone https://github.com/agentshield-ai/agentshield-rules.git

# Use with AgentShield engine  
agentshield serve -rules ./agentshield-rules/rules -port 8432

# Validate rules
agentshield rules validate -path ./agentshield-rules/rules

# List loaded rules
agentshield rules list
```

## Rule Format

All rules follow the standard Sigma format with AI-specific enhancements:

```yaml
title: Direct Prompt Injection Attempt
id: agent-prompt-injection-direct-001
status: production
description: |
  Detects direct prompt injection attempts in AI agent inputs containing
  common jailbreak phrases and system override commands.
author: AgentShield Team
date: "2024-01-15"
level: critical
logsource:
  product: ai_agent  
  category: agent_events
tags:
  - attack.initial_access
  - attack.t1190
detection:
  selection:
    event_type: 'user_input'
    message|contains:
      - 'ignore previous instructions'
      - 'you are now' 
      - 'developer mode'
  condition: selection
falsepositives:
  - Legitimate AI safety research
  - Educational content about prompt injection
```

### Key Fields

- **title**: Human-readable rule name
- **id**: Unique identifier following `[platform]-[tactic]-[description]-[number]` format  
- **level**: Severity level (critical, high, medium, low)
- **logsource**: Specifies AI agent log format
- **detection**: Sigma detection logic with AI-specific field names
- **tags**: MITRE ATT&CK technique mappings

## Directory Structure

```
rules/
├── collection/              # Data collection techniques (1 rule)
├── credential_access/       # Credential theft and access (3 rules)  
├── defense_evasion/         # Evasion and hiding techniques (8 rules)
├── discovery/               # Information gathering (2 rules)
├── execution/               # Code execution techniques (3 rules)
├── exfiltration/            # Data exfiltration methods (5 rules)
├── initial_access/          # Initial compromise vectors (1 rule)
├── lateral_movement/        # Movement between systems (1 rule) 
├── persistence/             # Maintaining access (3 rules)
├── privilege_escalation/    # Escalating privileges (4 rules)
├── prompt_injection/        # AI-specific prompt attacks (3 rules)
└── tool_poisoning/          # AI tool manipulation (2 rules)
```

Each directory contains rules specific to that MITRE ATT&CK tactic, organized for easy navigation and management.

## Known Limitations

**Sigmalite `not` Modifier Support**: 3 rules require the `not` modifier which is not yet supported in the sigmalite engine. These rules are marked as `experimental` and will be promoted to `production` status once sigmalite adds this functionality:

- `agent-lateral-movement-001`: Agent Lateral Movement and Pivoting
- `openclaw-memory-poisoning-001`: OpenClaw Memory File Manipulation  
- `agent-context-poisoning-001`: RAG and Context Manipulation

These rules currently use alternative detection logic to work around this limitation.

## Contributing New Rules

We welcome contributions of new detection rules! Please follow these guidelines:

### Rule Development Process

1. **Research the Attack**: Understand the attack technique and how it manifests in AI agent logs
2. **Create Detection Logic**: Write Sigma detection rules following our format
3. **Test Thoroughly**: Validate against both malicious and benign samples
4. **Document False Positives**: Include known false positive scenarios  
5. **Map to MITRE ATT&CK**: Add appropriate technique tags

### Naming Convention

- **Rule ID**: `[platform]-[tactic]-[description]-[number]`
  - Platform: `agent`, `openclaw`, `generic`
  - Tactic: MITRE ATT&CK tactic (lowercase, underscore-separated)
  - Description: Brief technique description (dash-separated)
  - Number: 3-digit sequence starting from 001

- **File Name**: Same as rule ID with `.yml` extension
- **Category Directory**: Place in appropriate MITRE ATT&CK tactic folder

### Quality Standards

- **Accuracy**: Low false positive rate (<5% in testing)
- **Performance**: Rules should execute in <10ms on average
- **Coverage**: Should detect variations of the attack technique
- **Documentation**: Clear description and false positive guidance

### Submission Process

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/new-detection-rule`)
3. Add your rule in the appropriate category directory
4. Update this README if adding a new category
5. Test your rule thoroughly
6. Commit your changes with descriptive messages
7. Push to your branch (`git push origin feature/new-detection-rule`)
8. Open a Pull Request with rule description and test results

## Testing Rules

### Local Testing

```bash
# Validate rule syntax
sigma check rules/

# Test against sample logs
sigma convert -t agentshield rules/prompt_injection/

# Performance testing
agentshield rules benchmark -path rules/
```

### Automated Testing

The repository includes automated testing for:
- Rule syntax validation
- False positive rate testing  
- Performance benchmarking
- MITRE ATT&CK mapping validation

## License

Apache 2.0 - See [LICENSE](LICENSE) file for details.

## Related Projects

- **[AgentShield](https://github.com/agentshield-ai/agentshield)** - Main project and OpenClaw plugin
- **[AgentShield Engine](https://github.com/agentshield-ai/agentshield-engine)** - Go detection engine  
- **[Sigma](https://github.com/SigmaHQ/sigma)** - Original Sigma project and specification

## Acknowledgments

- [Sigma Community](https://github.com/SigmaHQ/sigma) for the detection rule format
- [MITRE ATT&CK](https://attack.mitre.org/) for the threat taxonomy
- AI security researchers and the AgentShield community for rule contributions

---

**Comprehensive detection rules for AI agent security - keeping your agents safe from adversarial attacks.**