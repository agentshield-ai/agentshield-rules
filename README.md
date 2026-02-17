# AgentShield Sigma Rules

A comprehensive collection of Sigma detection rules specifically designed for AI agent security monitoring and threat detection.

## Overview

This repository contains 36 Sigma rules organized by MITRE ATT&CK tactics, covering various attack vectors against AI agents including:

- **Prompt Injection**: Direct and indirect manipulation of AI agent inputs
- **Tool Poisoning**: Malicious manipulation of agent tools and capabilities  
- **Credential Access**: Unauthorized access to sensitive credentials and keys
- **Data Exfiltration**: Unauthorized data extraction and transmission
- **Privilege Escalation**: Attempts to gain elevated permissions
- **Defense Evasion**: Techniques to avoid detection
- **Execution**: Malicious code execution attempts
- **And more...**

## Rule Categories

### Collection (1 rules)

- **OpenClaw Suspicious File Write to Sensitive Paths** (`high`) - Detects OpenClaw file write or edit operations targeting sensitive system

### Credential Access (3 rules)

- **Cloud Metadata Endpoint Access** (`critical`) - Detects attempts to access cloud metadata endpoints that could expose
- **Credential File Access Attempt** (`high`) - Detects access to sensitive credential files including environment files,
- **OpenClaw Credential File Access** (`high`) - Detects OpenClaw file read or tool call operations that access sensitive

### Defense Evasion (8 rules)

- **Auto-Approve Configuration Changes** (`critical`) - Detects modifications to configuration files that enable automatic
- **Encoded or Obfuscated Command Execution** (`high`) - Detects base64-encoded payloads piped to shell execution, obfuscated
- **Environment Variable Manipulation** (`high`) - Detects PATH hijacking, LD_PRELOAD injection, and manipulation of
- **MCP Configuration File Tampering** (`critical`) - Detects unauthorized modifications to MCP configuration files including
- **OpenClaw Memory File Manipulation** (`critical`) - Detects malicious modifications to OpenClaw workspace context files
- **RAG and Context Manipulation** (`high`) - Detects context poisoning attacks where instructions are embedded in
- **Shell Configuration Modification** (`high`) - Detects writes to shell startup files (.bashrc, .zshrc, .profile)
- **SpAIware-Style Memory Manipulation** (`critical`) - Detects SpAIware-style attacks that manipulate AI agent memory or

### Discovery (2 rules)

- **Network Reconnaissance Activity** (`high`) - Detects network scanning and reconnaissance activities that may indicate
- **Potential DNS Tunneling or Encoded Data Transfer** (`medium`) - Detects patterns that may indicate DNS-based data exfiltration including

### Execution (3 rules)

- **OpenClaw Remote Code Execution via Piped Script Download** (`critical`) - Detects OpenClaw tool calls that download and execute scripts from remote
- **OpenClaw Suspicious Session Spawn Activity** (`medium`) - Detects OpenClaw session_spawn events and related patterns that may
- **Remote Code Execution via Piped Script Download** (`critical`) - Detects attempts to download and execute scripts from remote sources,

### Exfiltration (5 rules)

- **Data Exfiltration via HTTP** (`critical`) - Detects commands that POST or upload file contents to external URLs,
- **Enhanced DNS Exfiltration** (`high`) - Detects DNS-based data exfiltration techniques including DNS tunneling
- **Markdown Image Exfiltration Pattern** (`critical`) - Detects markdown image syntax with encoded data in URL parameters that
- **OpenClaw Data Exfiltration via Network Upload** (`medium`) - Detects OpenClaw exec tool calls that upload data to external servers
- **Steganographic Data Hiding** (`high`) - Detects the use of steganographic tools and techniques that could be

### Initial Access (1 rules)

- **Untrusted Package or Skill Installation** (`high`) - Detects attempts to install packages or skills from untrusted sources

### Lateral Movement (1 rules)

- **Agent Lateral Movement and Pivoting** (`critical`) - Detects lateral movement patterns where AI agents pivot to other systems

### Persistence (3 rules)

- **Hidden Unicode in AI Rule Files** (`high`) - Detects hidden Unicode characters in AI assistant rule files that could
- **OpenClaw MCP Configuration Tampering** (`critical`) - Detects unauthorized modifications to OpenClaw MCP configuration files
- **Persistence Mechanism Installation** (`high`) - Detects attempts to establish persistence on the system through

### Privilege Escalation (4 rules)

- **Cloud IAM Privilege Escalation** (`critical`) - Detects cloud IAM operations that could lead to privilege escalation
- **Container Escape Attempt** (`critical`) - Detects patterns associated with Docker/container escape techniques
- **Privilege Escalation Attempt** (`high`) - Detects sudo usage, setuid changes, ownership changes to root,
- **System File Modification** (`critical`) - Detects writes to critical system directories and binaries such as

### Prompt Injection (3 rules)

- **Direct Prompt Injection Attempt** (`critical`) - Detects direct prompt injection attempts in AI agent inputs containing
- **Indirect Prompt Injection in Retrieved Content** (`high`) - Detects indirect prompt injection markers in content retrieved by AI agents
- **OpenClaw Prompt Injection in Tool Outputs** (`critical`) - Detects prompt injection attempts within OpenClaw tool call responses

### Tool Poisoning (2 rules)

- **MCP Tool Description Changes (Rug Pull)** (`medium`) - Detects changes in MCP tool descriptions between loads, particularly
- **Suspicious MCP Tool Descriptions** (`high`) - Detects MCP tool descriptions containing system-level instructions,

## Rule Reference

| Rule ID | Title | Category | Severity | Description |
|---------|-------|----------|----------|-------------|
| openclaw-suspicious-file-write-001 | OpenClaw Suspicious File Write to Sensitive Paths | collection | high | Detects OpenClaw file write or edit operations targeting sensitive system |
| agent-cloud-metadata-access-001 | Cloud Metadata Endpoint Access | credential_access | critical | Detects attempts to access cloud metadata endpoints that could expose |
| agent-credential-access-001 | Credential File Access Attempt | credential_access | high | Detects access to sensitive credential files including environment files, |
| openclaw-credential-access-001 | OpenClaw Credential File Access | credential_access | high | Detects OpenClaw file read or tool call operations that access sensitive |
| agent-config-autoapprove-001 | Auto-Approve Configuration Changes | defense_evasion | critical | Detects modifications to configuration files that enable automatic |
| agent-encoded-payload-001 | Encoded or Obfuscated Command Execution | defense_evasion | high | Detects base64-encoded payloads piped to shell execution, obfuscated |
| agent-env-manip-001 | Environment Variable Manipulation | defense_evasion | high | Detects PATH hijacking, LD_PRELOAD injection, and manipulation of |
| agent-mcp-config-manipulation-001 | MCP Configuration File Tampering | defense_evasion | critical | Detects unauthorized modifications to MCP configuration files including |
| openclaw-memory-poisoning-001 | OpenClaw Memory File Manipulation | defense_evasion | critical | Detects malicious modifications to OpenClaw workspace context files |
| agent-context-poisoning-001 | RAG and Context Manipulation | defense_evasion | high | Detects context poisoning attacks where instructions are embedded in |
| agent-shell-config-001 | Shell Configuration Modification | defense_evasion | high | Detects writes to shell startup files (.bashrc, .zshrc, .profile) |
| agent-memory-poisoning-001 | SpAIware-Style Memory Manipulation | defense_evasion | critical | Detects SpAIware-style attacks that manipulate AI agent memory or |
| agent-network-recon-001 | Network Reconnaissance Activity | discovery | high | Detects network scanning and reconnaissance activities that may indicate |
| agent-dns-tunnel-001 | Potential DNS Tunneling or Encoded Data Transfer | discovery | medium | Detects patterns that may indicate DNS-based data exfiltration including |
| openclaw-dangerous-exec-001 | OpenClaw Remote Code Execution via Piped Script Download | execution | critical | Detects OpenClaw tool calls that download and execute scripts from remote |
| openclaw-session-spawn-abuse-001 | OpenClaw Suspicious Session Spawn Activity | execution | medium | Detects OpenClaw session_spawn events and related patterns that may |
| agent-rce-injection-001 | Remote Code Execution via Piped Script Download | execution | critical | Detects attempts to download and execute scripts from remote sources, |
| agent-data-exfil-001 | Data Exfiltration via HTTP | exfiltration | critical | Detects commands that POST or upload file contents to external URLs, |
| agent-exfil-via-dns-001 | Enhanced DNS Exfiltration | exfiltration | high | Detects DNS-based data exfiltration techniques including DNS tunneling |
| agent-prompt-injection-exfil-001 | Markdown Image Exfiltration Pattern | exfiltration | critical | Detects markdown image syntax with encoded data in URL parameters that |
| openclaw-network-exfiltration-001 | OpenClaw Data Exfiltration via Network Upload | exfiltration | medium | Detects OpenClaw exec tool calls that upload data to external servers |
| agent-steganographic-exfil-001 | Steganographic Data Hiding | exfiltration | high | Detects the use of steganographic tools and techniques that could be |
| agent-untrusted-skill-install-001 | Untrusted Package or Skill Installation | initial_access | high | Detects attempts to install packages or skills from untrusted sources |
| agent-lateral-movement-001 | Agent Lateral Movement and Pivoting | lateral_movement | critical | Detects lateral movement patterns where AI agents pivot to other systems |
| agent-rules-file-backdoor-001 | Hidden Unicode in AI Rule Files | persistence | high | Detects hidden Unicode characters in AI assistant rule files that could |
| openclaw-mcp-manipulation-001 | OpenClaw MCP Configuration Tampering | persistence | critical | Detects unauthorized modifications to OpenClaw MCP configuration files |
| agent-persistence-001 | Persistence Mechanism Installation | persistence | high | Detects attempts to establish persistence on the system through |
| agent-cloud-iam-escalation-001 | Cloud IAM Privilege Escalation | privilege_escalation | critical | Detects cloud IAM operations that could lead to privilege escalation |
| agent-container-escape-001 | Container Escape Attempt | privilege_escalation | critical | Detects patterns associated with Docker/container escape techniques |
| agent-privesc-001 | Privilege Escalation Attempt | privilege_escalation | high | Detects sudo usage, setuid changes, ownership changes to root, |
| agent-sys-tamper-001 | System File Modification | privilege_escalation | critical | Detects writes to critical system directories and binaries such as |
| agent-prompt-injection-direct-001 | Direct Prompt Injection Attempt | prompt_injection | critical | Detects direct prompt injection attempts in AI agent inputs containing |
| agent-prompt-injection-indirect-001 | Indirect Prompt Injection in Retrieved Content | prompt_injection | high | Detects indirect prompt injection markers in content retrieved by AI agents |
| openclaw-prompt-injection-001 | OpenClaw Prompt Injection in Tool Outputs | prompt_injection | critical | Detects prompt injection attempts within OpenClaw tool call responses |
| agent-mcp-rug-pull-001 | MCP Tool Description Changes (Rug Pull) | tool_poisoning | medium | Detects changes in MCP tool descriptions between loads, particularly |
| agent-mcp-tool-poisoning-001 | Suspicious MCP Tool Descriptions | tool_poisoning | high | Detects MCP tool descriptions containing system-level instructions, |


## Usage

These rules are designed to be used with the [AgentShield detection engine](https://github.com/agentshield-ai/agentshield-engine).

### With AgentShield Engine

```bash
# Clone the rules repository
git clone https://github.com/agentshield-ai/agentshield-rules.git

# Use with AgentShield engine
agentshield -rules ./agentshield-rules/rules
```

### With Standard Sigma Tools

These rules are compatible with standard Sigma tools and can be converted to various SIEM formats:

```bash
# Convert to Elasticsearch
sigmac -t elasticsearch rules/

# Convert to Splunk
sigmac -t splunk rules/
```

## Rule Development

### Adding New Rules

1. Follow the [Sigma rule format](https://sigmahq.io/docs/basics/rules.html)
2. Place rules in appropriate category directories
3. Use consistent naming: `[platform]_[tactic]_[description].yml`
4. Include proper MITRE ATT&CK tags
5. Set appropriate severity levels

### Testing Rules

Validate rules using the Sigma CLI:

```bash
sigma check rules/
```

## Contributing

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/amazing-rule`)
3. Commit your changes (`git commit -m 'Add amazing detection rule'`)
4. Push to the branch (`git push origin feature/amazing-rule`)
5. Open a Pull Request

## License

Apache 2.0 - See [LICENSE](LICENSE) file for details.

## Related Projects

- [AgentShield](https://github.com/agentshield-ai/agentshield) - Main project and plugin
- [AgentShield Engine](https://github.com/agentshield-ai/agentshield-engine) - Detection engine
- [Sigma](https://github.com/SigmaHQ/sigma) - Original Sigma project
