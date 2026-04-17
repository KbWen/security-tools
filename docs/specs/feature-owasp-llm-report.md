# Feature Spec: OWASP LLM Compliance Report (E5-F6)

## Overview
This feature integrates the [OWASP Top 10 for LLM Applications (v2025)](https://llmtop10.org/) into GhostCheck's reporting system. It maps GhostCheck's internal security findings to standardized LLM security categories.

## Mapping Table

| OWASP LLM Category | GhostCheck Internal Checks | Description |
|-------------------|----------------------------|-------------|
| **LLM01: Prompt Injection** | `agent_rules`, `mcp_poisoning` | Direct and indirect prompt injection patterns. |
| **LLM02: Sensitive Info Disclosure** | `secrets`, `env_scan`, `data_exfil` | Leakage of PII, secrets, or sensitive project data. |
| **LLM03: Supply Chain Risks** | `hallucinated_package`, `mcp_registry` | Vulnerable AI dependencies or malicious model weights. |
| **LLM06: Excessive Agency** | `excessive_agency`, `mcp_permissions` | Overly broad permissions for AI agents. |
| **LLM09: Misinformation** | `hallucination_checker` | AI hallucinations or package confusion. |

## Implementation Details

### User Interface
- Command: `ghostcheck scan --format owasp-llm`
- Target: Projects using AI agents (AGENTS.md, .cursorrules) or having AI dependencies.

### Output Format
- **Console**: Grouped by category with a summary badge (Passed/Failed).
- **Compliance Score**: Percentage of categories with zero high-severity findings.
- **Remediation**: Standardized advice from OWASP guidelines.

## Technical Architecture
1. **Mapping Engine**: A utility to tag `Finding` objects with OWASP cross-references.
2. **Reporter Class**: A specialty reporter that filters and aggregates findings by these tags.
3. **CLI Extension**: Registration of the new format in the `ReporterFactory`.
