---
status: frozen
---
# E3-F2: Prompt Template Injection Scanner

## Problem Description
In LLM-based applications, prompt templates (.prompt, .jinja2, etc.) are used to compose instructions dynamically. Without proper isolation boundaries, untrusted user inputs can override the developer's instructions (Prompt Injection).

## Proposed Capabilities
1. **High-Risk Placeholder Detection**: Identify variable names that represent system directives (e.g., `{system}`, `{instructions}`).
2. **Missing Delimiter Warnings**: Warn when user inputs are interpolated without XML tags, triple quotes, horizontal lines, or code blocks.
3. **Insecure Jinja Filters**: Flag uses of `| safe` which bypasses rendering escaping.
4. **Jailbreak Phrasing Detection**: Detect hardcoded override phrases in template content.

## Acceptance Criteria
* [ ] Scans files with extensions `.prompt`, `.jinja`, `.jinja2`, `.tmpl`, `.template`, or files under `prompts/` directories.
* [ ] Detects placeholder variables named after system roles/instructions and flags them with `HIGH` severity.
* [ ] Detects placeholders without delimiters and flags them with `MEDIUM` severity.
* [ ] Detects `| safe` filter usage in Jinja templates and flags it with `HIGH` severity.
* [ ] Detects hardcoded jailbreak phrasing and flags it with `MEDIUM` severity.

## Non-goals
* Establishing external LLM API connections or database queries during scanning.
