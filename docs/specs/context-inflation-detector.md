---
status: frozen
title: Context Inflation / Prompt Flooding Detector
source: external
source_doc: _product-backlog.md (E10-F2)
created: 2026-07-01
---

# Context Inflation / Prompt Flooding Detector

## Goal
Implement a security scanner plugin (`ContextInflationDetector`) to detect Context Inflation and Prompt Flooding attacks. These attacks attempt to bypass LLM system instructions or safety filters by flooding the context window with repetitive text, large blocks of whitespace, or invisible zero-width characters.

## Acceptance Criteria
1. **E10-F2 Alignment**: Scan files to detect context inflation and prompt flooding patterns.
2. **Invisible Character Flooding Detection**:
   - Detect consecutive sequences of zero-width or invisible Unicode characters (e.g., `\u200b`, `\u200c`, `\u200d`, `\u200e`, `\u200f`, `\ufeff`, `\u202a`–`\u202e` RTL/LTR overrides, zero-width spaces).
   - Trigger `CRITICAL` finding if a single file contains more than 50 consecutive zero-width/invisible characters, or more than 200 total zero-width/invisible characters (excluding common Markdown syntax or standard formatting if applicable, but strictly flags malicious obfuscation).
3. **Whitespace Padding / Large Gap Detection**:
   - Detect huge blocks of whitespaces, tabs, or newlines designed to push text out of the context window or user screen.
   - Trigger `MEDIUM` finding if there are more than 1000 consecutive whitespace/newline characters without non-whitespace content.
4. **Word Repetition Flooding Detection**:
   - Detect cases where a single word or short phrase (1-3 words) is repeated consecutively or near-consecutively (e.g., "ignore ignore ignore", "hello hello hello").
   - Trigger `HIGH` finding if a word/phrase is repeated consecutively more than 30 times.
5. **Repetitive Line Flooding Detection**:
   - Detect identical lines repeated consecutively.
   - Trigger `HIGH` finding if the same line (ignoring leading/trailing whitespace) is repeated consecutively more than 15 times.
6. **Padding Token Spamming Detection**:
   - Detect excessive repetitions of padding patterns (e.g., `<pad>`, `[PAD]`, `<unk>`, `...`, `---`, `***`, `===`).
   - Trigger `MEDIUM` finding if a file contains more than 50 occurrences of standard padding patterns or dividers in close proximity or within a single file.
7. **Scanner Registry & Integration**:
   - The plugin must be integrated into `PluginManager` and registered under the name `context_inflation_detector`.
   - Appropriate test cases must verify all detection mechanisms against mock payloads.

## Non-goals
- Parsing ASTs for this check: since context inflation and prompt flooding are character/line-level text attacks, a fast text-based scan is sufficient and more performant than AST parsing.
- Correcting or sanitizing the files: the scanner only audits and reports findings; it does not modify the scanned files.

## Constraints
- **Performance**: The linter must perform fast pre-filtering. If none of the inflation characteristics (like zero-width characters, long whitespace blocks, or high repetitions) are present, it should skip the file immediately.
- **Encoding**: Must handle UTF-8 and non-UTF-8 files gracefully without crashing, utilizing safe decoding fallbacks (similar to other scanners in GhostCheck).

## API / Data Contract
The scanner must return findings in the standard GhostCheck finding format:
```json
{
  "file": "path/to/file",
  "line": 12,
  "name": "context_inflation_detected",
  "severity": "CRITICAL | HIGH | MEDIUM",
  "message": "Detailed description of the detected inflation pattern",
  "suggestion": "How to resolve the issue"
}
```

## File Relationship
INDEPENDENT
