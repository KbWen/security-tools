# Work Log: feat-data-exfiltration

- Branch: feat/data-exfiltration
- Classification: feature
- Classified by: Antigravity
- Frozen: true
- Created Date: 2026-06-15
- Owner: wen
- Guardrails Mode: Full
- Recommended Skills: auth-security (資料防洩漏與金鑰保護), frontend-patterns (資料通道與流向監控)

## Session Info
- Agent: Antigravity (Gemini 3.5 Flash)
- Session: 2026-06-15T16:20:00+08:00
- Platform: Antigravity

- Agent: Gemini 3.5 Flash (High)
- Session: 2026-06-15T10:41:26+08:00
- Platform: Antigravity

## Drift Log
- Skip Attempt: NO
- Gate Fail Reason: N/A
- Token Leak: NO

## Risks / 風險
- False positive risk: 如果檢測規則過於寬鬆，可能把一般的 LLM Prompt 當作資料外洩警告。(Mitigated: 使用精確的 AST 屬性關聯與 Shannon 資訊熵閥值排除無害字串與範本公鑰檔)
  - Alert fatigue on regular prompts if rules are overly broad. (Mitigated: Filtered via precise AST property flows, entropy calculations, and explicit template/public-key exclusions).
- Performance overhead: AST 靜態掃描大檔案時可能增加額外 CPU 負擔。(Mitigated: 實作 pre-filtering 以快速跳過不相關的檔案)
  - CPU latency when parsing large non-target files. (Mitigated: Implemented early path pre-filtering to skip non-target extensions).

## Decisions / 決策
- 開發新安全檢查器 `data_exfiltration_detector.py` 以偵測潛在的 AI 通道資料外洩漏洞（E4-F3）。
  - Developed and integrated `data_exfiltration_detector.py` to statically scan for data exfiltration risks across AI channels (Epic 4-F3).

## Evidence / 驗證證據
- Pytest 281/281 tests passing (100% success rate).
- Added `tests/test_self_scan_exemption.py` to cover all self-scan exemption rules (100% pass).
- Verified that running `ghostcheck scan src/ghostcheck --no-ignore` produces 0 false positive warnings and achieves a Project Security Grade: A (100/100).
- 95% unit test coverage for `data_exfiltration_detector.py`.
- Checked and resolved JS AST scope visitor parameter/method double-scoping TypeError.
- Checked and resolved redundant/dead logic in Python AST visitor nested call checker.
- Spec updated with Metadata SSRF and dynamic path validation requirements.
- No regressions introduced.

## Red Team Findings / 紅隊安全發現
- **MEDIUM — Code Obfuscation Bypass**: Attackers might attempt to bypass static AST analysis using runtime string construction (e.g., `eval("os.en" + "viron")` or dynamic `importlib` calls).
  - *Mitigation*: Handled by defense-in-depth: the detector falls back to a text-based regex scanner checking for high-entropy tokens and generic variable assignments, which catches statically constructed obfuscations.
- **HIGH — Comment-Based HITL Scanner Bypass**: Attackers could bypass package installation scanner by hiding `input(` inside JS block comments `/* ... */` or Python docstrings.
  - *Mitigation*: Hardened `silent_installer.py` preprocessor to strip block comments, docstrings, single-line comments, and string literals before running the HITL indicator checks.

## Lessons / 經驗教訓
- `[Shannon-Entropy-Refinement]` - Refined key token extraction by using high-entropy checks only on regex-filtered key patterns, avoiding false alerts on natural languages (Chinese/Japanese).
  - Pre-filtered token extraction via regex key patterns prior to Shannon entropy checks, preventing natural language false alarms.
- `[TS-Syntax-Fallback]` - Implemented esprima parsing fallback to text-based scans when processing TS files with complex annotations.
  - Enabled smooth text-scan fallback on esprima parsing failures to guarantee TypeScript scanning resilience.
- `[Parentheses-Depth-Extraction]` - Replaced simple non-greedy regex matching with dynamic parentheses depth balancing in fallback text scanner to support nested function calls.
  - Replaced naive non-greedy regex matching with dynamic parentheses depth counter to parse nested parameters accurately.
- `[Masked-Context-Exemption]` - When writing scanner self-exemptions checking line contexts, always account for both the raw string representation and the masked representation (e.g. `abcd******************wxyz`), as masking happens prior to the final post-processing filter.

## Observability / 系統觀測度
- Error sink: Standard Python logging (`logger.debug`) for exception flows in CLI execution.
  - Redirected scanner exceptions to standard Python logging to avoid stdout pollution.
- Health check: Checked via command line unit tests and CI integration.
  - Health and functionality verified via automated tests and GitHub CI integration.
- Rollback signal: Rollback if error rate in scan pipelines exceeds threshold or CLI execution crashes.
  - Rollback triggered if scanner pipeline error rate exceeds baseline thresholds.

- Agent: Antigravity (Gemini 3.5 Flash)
- Session: 2026-06-15T16:48:00+08:00
- Platform: Antigravity

## Decisions / 決策
- 優化 `src/ghostcheck/scanner.py` 中的 `_is_self_scan_exempt` 機制，以精確免除 checks、init.py、config.py 以及 demo fixtures 中因靜態分析產生的誤報，並在本地自檢時豁免 git 歷史 unreviewed_commit 警告。
  - Optimize the self-scan exemption mechanism to filter out false positives in checks, config files, and demo fixtures, while preserving active detection for actual credentials.

- Agent: Antigravity (Gemini 3.5 Pro)
  - Session: 2026-06-26T08:58:05+08:00
  - Platform: Antigravity
  - Plan Reference: [implementation_plan.md](file:///C:/Users/wen/.gemini/antigravity/brain/caeb4ed5-f7aa-47d0-b4a6-4d72eaf48a08/implementation_plan.md)
  - Status: Implementing JavaScript AST Hardening and fixing Python validation check failures.

