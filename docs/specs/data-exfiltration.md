---
status: frozen
feature: data-exfiltration
created: 2026-06-15
author: Antigravity
---

# Feature Specification: AI Data Exfiltration Detector

本規格書定義了針對 「經由 AI 管道進行資料外洩 (Data Exfiltration via AI Channel)」之安全檢查器的功能需求與驗收標準。此功能旨在協助開發者檢測專案代碼中，因不安全的 AI 呼叫或 Agent tools 配置所導致的敏感資料洩漏隱患。

This specification defines the functional requirements and acceptance criteria for the "Data Exfiltration via AI Channel" security detector. This feature aims to help developers identify sensitive data leakage risks caused by insecure AI calls or Agent tool configurations in codebase.

---

## 1. Goal / 目標

建立一個靜態分析檢查器 `DataExfiltrationDetector`，用於檢測以下三類 AI 管道中的資料外洩風險：
Build a static analysis detector `DataExfiltrationDetector` to scan for data exfiltration risks across three types of AI channels:

1. **LLM API Prompt 洩漏 (LLM API Prompt Leakage)**：檢測程式碼中呼叫大語言模型 API（如 OpenAI, Anthropic, LangChain 等）時，將敏感變數或高熵字串直接作為 prompt/message 的內容傳遞給外部模型。
   Detect cases where sensitive variables or high-entropy strings are passed directly as prompt/message inputs when calling LLM APIs (e.g., OpenAI, Anthropic, LangChain).
2. **MCP Tool 檔案洩漏 (MCP Tool File Leakage)**：檢測 MCP (Model Context Protocol) server 工具實作中，讀取本地敏感路徑檔案（如 `.env`, `~/.ssh/`, `~/.aws/`）並將內容直接回傳暴露給外部模型的行為。
   Detect instances in MCP (Model Context Protocol) server tool implementations where local sensitive files (e.g., `.env`, `~/.ssh/`, `~/.aws/`) are read and returned directly, exposing them to the LLM.
3. **公開路徑敏感輸出 (Public Directory Output Leakage)**：檢測 AI Agent / 工具的輸出檔案被指定寫入至公開目錄（如 `public/`, `dist/`, `static/` 等），特別是當內容包含潛在敏感變數時。
   Detect file writes by AI agents or tools into public directories (e.g., `public/`, `dist/`, `static/`, `assets/`) when the written content contains sensitive information.

---

## 2. Acceptance Criteria (AC) / 驗收標準

### AC1: LLM API Prompt 洩漏檢測 (Python & JS AST) / LLM API Prompt Leakage Detection
- **檢測對象 (Targets)**：檢測呼叫 `openai.chat.completions.create`、`client.messages.create`、`llm.invoke` 等 API 時的參數。
  Scans parameters of LLM API calls like `openai.chat.completions.create`, `client.messages.create`, `llm.invoke`, etc.
- **觸發規則 (Trigger Rules)**：若作為 Prompt 輸入的參數/變數滿足以下任一條件，應引發 `HIGH` 級別警告：
  Triggers a `HIGH` severity finding if prompt inputs satisfy any of the following:
  - 變數名稱包含敏感關鍵字（如 `api_key`, `secret`, `password`, `token`, `private_key`）。
    Variable names contain sensitive keywords (e.g., `api_key`, `secret`, `password`, `token`, `private_key`).
  - 字串內容中包含高熵（Shannon Entropy > 4.5）的字串，且疑似硬編碼密鑰。
    String content contains high-entropy tokens (Shannon Entropy > 4.5) suggesting hardcoded keys.
  - 直接傳遞讀取自環境變數（如 `os.environ` 或 `process.env`）的敏感 key。
    Directly passes values read from environment variables (e.g., `os.environ` or `process.env`).

### AC2: MCP Tool 檔案外洩檢測 (Python & JS AST) / MCP Tool File Leakage Detection
- **檢測對象 (Targets)**：檢測 MCP Server 中定義的工具函數（通常帶有 `@mcp.tool` 裝飾器或 TS 中宣告的 tools 註冊）。
  Scans tool functions defined in MCP Servers (decorated with `@mcp.tool` or registered via tools SDK).
- **觸發規則 (Trigger Rules)**：若工具函數的實作邏輯中，同時存在「讀取敏感路徑檔案」（如 `os.path.join(home, '.ssh')`、`.env`、`aws/credentials`）與「回傳檔案內容給呼叫者」的行為，應引發 `CRITICAL` 級別警告。
  Triggers a `CRITICAL` severity finding if a tool function contains both a sensitive file read (e.g., `.env`, `.ssh/`, `aws/credentials`) and returns the contents back to the caller.

### AC3: 公開目錄敏感寫入檢測 / Public Directory Sensitive Write Detection
- **檢測對象 (Targets)**：檢測程式碼中的檔案寫入呼叫（如 `open()`, `fs.writeFileSync()`）。
  Scans file write invocations (e.g., `open()`, `fs.writeFileSync()`, `shutil.copy`).
- **觸發規則 (Trigger Rules)**：若寫入的目的地路徑包含 `public/`, `dist/`, `static/`, `assets/` 等網頁伺服器公開目錄，且寫入的內容中包含環境變數或敏感變數，應引發 `MEDIUM` 級別警告。
  Triggers a `MEDIUM` severity finding if the destination path lies within a public directory (e.g., `public/`, `dist/`, `static/`, `assets/`) and the contents contain environment variables or sensitive variables.

### AC4: 誤判過濾與性能優化 / False Positive Reduction & Performance Optimization
- **預過濾 (Pre-filtering)**：僅對副檔名為 `.py`, `.js`, `.ts`, `.jsx`, `.tsx` 的程式碼檔案進行掃描。
  Only scans source code files with extensions `.py`, `.js`, `.ts`, `.jsx`, `.tsx`.
- **過濾機制 (Exclusions)**：排除了無害的一般變數（例如 `is_active`, `id`, `user_id`, `prompt_template` 本身無敏感前綴字），且路徑匹配排除 `.example`, `.template`, `.dist`, `.pub` 等範本公鑰檔案，以避免對常規呼叫產生大量誤報。
  Excludes common non-sensitive variables and filters out template files, examples, and public keys (e.g., `.env.example`, `id_rsa.pub`) to minimize false positives.

### AC5: 框架整合與標準輸出 / Integration & Standard Output
- **整合性 (Integration)**：繼承自 `BaseScannerPlugin`，插件名稱註冊為 `data_exfiltration_detector`。
  Inherits from `BaseScannerPlugin` and registered under the plugin name `data_exfiltration_detector`.
- **警告格式 (Format)**：產生標準 findings JSON 陣列，包括 `file`, `line`, `name`, `severity`, `message`, `suggestion` 等必填欄位。
  Outputs standard findings structure including `file`, `line`, `name`, `severity`, `message`, and `suggestion` fields.

---

## 3. Non-goals / 非目標

- 本檢查器僅做靜態程式碼審計，不提供動態執行期出站流量監控 (DLP) 或網絡防火牆阻斷功能。
  This detector only performs static code auditing. It does not provide runtime outbound data loss prevention (DLP) or network firewall blocking.
- 不提供自動修復（Auto-fix）代碼的功能，僅提供安全修改建議。
  Does not provide auto-remediation features; only provides security recommendations.

---

## 4. Constraints / 限制

- 必須能在無網絡的離線模式下執行，不依賴外部服務進行分析。
  Must execute fully offline without external service dependencies.
- AST 遍歷深度限制為最大 100 層，防止極複雜檔案導致遞迴溢出。
  Recursion traversal limit set to 100 levels to prevent stack overflow on extremely complex AST trees.

---

## 5. File Relationship / 關聯性

- `INDEPENDENT`：本規格書定義的新檢查器是一個獨立的安全功能，但與既有的 `secrets` 密鑰掃描及 `lethal_trifecta` 資料流檢查器互補，共同構成完整的防洩漏規則鏈。
  Complementary to existing secrets scanners and lethal trifecta data flow checkers to build a complete exfiltration defense chain.
