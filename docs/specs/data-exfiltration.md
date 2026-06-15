---
status: frozen
feature: data-exfiltration
created: 2026-06-15
author: Antigravity
---

# Feature Specification: AI Data Exfiltration Detector

本規格書定義了針對 「經由 AI 管道進行資料外洩 (Data Exfiltration via AI Channel)」之安全檢查器的功能需求與驗收標準。此功能旨在協助開發者檢測專案代碼中，因不安全的 AI 呼叫或 Agent tools 配置所導致的敏感資料洩漏隱患。

This specification outlines the functional requirements and acceptance criteria for the "Data Exfiltration via AI Channel" security detector. The feature aims to help developers audit codebases for sensitive data exposure arising from insecure AI API integrations or Model Context Protocol (MCP) tool configurations.

---

## 1. Goal / 目標

建立一個靜態分析檢查器 `DataExfiltrationDetector`，用於檢測以下三類 AI 管道中的資料外洩風險：
Establish a static analysis detector, `DataExfiltrationDetector`, to identify and mitigate data exfiltration risks across three key AI interaction channels:

1. **LLM API Prompt 洩漏 (LLM API Prompt Exposure)**：檢測程式碼中呼叫大語言模型 API（如 OpenAI, Anthropic, LangChain 等）時，將敏感變數或高熵字串直接作為 prompt/message 的內容傳遞給外部模型。
   Detect instances where sensitive variables, high-entropy credentials, or environmental secrets are passed directly as prompt or message payloads to external LLM APIs (e.g., OpenAI, Anthropic, LangChain).
2. **MCP Tool 檔案洩漏 (MCP Tool Data Exfiltration)**：檢測 MCP (Model Context Protocol) server 工具實作中，讀取本地敏感路徑檔案（如 `.env`, `~/.ssh/`, `~/.aws/`）並將內容直接回傳暴露給外部模型的行為。
   Detect Model Context Protocol (MCP) server tool implementations that read local sensitive files (e.g., `.env`, SSH directory, cloud credentials) and return their raw contents directly, exposing them to the model context.
3. **公開路徑敏感輸出 (Public-Facing Outputs)**：檢測 AI Agent / 工具的輸出檔案被指定寫入至公開目錄（如 `public/`, `dist/`, `static/` 等），特別是當內容包含潛在敏感變數時。
   Warn if AI agents or automated scripts write sensitive variables, credentials, or environment-derived values into web-accessible directories (such as `public/`, `dist/`, `static/`, or `assets/`).

---

## 2. Acceptance Criteria (AC) / 驗收標準

### AC1: LLM API Prompt 洩漏檢測 (Python & JS AST) / LLM API Prompt Exposure Detection
- **檢測對象 (Target APIs)**：檢測呼叫 `openai.chat.completions.create`、`client.messages.create`、`llm.invoke` 等 API 時的參數。
  Intercepts arguments in calls to `openai.chat.completions.create`, `client.messages.create`, `llm.invoke`, and similar endpoints.
- **觸發規則 (Detection Logic)**：若作為 Prompt 輸入的參數/變數滿足以下任一條件，應引發 `HIGH` 級別警告：
  Triggers a `HIGH` severity finding if prompt parameters:
  - 變數名稱包含敏感關鍵字（如 `api_key`, `secret`, `password`, `token`, `private_key`）。
    Reference variables matching sensitive names (e.g., `api_key`, `secret`, `password`, `token`, `private_key`, `credentials`).
  - 字串內容中包含高熵（Shannon Entropy > 4.5）的字串，且疑似硬編碼密鑰。
    Contain hardcoded string literals with high Shannon entropy (> 4.5) matching secret patterns.
  - 直接傳遞讀取自環境變數（如 `os.environ` 或 `process.env`）的敏感 key。
    Directly propagate values read from environment stores (such as `os.environ` or `process.env`).
  - 包含混淆後的雲端中繼資料服務 IP 或主機網域（Metadata SSRF 檢測），支持十進位、十六進位、八進位及 IPv6 映射之 dotted IP 正規化解析（如 AWS/GCP `169.254.169.254`、Azure WireServer `168.63.129.16`、阿里雲 `100.100.100.200`、Oracle `192.0.0.192`）。
    Contain obfuscated cloud metadata service IPs or hostnames (Metadata SSRF Detection), supporting normalization of decimal, hexadecimal, octal, and IPv6-mapped dotted IP formats (e.g., AWS/GCP `169.254.169.254`, Azure WireServer `168.63.129.16`, Alibaba Cloud `100.100.100.200`, Oracle `192.0.0.192`).

### AC2: MCP Tool 檔案外洩檢測 (Python & JS AST) / MCP Tool Data Exfiltration Detection
- **檢測對象 (Target Structures)**：檢測 MCP Server 中定義的工具函數（通常帶有 `@mcp.tool` 裝飾器或 TS 中宣告的 tools 註冊）。
  Analyzes functions decorated with `@mcp.tool`, `fastmcp.tool`, or dynamically registered using MCP SDKs.
- **觸發規則 (Detection Logic)**：
  - **敏感檔案讀取洩漏 (Sensitive File Read Leakage)**：若工具函數的實作邏輯中，同時存在「讀取敏感路徑檔案」（如 `os.path.join(home, '.ssh')`、`.env`、`aws/credentials`）與「回傳檔案內容給呼叫者」的行為，應引發 `CRITICAL` 級別警告。
    Triggers a `CRITICAL` finding if a tool implementation reads files from sensitive paths (e.g., `.env`, SSH directory, AWS credentials) and subsequently returns the raw file contents to the LLM context.
  - **動態參數任意讀取防護 (Dynamic Parameter Arbitrary Read Protection)**：當工具函數接受來自 LLM 外部輸入的動態路徑參數並進行讀取與回傳時，若缺乏路徑安全性校驗邏輯（例如未調用 `is_relative_to`、`realpath`、`abspath` 或未檢查 `".." in path` 等安全防護），應引發 `HIGH` 級別警告。
    Triggers a `HIGH` finding if a tool reads and returns content from a path dynamically received from parameter input without verifying relative safety (e.g., missing checks like `is_relative_to`, `realpath`, `abspath`, or checking `".." in path`).

### AC3: 公開目錄敏感寫入檢測 / Public-Facing Directory Write Auditing
- **檢測對象 (Target Invocations)**：檢測程式碼中的檔案寫入呼叫（如 `open()`, `fs.writeFileSync()`）。
  Monitors file system operations including `open()`, `fs.writeFileSync()`, `pathlib.Path.write_text()`, and `shutil.copy()`.
- **觸發規則 (Detection Logic)**：若寫入的目的地路徑包含 `public/`, `dist/`, `static/`, `assets/` 等網頁伺服器公開目錄，且寫入的內容中包含環境變數或敏感變數，應引發 `MEDIUM` 級別警告。
  Triggers a `MEDIUM` finding when data derived from environment variables or sensitive stores is written to web-accessible public directories (e.g., `public/`, `dist/`, `static/`, `assets/`), accounting for relative path traversal (e.g., `../public`).

### AC4: 誤判過濾與性能優化 / False Positive Mitigation & Performance Scoping
- **預過濾 (Target Scope)**：僅對副檔名為 `.py`, `.js`, `.ts`, `.jsx`, `.tsx` 的程式碼檔案進行掃描。
  Limits scanning strictly to source files with `.py`, `.js`, `.ts`, `.jsx`, `.tsx` extensions to minimize I/O overhead.
- **過濾機制 (Noise Filtering)**：排除了無害的一般變數（例如 `is_active`, `id`, `user_id`, `prompt_template` 本身無敏感前綴字），且路徑匹配排除 `.example`, `.template`, `.dist`, `.pub` 等範本公鑰檔案，以避免對常規 Prompt 呼叫產生大量誤報。
  Excludes common non-sensitive variables (e.g., `is_active`, `id`, `user_id`) and filters out configuration examples, templates, and public keys (e.g., `.env.example`, `id_rsa.pub`) to prevent alert fatigue.

### AC5: 框架整合與標準輸出 / Plugin Architecture & Structured Output
- **整合性 (Integration)**：繼承自 `BaseScannerPlugin`，插件名稱註冊為 `data_exfiltration_detector`。
  Inherits from `BaseScannerPlugin` and integrates dynamically into the main `Scanner` engine under the key `data_exfiltration_detector`.
- **警告格式 (Report Format)**：產生標準 findings JSON 陣列，包括 `file`, `line`, `name`, `severity`, `message`, `suggestion` 等必填欄位。
  Appends findings to the unified JSON schema, specifying `file`, `line`, `name`, `severity`, `message`, and `suggestion` fields.

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
