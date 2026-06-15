---
status: frozen
feature: data-exfiltration
created: 2026-06-15
author: Antigravity
---

# Feature Specification: AI Data Exfiltration Detector

本規格書定義了針對 「經由 AI 管道進行資料外洩 (Data Exfiltration via AI Channel)」之安全檢查器的功能需求與驗收標準。此功能旨在協助開發者檢測專案代碼中，因不安全的 AI 呼叫或 Agent tools 配置所導致的敏感資料洩漏隱患。

---

## 1. Goal

建立一個靜態分析檢查器 `DataExfiltrationDetector`，用於檢測以下三類 AI 管道中的資料外洩風險：
1. **LLM API Prompt 洩漏**：檢測程式碼中呼叫大語言模型 API（如 OpenAI, Anthropic, LangChain 等）時，將敏感變數或高熵字串直接作為 prompt/message 的內容傳遞給外部模型。
2. **MCP Tool 檔案洩漏**：檢測 MCP (Model Context Protocol) server 工具實作中，讀取本地敏感路徑檔案（如 `.env`, `~/.ssh/`, `~/.aws/`）並將內容直接回傳暴露給外部模型的行為。
3. **公開路徑敏感輸出**：檢測 AI Agent / 工具的輸出檔案被指定寫入至公開目錄（如 `public/`, `dist/`, `static/` 等），特別是當內容包含潛在敏感變數時。

---

## 2. Acceptance Criteria (AC)

### AC1: LLM API Prompt 洩漏檢測 (Python & JS AST)
- **檢測對象**：檢測呼叫 `openai.chat.completions.create`、`client.messages.create`、`llm.invoke` 等 API 時的參數。
- **觸發規則**：若作為 Prompt 輸入的參數/變數滿足以下任一條件，應引發 `HIGH` 級別警告：
  - 變數名稱包含敏感關鍵字（如 `api_key`, `secret`, `password`, `token`, `private_key`）。
  - 字串內容中包含高熵（Shannon Entropy > 4.5）的字串，且疑似硬編碼密鑰。
  - 直接傳遞讀取自環境變數（如 `os.environ` 或 `process.env`）的敏感 key。

### AC2: MCP Tool 檔案外洩檢測 (Python & JS AST)
- **檢測對象**：檢測 MCP Server 中定義的工具函數（通常帶有 `@mcp.tool` 裝飾器或 TS 中宣告的 tools 註冊）。
- **觸發規則**：若工具函數的實作邏輯中，同時存在「讀取敏感路徑檔案」（如 `os.path.join(home, '.ssh')`、`.env`、`aws/credentials`）與「回傳檔案內容給呼叫者」的行為，應引發 `CRITICAL` 級別警告。

### AC3: 公開目錄敏感寫入檢測
- **檢測對象**：檢測程式碼中的檔案寫入呼叫（如 `open()`, `fs.writeFileSync()`）。
- **觸發規則**：若寫入的目的地路徑包含 `public/`, `dist/`, `static/`, `assets/` 等網頁伺服器公開目錄，且寫入的內容中包含環境變數或敏感變數，應引發 `MEDIUM` 級別警告。

### AC4: 誤判過濾與性能優化 (False Positive Reduction)
- **預過濾**：僅對副檔名為 `.py`, `.js`, `.ts`, `.jsx`, `.tsx` 的程式碼檔案進行掃描。
- **過濾機制**：排除了無害的一般變數（例如 `is_active`, `id`, `user_id`, `prompt_template` 本身無敏感前綴字），以避免對常規 Prompt 呼叫產生大量誤報。

### AC5: 框架整合與標準輸出
- **整合性**：繼承自 `BaseScannerPlugin`，插件名稱註冊為 `data_exfiltration_detector`。
- **警告格式**：產生標準 findings JSON 陣列，包括 `file`, `line`, `name`, `severity`, `message`, `suggestion` 等必填欄位。

---

## 3. Non-goals

- 本檢查器僅做靜態程式碼審計，不提供動態執行期出站流量監控 (DLP) 或網絡防火牆阻斷功能。
- 不提供自動修復（Auto-fix）代碼的功能，僅提供安全修改建議。

---

## 4. Constraints

- 必須能在無網絡的離線模式下執行，不依賴外部服務進行分析。
- AST 遍歷深度限制為最大 100 層，防止極複雜檔案導致遞迴溢出。

---

## 5. File Relationship

- `INDEPENDENT`：本規格書定義的新檢查器是一個獨立的安全功能，但與既有的 `secrets` 密鑰掃描及 `lethal_trifecta` 資料流檢查器互補，共同構成完整的防洩漏規則鏈。
