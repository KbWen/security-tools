# Changelog

## [5.0.0] - 2026-03-05

### 🛡️ Runtime v5 Anti-Drift & Concurrency Release

- **Gate Engine & Handshake**: Implemented a hard-path enforcement overlay for `plan`, `ship`, and `implement` workflows. High-risk tasks now require explicit `PROCEED-<STAGE>:<branch>` contextual handshakes to continue.
- **Skill Safety Guardrails**: Established strict precedence (`AGENTS.md` > `workflows` > `skills`) to prevent Antigravity semantic skills from hijacking execution loops.
- **Multi-Session Concurrency**: Added `Owner` and `Session` metadata requirements to Work Logs. `/bootstrap` now checks for concurrent edits to prevent collisions.
- **Legacy Migration Safety**: Introduced the `/audit` workflow for read-only system mapping of non-AgentCortex repos.
- **SSoT Append-only History**: Changed `current_state.md` to use an append-only `## Ship History` for safer archival.
- **Sentinel Token**: Injected `SENTINEL: ACX-READ-OK` to combat context truncation.

## [3.5.4] - 2026-03-04

### 🔌 External Tool Integration (Natural Language Driven)

- **ask-openrouter workflow**: New `[OPTIONAL MODULE]` workflow (`.agent/workflows/ask-openrouter.md`) enabling natural language delegation to OpenRouter models. Features 3-layer architecture: Intent Router, Pre/Post-Flight, and Dynamic Parameter Assembly.
- **codex-cli alignment**: Updated `codex-cli.md` with `[OPTIONAL MODULE]` tag, silent availability check, and `§8.2` reference for consistency.
- **§8.2 External Tool Delegation Protocol**: New section in `engineering_guardrails.md` defining shared rules for all external CLI tools — silent availability check, cost-tier confirmation, and mandatory Pre/Post-Flight.
- **Graceful degradation**: Users without external tools experience zero disruption — AI silently falls back to native execution.
- **Deploy script**: Bumped to v3.5.4. Added `.openrouter/` to gitignore template.
- **SSoT update**: Registered both tools as `[OPTIONAL]` in `current_state.md` Canonical Commands.

## [3.5.2] - 2026-02-27

### ⚖️ Governance Refinement & Directory Polish

- **指令語義優化**: 修正 `/test-skeleton` 的啟動狀態門檻為 `IMPLEMENTABLE`；為 `/implement` 與 `/execute-plan` 加入硬性進入條件提示（state machine 對齊）。
- **平台技能隔離**: 更新 `AGENTS.md` 與 `README.md`，明確區分 `.agent/skills` 與 `.agents/skills` 為平台獨立目錄，取消自動符號連結以增加配置彈性。
- **Token 反思機制**: 在 `/handoff` 工作流加入 `Token & Efficiency Reflection` 區塊，落實自我管理哲學。
- **清理修復**: 移除了已棄用的 `.agent/workflows/` 冗餘檔案（`update-docs.md`, `docs-update.md`）。

## [3.5.1] - 2026-02-27

### 🛠️ Directory Structure & Multi-Platform Support

- **部署升級**: `deploy_brain.sh` 升級為 v3.5.1，全面支援 vNext 目錄結構。
- **文件策略修復**: 修正 `AGENTS.md` 中的「盲目掃描」反模式，改為基於 `current_state.md` 的精準讀取。
- **Token 極致壓縮**: `rules.md` 與 `AGENTS.md` 完成大幅度內縮優化，節省每回合啟動開銷。

## [3.5.0] - 2026-02-27

### 🚀 vNext Self-Managed Architecture Release

- **SSoT 狀態模型**: 導入 `docs/context/current_state.md` 作為唯一真實來源，任務隔離於 `docs/context/work/` 目錄。
- **工作流全面遷移**: 所有 superpowers 遷移至 `.agent/workflows/`，對齊 Google Antigravity 原生指令。
- **任務分類凍結**: `/bootstrap` 現在強制執行任務分類並凍結，防止開發路徑偏離。
- **遷移工具**: 新增 `docs/guides/migration.md`，支援從舊版 v3.0 無縫升級。

## [3.4.0] - 2026-02-23

### 🚀 Release v3.4.0 (Version Sync + Practical Examples)

- **版本同步**: `README.md`、`.agent/AGENT.md`、`deploy_brain.sh` 全面升級為 v3.4.0。
- **實戰範例**: 新增 `docs/PROJECT_EXAMPLES.md`，提供 Node.js（Express + Vitest）與 Python（FastAPI + pytest）導入流程。
- **部署擴充**: `deploy_brain.sh` 現在會部署 `docs/PROJECT_EXAMPLES.md`。
- **驗證強化**: `validate.sh` 新增 `PROJECT_EXAMPLES.md` 存在檢查，並驗證 README 已連結範例文件。

## [3.3.1] - 2026-02-23

### 🔧 Superpowers Features Completion & README Clarity

- **功能補齊**: 新增 `.agent/superpowers/features/` 模組，包含 `brainstorm`, `research`, `spec`, `execute`, `review`, `retro` 六種能力檔案。
- **指令擴充**: `.agent/superpowers/commands.md` 新增 `/brainstorm`, `/research`, `/spec`, `/retro` 指令模板。
- **工作流深化**: `.agent/superpowers/workflows.md` 納入探索型開發節奏（Idea → Spec → Plan → Implement → Review/Test）。
- **操作文件強化**: `README.md` 補上「原始操作流程」與「如何呼叫各功能檔案」的完整範例。
- **部署修正**: `deploy_brain.sh` 支援部署 `.agent/superpowers/features/*.md`。
- **可用性驗證**: 新增 `/.agent/superpowers/validate.sh`，可一鍵檢查指令、功能檔與 README 對應是否一致。
- **命名一致性**: 新增 `features/implement.md` 並將 `execute.md` 改為相容別名，避免 `/implement` 指令對不上檔名。
- **能力補齊**: 新增 `features/bootstrap.md`（任務啟動）與 `features/handoff.md`（跨回合交接）。
- **Codex 平台相容**: 新增 `docs/CODEX_PLATFORM_GUIDE.md`，提供 Web 與 App 兩端一致操作建議。
- **參考來源標註**: README 新增 Superpowers 原始專案連結，明確標示設計參考來源。
- **規範稽核強化**: `validate.sh` 新增平台文件與 AGENT 引用檢查，並驗證 README 含參考來源。
- **流程強制化**: 新增 `policies/methodology.md` 與 `policies/state_machine.md`，導入 workflow gate 與完成條件。
- **Codex 入口**: 新增 `.codex/INSTALL.md`，支援一句話「Fetch and follow instructions ...」載入流程。
- **指令別名**: 新增 `/write-plan`、`/execute-plan` 對齊 Superpowers 常見命名。

## [3.3.0] - 2026-02-23

### 🧩 Superpowers Alignment for Google Antigravity

- **流程升級**: `README.md` 改版為 Antigravity Superpowers Edition，加入 Plan → Implement → Review → Test 的標準節奏。
- **Agent 強化**: `.agent/AGENT.md` 新增 Superpowers 導向執行模式，明確化可重複操作流程。
- **Prompt 工具箱**: 新增 `.agent/superpowers/commands.md`，提供可直接貼用的高訊噪比指令模板。
- **工作流卡片**: 新增 `.agent/superpowers/workflows.md`，涵蓋小修補、中型功能、Hotfix 與文件治理場景。
- **部署腳本更新**: `deploy_brain.sh` 支援部署 `.agent/superpowers/` 內容與 v3.3 版本訊息。

## [3.2.0] - 2026-02-14

### 🧪 Zero-Token Enhancements (零成本工作流強化)

- **品質閘門**: 新增 `.github/PULL_REQUEST_TEMPLATE.md`，標準化 AI 的產出總結與自檢項目。
- **測試規範**: 新增 `docs/TESTING_PROTOCOL.md`，提供邊際情況與錯誤處理的測試標準，採 Opt-in (手動呼叫) 模式以節省 Token。
- **部署擴充**: `deploy_brain.sh` 現在完整支援所有 v3.2 文檔與模板。

## [3.1.0] - 2026-02-14

### ⚖️ Agent-First Constitution (憲法級架構)

- **憲法層級**: 新增 `.agent/rules/engineering_guardrails.md`，定義 Agent 不可違背的工程準則。
- **協作介面**: 新增 `.github/ISSUE_TEMPLATE/agent_issue.md`，將任務描述結構化。
- **角色 manifest**: 新增 `docs/AGENT_PHILOSOPHY.md`，定義 AI 與人類的協作邊界。
- **腳本優化**: `deploy_brain.sh` 支援部署隱藏資料夾（.github）與文檔。

## [3.0.0] - 2026-02-14

### 🪶 Pragmatic Lean (務實精小版)

- **Radical Simplification**: 將 40+ 個檔案整理為 1 個核心 Prompt (`AGENT.md`)，系統提示開銷降低 94%。
- **Antigravity-Native**: 專位 Google Antigravity 打造，利用 IDE 自動讀取 `.agent/` 目錄的特點，減少手動配置。
- **Human-Centric Guidance**: 移除無效的自動路由，改由 `AGENT_MODEL_GUIDE.md` 指引用戶手動切換模型，確保正確使用 Flash/Pro/Advanced 模型。
- **Audit Implementation**: 合併精華版 PII 掩碼、Secrets 偵測與編碼規範。

## [2.6.5] - 2026-02-13

### 🚀 Flash-First Strategy (重大策略轉變)

- **架構反轉**: 核心邏輯改為以 Flash 為主體，處理 80% 低成本任務。
- **升級請求 (Escalation)**: 當背景超出 Flash 負荷時，模型會主動停止並提示切換至 Pro，確保 100% 節省 Pro Token。
- **新版 README**: 強調操作流程的改變，降低 Token 誤用風險。

## [2.5.1] - 2026-02-13

### 🛡️ Security & Language

- **強制語言**: 全局強制使用繁體中文 (台灣) 進行對話。
- **隱私加固**: `08_compliance` 加入 PII 掩碼規則。
- **漏洞掃描**: `08_code_review` 加入 OWASP Top 10 與 Secrets 掃描指南。

## [2.5.0] - 2026-02-13

### ✨ Added

- **重大升級**: 正式進入工業級架構 (Industrial-Grade)。
- **元數據驅動**: 全檔案加入 YAML frontmatter 支援元數據解析。
- **精細化 Thresholds**: 支援各工作流自定義 Token 閾值，極大化節省成本。
- **新增 4 大工作流**: 工程開發 (`01`)、內容創作 (`10`)、數據報表 (`11`)、環境自檢 (`12`)。
- **新增 3 大規則**: 安全合規 (`08`)、格式標准 (`09`)、指令設計 (`10`)。
- **新增 3 大技能**: 質量審查、圖表建議、架構設計。

### 🚀 Optimized

- **Meta Router**: 升級動態信心調節與多階執行邏輯。
- **README**: 全面繁體中文優化，新增「擴充指南」範例。
- **Deployment**: `deploy_brain.sh` 支援更精確的模組複寫。
