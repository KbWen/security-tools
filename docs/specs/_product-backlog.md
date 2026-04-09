# GhostCheck — Product Backlog (AI-Era Security)

> 本文件為 GhostCheck 後續版本的 **產品待辦清單**，聚焦於 AI 開發時代特有的安全風險。
> 每個 Feature 標記優先順序 (P0=必做, P1=重要, P2=加分) 及預估版本歸屬。
> 狀態: 🟢 Ready | 🟡 Needs Refinement | 🔴 Blocked | ✅ Done

---

## 戰略定位

GhostCheck 的核心差異化：**不只是另一個 SAST 工具，而是第一個為「用 AI 寫 code 的開發者」設計的安全掃描器。**

傳統工具掃描的是人寫的程式碼。GhostCheck 掃描的是：
1. **AI 產生的程式碼** — 幻覺套件、不安全模式
2. **AI Agent 的設定與行為** — Agent rules injection、MCP tool poisoning
3. **AI 開發工作流本身** — 供應鏈信任、權限邊界、資料洩漏

---

## 已完成版本

| 版本 | 主題 | 狀態 |
|------|------|------|
| v0.1.0 | MVP (幻覺偵測 + 密鑰掃描) | ✅ |
| v0.2.0 | Docker + Git Hooks | ✅ |
| v0.3.0 | AST + 離線模式 + 安全強化 | ✅ |
| v0.4.0 | CI/CD + SARIF | ✅ |
| v0.5.0 | JS AST + 嚴重度引擎 + .env | ✅ |
| v0.6.0 | Zero-Config + Git Diff + Baseline | ✅ |
| v0.7.0 | IaC + CI/CD Audit + Firebase + Plugin | ✅ |

---

## Backlog: AI-Era Security Features

---

### 🏷️ Epic 1: MCP (Model Context Protocol) Security Scanner

> **為什麼重要**: MCP 讓 AI Agent 從「只能生文字」變成「能操作檔案、呼叫 API、執行指令」。
> 這意味著 prompt injection 的危害從「產生不良文字」升級為「遠端程式碼執行」。
> 目前沒有任何開源工具專門掃描 MCP 設定的安全性。

| # | Feature | 優先 | 版本 | 狀態 | 說明 |
|---|---------|------|------|------|------|
| E1-F1 | **MCP Server Config Auditor** | P0 | v0.8.0 | 🟢 | 掃描 `mcp.json` / `mcp_config.json` / `.cursor/mcp.json` / VS Code MCP 設定，偵測：<br>- 繫結 `0.0.0.0` 而非 `127.0.0.1` (NeighborJack) → CRITICAL<br>- 缺少認證/token 的 MCP server → HIGH<br>- 使用 `stdio` transport 搭配 `npx` 執行未固定版本套件 → HIGH<br>- `env` block 中明文寫入 API keys → CRITICAL |
| E1-F2 | **MCP Tool Poisoning Detector** | P0 | v0.8.0 | 🟡 | 掃描 MCP server 原始碼 (Python/TS)，偵測 tool description 中的隱藏指令：<br>- Tool description 含 `<IMPORTANT>` / invisible Unicode / base64 payload → CRITICAL<br>- Tool description 長度異常 (>500 chars) 可能藏有 injection → MEDIUM<br>- Parameter description 含 injection pattern (`ignore previous`, `you must`) → HIGH |
| E1-F3 | **MCP Permission Boundary Checker** | P1 | v0.9.0 | 🟡 | 分析 MCP server 宣告的 capabilities vs 實際行為：<br>- Server 宣稱 read-only 但 code 中有 `fs.writeFile` / `os.remove` → HIGH<br>- Server 存取的路徑超出宣告 scope → MEDIUM<br>- Server 對外發送 HTTP 請求至非白名單域名 → HIGH |
| E1-F4 | **MCP Rug Pull Detection** | P2 | v1.0.0 | 🟡 | 監控 MCP server npm/pip 套件版本變更：<br>- 記錄已安裝 MCP server 的 tool description hash<br>- 下次掃描比對變化 → 若 description 被修改則告警<br>- 可整合 `ghostcheck watch` |

---

### 🏷️ Epic 2: AI Agent Rules Security (AGENTS.md / .cursorrules)

> **為什麼重要**: Agent rules 檔案本質上是「被自動注入到 LLM system prompt 的程式碼」。
> 攻擊者只需在 repo 裡放一個惡意 `.cursorrules`，任何用 AI IDE 開啟該 repo 的開發者就會被控制。
> GhostCheck 已有基本的 Agent Rules Linter (v0.1.0)，現在需要大幅擴展。

| # | Feature | 優先 | 版本 | 狀態 | 說明 |
|---|---------|------|------|------|------|
| E2-F1 | **Agent Rules Injection Scanner (強化版)** | P0 | v0.8.0 | 🟢 | 擴展現有 `agent_rules.py`，新增偵測：<br>- 隱藏的 prompt injection patterns (invisible chars, Unicode RTL, zero-width spaces) → CRITICAL<br>- 指示 agent 讀取 `~/.ssh/`, `~/.aws/`, `.env` 等敏感路徑 → CRITICAL<br>- 指示 agent 發送 HTTP 請求至外部 URL → HIGH<br>- 指示 agent 執行 `curl`, `wget`, `nc`, `base64` 等危險指令 → HIGH<br>- 指示 agent 繞過安全檢查 (`skip review`, `ignore warnings`, `auto-approve`) → MEDIUM |
| E2-F2 | **Multi-Format Rules Support** | P1 | v0.8.0 | 🟢 | 擴展掃描範圍至所有 AI IDE 設定檔格式：<br>- `.cursorrules` / `.cursor/rules/*.mdc`<br>- `AGENTS.md` / `.agents/*.md`<br>- `.github/copilot-instructions.md`<br>- `.windsurf/rules/*.md`<br>- `CLAUDE.md` / `.claude/settings.json`<br>- `.gemini/settings.json` / `GEMINI.md`<br>- `.aider/config.yml` |
| E2-F3 | **Cross-File Influence Analysis** | P2 | v1.0.0 | 🟡 | 偵測 agent rules 引用其他檔案時的信任邊界問題：<br>- Rules 指令 agent 讀取某檔案 → 該檔案也需被掃描<br>- 偵測 include chain 形成的間接注入 |

---

### 🏷️ Epic 3: LLM Supply Chain Security

> **為什麼重要**: 傳統 supply chain (npm/PyPI) 已有許多工具。
> 但 AI 時代新增了全新的供應鏈：model weights, LoRA adapters, prompt templates, MCP servers, AI plugins。
> 這些都是「黑盒」元件，傳統的 CVE 掃描完全無法覆蓋。

| # | Feature | 優先 | 版本 | 狀態 | 說明 |
|---|---------|------|------|------|------|
| E3-F1 | **AI Dependency Manifest Scanner** | P0 | v0.8.0 | 🟢 | 掃描 AI 專案特有的 dependency 宣告：<br>- `mcp.json` 中的 MCP server → 驗證 npm/pip 套件是否存在<br>- LangChain / LlamaIndex `requirements.txt` → 已知 CVE 檢查<br>- `docker-compose.yml` 中的 LLM inference server (ollama, vllm, text-generation-inference) → 版本安全<br>- `.env` 中的 model name → 驗證 Hugging Face model 是否存在 (防幻覺) |
| E3-F2 | **Prompt Template Injection Scanner** | P1 | v0.9.0 | 🟡 | 掃描專案中的 prompt template 檔案 (`.prompt`, `.jinja2`, `prompts/`目錄)：<br>- 偵測 template 中缺少 input sanitization placeholder → MEDIUM<br>- 偵測 template 允許使用者直接控制 system prompt → HIGH<br>- 偵測 hardcoded API keys 在 prompt 字串中 → CRITICAL |
| E3-F3 | **Model Provenance Checker** | P2 | v1.0.0 | 🟡 | 掃描 model 設定檔 (`Modelfile`, `.gguf` references, HuggingFace `config.json`)：<br>- 偵測使用未經驗證來源的 model weights<br>- 偵測 LoRA adapter 從非官方來源載入<br>- 建議使用 signed model checksums |

---

### 🏷️ Epic 4: Agentic Workflow Security

> **為什麼重要**: 越來越多團隊讓 AI Agent 直接寫 code、建 PR、部署應用。
> 這些 workflow 如果缺乏安全邊界，就等於給了 AI 無限信用卡。

| # | Feature | 優先 | 版本 | 狀態 | 說明 |
|---|---------|------|------|------|------|
| E4-F1 | **Excessive Agency Detector** | P0 | v0.8.0 | 🟢 | 偵測 AI Agent 設定中過度寬鬆的權限：<br>- GitHub Actions 中 AI bot 使用 `GITHUB_TOKEN` 且有 `contents: write` + `pull-requests: write` → HIGH<br>- Agent rules 指示 `auto-apply`, `auto-run`, `no confirmation` → HIGH<br>- Dockerfile 中以 `root` 運行 AI agent service → CRITICAL<br>- CI/CD pipeline 中 AI agent 可直接 deploy to production → CRITICAL |
| E4-F2 | **AI-Generated Code Marker** | P1 | v0.9.0 | 🟡 | 偵測可能由 AI 生成但未被審查的程式碼：<br>- 偵測 `// Generated by` / `# Auto-generated` 等標記<br>- 偵測 commit message 含 AI 工具名稱 (`Copilot`, `Cursor`, `Claude`) 但缺少 review 標記<br>- 生成 AI-authored code coverage 報告 |
| E4-F3 | **Data Exfiltration via AI Channel** | P1 | v0.9.0 | 🟡 | 擴展現有 exfiltration 偵測至 AI 特有管道：<br>- 偵測將敏感資料作為 prompt 傳送給 LLM API → HIGH<br>- 偵測 MCP server 將本地檔案內容回傳 → MEDIUM<br>- 偵測 agent 輸出被直接寫入可公開存取的位置 → HIGH |
| E4-F4 | **Human-in-the-Loop Verification** | P2 | v1.0.0 | 🟡 | 偵測高風險操作缺少人工確認機制：<br>- AI agent 執行 `git push --force` 無確認 → CRITICAL<br>- AI agent 執行 `rm -rf` / `DROP TABLE` 無確認 → CRITICAL<br>- AI agent 修改 `.env` / `secrets` 無確認 → HIGH |

---

### 🏷️ Epic 5: OWASP LLM Top 10 Compliance Scanner

> **為什麼重要**: OWASP LLM Top 10 (2025) 已成為 AI 應用安全的業界標準。
> 提供合規掃描報告將大幅提升 GhostCheck 的企業價值。

| # | Feature | 優先 | 版本 | 狀態 | 說明 |
|---|---------|------|------|------|------|
| E5-F1 | **LLM01: Prompt Injection Detection** | P0 | v0.8.0 | 🟢 | 整合 E2 (Agent Rules) + E1-F2 (Tool Poisoning) 的偵測結果，對應 LLM01 |
| E5-F2 | **LLM02: Sensitive Info Disclosure** | P0 | v0.8.0 | 🟢 | 整合現有 secret scanner + E4-F3 (Data Exfil)，偵測 AI 管道中敏感資訊洩漏 |
| E5-F3 | **LLM03: Supply Chain** | P0 | v0.8.0 | 🟢 | 整合 E3 (AI Supply Chain) + 既有幻覺偵測，對應 LLM03 |
| E5-F4 | **LLM06: Excessive Agency** | P0 | v0.8.0 | 🟢 | 整合 E4-F1，對應 LLM06 |
| E5-F5 | **LLM09: Misinformation (Hallucination)** | P0 | v0.8.0 | 🟢 | 整合既有 hallucination checker，對應 LLM09 |
| E5-F6 | **OWASP LLM Compliance Report** | P1 | v0.9.0 | 🟡 | 新增報告格式 `--format owasp-llm`：<br>- 依 LLM01-LLM10 分類列出發現<br>- 含合規百分比與 remediation 優先順序<br>- 可匯出 PDF / HTML |

---

### 🏷️ Epic 6: Developer Experience & SAST Ergonomics

> **為什麼重要**: 安全工具如果產生過多誤判，最終會被團隊全面停用。目前已知當 GhostCheck 掃描其「自身原始碼」或「文件」中儲存的安全特徵碼時，會在 Pre-commit Hook 造成阻斷式誤判 (False Positives on Self)。需要有優雅的解決方案。

| # | Feature | 優先 | 版本 | 狀態 | 說明 |
|---|---------|------|------|------|------|
| E6-F1 | **Smart Pre-commit Exemption (Self-Scan Safe)** | P1 | v0.9.0 | 🟡 | 實作智慧豁免機制以避免 SAST 掃描自身時引發誤報：<br>- 自動忽略 `ghostcheck` 自身安裝路徑或設定檔內的安全特徵碼。<br>- 支援 `.ghostcheckignore` 內明確標記 `inline-signature-bypass`。<br>- 即便命中規則，若偵測為「工具自身的展示/測試」，應降級為 INFO 而非 HIGH/CRITICAL。 |
| E6-F2 | **Cross-Platform Output Encoding Fallback** | P1 | v0.9.0 | 🟡 | 提升控制台輸出的穩健度：<br>- 自動偵測終端機不支援 UTF-8 (如 Windows cp950) 時，自動降級/移除 Unicode Emoji 圖示。<br>- `--no-color` 之餘，新增 `--ascii-only` 模式。 |

---

## 版本規劃 (AI-Era Features 歸屬)

### v0.8.0 — AI Agent Security Foundation ⭐

> **主題**: 讓 GhostCheck 成為第一個能掃描 MCP 設定和 Agent Rules 安全性的開源工具。

| 歸屬 | 功能 |
|------|------|
| E1-F1 | MCP Server Config Auditor |
| E1-F2 | MCP Tool Poisoning Detector |
| E2-F1 | Agent Rules Injection Scanner (強化版) |
| E2-F2 | Multi-Format Rules Support |
| E3-F1 | AI Dependency Manifest Scanner |
| E4-F1 | Excessive Agency Detector |
| E5-F1~F5 | OWASP LLM Top 10 Mapping (整合層) |
| (Roadmap) | Entropy-based Secret Detection |
| (Roadmap) | CVE Vulnerability Scanner |
| (Roadmap) | Mobile Config Audit |

### v0.9.0 — Deep AI Awareness

| 歸屬 | 功能 |
|------|------|
| E1-F3 | MCP Permission Boundary Checker |
| E3-F2 | Prompt Template Injection Scanner |
| E4-F2 | AI-Generated Code Marker |
| E4-F3 | Data Exfiltration via AI Channel |
| E5-F6 | OWASP LLM Compliance Report |
| E6-F1 | Smart Pre-commit Exemption (Self-Scan Safe) |
| E6-F2 | Cross-Platform Output Encoding Fallback |
| (Roadmap) | Go/Java AST, Dart AST, Watch Mode |

### v1.0.0 — Universal AI-Era Scanner

| 歸屬 | 功能 |
|------|------|
| E1-F4 | MCP Rug Pull Detection |
| E2-F3 | Cross-File Influence Analysis |
| E3-F3 | Model Provenance Checker |
| E4-F4 | Human-in-the-Loop Verification |
| (Roadmap) | Framework Presets, PyPI Publish, Docs |

---

## 競品分析

| 能力 | GhostCheck | Snyk | Semgrep | Trivy | Gitleaks |
|------|-----------|------|---------|-------|----------|
| Secret 掃描 | ✅ | ✅ | ✅ | ✅ | ✅ |
| CVE 偵測 | 🟡 v0.8 | ✅ | ❌ | ✅ | ❌ |
| IaC 掃描 | ✅ | ✅ | ✅ | ✅ | ❌ |
| **AI 幻覺套件** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Agent Rules Audit** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **MCP Security** | 🟡 v0.8 | ❌ | ❌ | ❌ | ❌ |
| **OWASP LLM Top 10** | 🟡 v0.8 | ❌ | ❌ | ❌ | ❌ |
| **Prompt Injection Detection** | 🟡 v0.9 | ❌ | ❌ | ❌ | ❌ |
| Docker 掃描 | ✅ | ✅ | ❌ | ✅ | ❌ |
| CI/CD Audit | ✅ | ❌ | ❌ | ❌ | ❌ |
| 免費開源 | ✅ | 部分 | 部分 | ✅ | ✅ |

---

## 更新紀錄

| 日期 | 變更 |
|------|------|
| 2026-04-09 | 初版建立，新增 Epic 1-5 (AI-Era Security Features) |
