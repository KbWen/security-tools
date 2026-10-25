<div align="center">

# 👻 GhostCheck

**為 AI 寫 code 時代量身打造的超輕量、零依賴、極速安全防禦小工具。**

[![Version](https://img.shields.io/badge/version-1.2.15-blue.svg?style=flat-square)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=flat-square)](https://www.python.org/)
[![授權: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![測試狀態](https://img.shields.io/badge/tests-417%20passed-brightgreen.svg?style=flat-square)](LICENSE)

*在 AI Agent 產出的程式碼送進 CI/CD 被主管電爆之前，幫你精準抓出高風險漏洞、惡意指令與 AI 瞎掰的「幻覺」套件，再也不怕寫 code 寫到裸奔！*

---

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

## 🚀 願景

現在寫 code 誰不用 AI？雖然 AI Agent 寫起 code 來飛快，但常常也是「一本正經地胡說八道」，甚至悄悄挖個大坑等你踩雷。傳統的安全掃描工具 (SAST) 根本看不懂 AI 時代的「指令注入」或「套件幻覺」，於是 **GhostCheck** 就誕生了！

我們不搞繁複的安裝，主打一個**「零依賴、超輕量、極速掃描」**。它就像是你在 AI 開發時代的最佳安全防護網（Safety Net），在程式碼被 commit 或是 push 之前幫你做最後把關，讓你既能享受 AI 的光速開發，又不用擔心隔天伺服器被駭、後台直接拋出 Exception！

---

## 🧠 為什麼你需要 GhostCheck？

**GhostCheck** 的核心理念很簡單：既然 AI 可以幫我們寫 code，那它也極有可能在不知不覺中幫我們「加料」。「AI 輔助開發」雖然爽，但如果沒有**可驗證的工程指令與規範 (Verifiable Engineering Directives)** 當作煞車，那就是載著你全速往懸崖衝的跑車。

傳統的靜態掃描工具只會檢查 SQL Injection 或是 Buffer Overflow 這些人類開發者常踩的雷。但在 AI 稱霸的時代，我們面臨的是全新、甚至有點獵奇的威脅：

*   **過度授權 (Excessive Agency)：** AI Agent 拿著 root 權限在你的系統裡「裸奔」，高興執行什麼就執行什麼。
*   **工具中毒 (Tool Poisoning)：** 不小心引進了有毒的第三方工具（例如來路不明的 MCP 伺服器），導致 Agent 被人劫持。
*   **指令注入 (Instruction Injection)：** 有些惡意指令藏在 README 或是註解裡，AI Agent 一讀到就「被洗腦」，乖乖聽從駭客的指示。
*   **AI 供應鏈安全 (AI Supply Chain Vulnerabilities)：** AI 一時想不起來某個套件名稱，就自己「通靈」瞎掰一個不存在的 dependency，直接把你的專案推進供應鏈漏洞的深淵。

GhostCheck 透過在專案中設定一道硬派的安全邊界，讓 AI Agent 在幫你寫 code 的時候老老實實遵守規範，成為真正幫你省力、而不是天天幫你寫 Bug 的神隊友！

---

## ✨ 核心功能與改版亮點

### 🛠️ v1.2.15: Tenth-Man 深度審計、並行加固與 Baseline 對齊 (Tenth-Man Deep Audit & Concurrency Hardening)
*   **結果快取隔離 (Results Cache Metadata Isolation)：** `Scanner` 結果快取完整雜湊納入 `offline`、`version`、`disabled_rules` 與 `exclude_patterns`，切換離線模式或版本升級時自動使舊快取失效，杜絕跨環境快取污染。
*   **Baseline 預設自動偵測與忽略對齊：** 自動發現專案根目錄下之 `.ghostcheckbaseline` 與 `.ghostcheck-baseline.json`，並同步將 `.ghostcheck-baseline.json` 納入預設忽略清單。
*   **完整 CLI 工作流旗標 (`init --hook`, `honeypot --clean`)：** 正式實作 `ghostcheck init --hook` 自動安裝 Git pre-commit 檢查鉤子；提供 `ghostcheck honeypot --clean` 快速清除誘餌 Canary 檔案並清理 `.gitignore` 與 `.ghostcheckignore` 登記項目。
*   **排除規則串接與 .env 保留：** 將設定檔中之 `exclude_patterns` 正式串接至 `IgnoreMatcher`，並將預設排除之 `".env*"` 調整為 `"*.canary"`，確保真實 `.env` 能被機密掃描器正常稽核。
*   **多執行緒並行安全與原子快取寫入：** 為 `HallucinationChecker` 與 `VulnScanner` 導入 `threading.Lock()` 鎖定與獨立狀態處理，並全面採用臨時檔原子取代 (`os.replace`)，防止並行快取損毀與狀態覆蓋。
*   **跨平台大小寫安全忽略匹配：** 在 Windows 環境下針對目錄前綴比對實現不區分大小寫匹配，同時保留原始路徑大小寫。
*   **框架 Preset 模組補齊與 SecretValidator 顯式啟用：** 為所有主流框架預設補齊 `entropy`、`vuln`、`tamper` 掃描模組；將線上機密即時驗證調整為顯式啟用 (`validate_secrets`) 並嚴格過濾空白字元防範外洩。

### 🛠️ v1.2.14: Skill Frontmatter 對齊、Proxy Opener Reset 與 CI 韌性強化 (Skill Parity & CI Resilience)
*   **Skill Frontmatter 規範對齊：** 全面校準 `.agents/skills/*/SKILL.md` 的 metadata frontmatter 格式與結構。
*   **Proxy Opener 洩漏防護：** 確保在 Proxy 與直連掃描切換時正確重設全域 urllib opener。
*   **CI 韌性全面強化：** 加固 CI 與測試管線，確保不同環境下 100% 穩定運行。

### 🛠️ v1.2.13: 實用主義 DX、離線熔斷器與零膨脹打磨 (Pragmatic DX & Offline Circuit Breaker)
*   **網路快速失敗熔斷器 (Fast-Fail Circuit Breaker)：** `HallucinationChecker` 與 `VulnScanner` 內建自動熔斷保護。當網路發生連續 2 次超時或連線失敗，自動切換至離線模式，徹底告別內網、隔離區或弱網環境下的卡頓與無謂等待。
*   **務實誤報大幅降低 (Pragmatic FP Reduction)：** 將 `APILinter` 的 `api_cors_wildcard` 與 `api_csrf_disabled` 降級為 `MEDIUM`。當檔案包含無狀態認證指標（`jwt`、`bearer`、`oauth`、`authorization`）時，智慧抑制 CSRF 告警；在 `EntropyScanner` 中精準排除 SRI 雜湊、Data URI 與多層路徑，不誤傷真實金鑰。
*   **極簡安靜模式 (`-q` / `--quiet`)：** 新增標準 `-q` / `--quiet` 命令列參數，自動壓制 Banner、快取訊息與資訊性頁尾。在專案安全無虞時完全靜默（Unix 標準哲學），存在 actionable 風險時輸出精簡、單行清晰報告。

### 🛠️ v1.2.12: DX、穩定性與誤報大掃除 (DX & False-Positive Overhaul)
*   **快取投毒修復與多套件庫支援：** 嚴格限制 `HallucinationChecker` 僅持久化快取 HTTP 200/404 權威響應（網路中斷或連線失敗永不快取），補齊 Rust crates.io 線上套件註冊表檢查，並為 OSV 漏洞庫新增本機 24 小時 TTL 快取機制。
*   **符合人性的 CI 預設值 (`--fail-on HIGH`)：** CLI 預設 `--fail-on` 調整為 `HIGH`，一般 `INFO`/`LOW`/`MEDIUM` 建議不再中斷 CI/CD 建置流程。
*   **非懲罰性與目標化壓制支援：** 行內 `# ghostcheck-ignore` 支援全面壓制（包含 CRITICAL）且不觸發逃逸告警；支援針對性壓制語法 `# ghostcheck-ignore: <rule_name>`，並於 `ghostcheck.toml` 支援 `disabled_rules` 設定。
*   **簡潔單行輸出格式 (`--compact`)：** 提供標準 linter 格式 `{file}:{line}: [{severity}] {name}: {message}` 與單行簡報，便於 IDE 與終端極簡整合。
*   **高精度誤報大掃除：** 全面校準 Shadow AI（僅在設定 `blocked_sdks` 或嚴格 `allowed_sdks` 時觸發）、Lethal Trifecta（一般 `.run()`/`.call()` 不再誤判為指令執行）、Kill Switch Auditor（遞迴必須包含 AI/LLM 上下文）與 AI Marker（未審核 commit 降級為 `INFO`）。

### 🛡️ v1.2.11: 全方位審計修復、OWASP LLM 映射對齊與框架預設強化
*   **OWASP LLM Top 10 映射全面對齊：** 同步 `owasp_mapping.json` 與全數 24 個掃描器類別，並新增確定性分類回退解析（`Scanner._resolve_owasp_llm`），確保 `--format owasp-llm` 精準反映合規分數。
*   **框架 Preset 對齊與自訂插件串接：** 為所有框架預設（`next.js`, `flutter`, `django`, `fastapi`, `terraform`）補齊 AI 專屬安全檢查（`rules`, `mcp`, `privilege`, `exfiltration`, `trifecta`, `killswitch`），並將 `.ghostcheck/plugins/` 自訂插件正式接入單通掃描管線。
*   **SARIF 定位與 Monorepo 相容強化：** 為套件幻覺檢測結果補齊精確 `file` 與 `line` 屬性（支援 SARIF 報表與 Baseline 指紋），在 CVE 掃描中過濾 `workspace:*` / `file:` / `git+` 等本地協議，並將 `ghostcheck init --ci` 產出之 GitHub Actions 改為 40 字元 SHA-1 鎖定以通過自身 CI 審計。

### 🛡️ v1.2.10: 範例展示豁免修復、發布鏈條對齊與 SSoT 同步
*   **針對性 Demo Fixtures 檢測支援：** 修復 `_is_self_scan_exempt`，使針對性掃描（如 `make demo`）能真實檢出並展示範例漏洞特徵，恢復展示體驗的同時，確保儲存庫自身自檢仍維持 Grade A (100/100) 滿分標準。
*   **Git 發布標籤完全對齊：** 版本號同步升級為 `1.2.10`，原子化更新 `uv.lock` 解決依賴鎖定漂移。
*   **文檔徽章與 SSoT 規格校正：** 更新測試徽章為 368 passed、校正 SSoT 規格索引並清理歷史殘留檔案。

### 🛡️ v1.2.9: 第十人發布驗證與鎖檔加固 (Tenth Man Hardening)
*   **相依性鎖檔完全同步：** 同步 `uv.lock` 與專案定義，解決版本漂移並消弭 CI 檢查不一致。
*   **Git Release 標籤鏈條補齊：** 補齊 v1.2.x 系列所有歷史標籤（`v1.2.6` 至 `v1.2.9`），確保版本可追溯性。
*   **第十人逆向審查與圓桌評審：** 完成逆向批判式安全審計與五方專家圓桌會審。

### 🧪 v1.2.8: 多框架真實世界模擬與 Agent 規則防禦性上下文 (Downstream Simulations)
*   **多框架真實世界模擬測試套件：** 覆蓋 Cursor, Claude Code, LangChain, LlamaIndex, CrewAI, AutoGen 及企業級 MCP 等多種下游架構。
*   **Agent 規則防禦上下文零誤判：** 辨識安全規則中的負向/防禦性警語（如 `NEVER run curl`、`嚴禁 rm -rf`），消弭自我保護規範被誤判為攻擊指令的問題；同時對零寬字元與 RTL 混淆維持絕對無例外攔截。

### 🔒 v1.2.7: Anthropic MCP 深度防禦與根目錄掛載加固 (MCP Deep Defense)
*   **未鎖定版本套件執行防護：** 審計 `npx -y package`（缺少 `@version`）與 `uvx package`（缺少 `==version`），防範依賴混淆與供應鏈 Rug Pull。
*   **過度寬鬆根目錄掛載審計：** 嚴格標記掛載根目錄（`/`, `C:\`, `~`, `/etc`）的 MCP Server 配置。
*   **不安全網路綁定與 SSRF 防禦：** 標記通配綁定（`0.0.0.0`, `::`）並阻斷雲端 Metadata SSRF（`169.254.169.254`, `metadata.google.internal`）。

### ⚡ v1.2.6: AST 常數摺疊與 AI 資料外洩防護 (AST Folding & Data Exfiltration)
*   **Python AST 常數摺疊：** 遞迴解構 `ast.JoinedStr` f-string 與字串拼接，設有遞迴深度保護（`depth > 30`），防禦動態混淆引入與金鑰遮罩逃逸。
*   **資料外洩檢測全面啟動：** 將 AI 資料外洩防禦模組納入標準掃描與各框架預設配置。
*   **忽略規則語意修正：** 支援 `.ghostcheckignore` 依循 Git 最後匹配優先語意，允許以否定規則（`!path`）覆蓋預設忽略。

### 🎯 v1.1.0: Agent 專屬安全性檢查與本地誘捕工具 (Honeypot)
分享幾個簡單實用的 Agent 邊界檢查工具，幫助驗證 Agent 的安全執行邊界：
*   **本地誘捕 CLI (`ghostcheck honeypot`)：** 一鍵在工作區部署偽裝的 credentials 檔案（如 `.env.canary`、`aws_credentials.canary` 及 SSH 金鑰），用以測試和追蹤被劫持的 Agent 是否會私自探測並向外傳送金鑰。產生後會自動加進忽略清單避免自我誤報。
*   **Lethal Trifecta AST 偵測器：** 分析 Python/JS 的抽象語法樹 (AST)，檢測單一執行範疇內是否同時包含私有資料讀取、用戶互動與系統指令執行（致命三要素）。
*   **Agent 逃逸生命週期審計 (Killswitch Auditor)：** 檢測 infinite loop (`while true` 或 recursive 呼叫) 是否有設定合理的次數上限、逾時限制或人工確認門檻。
*   **靜態相依套件安裝稽核 (Silent Installer)：** 掃描 `.cursorrules`、`.mdc` 指令檔及 Shell 腳本，防範未鎖定版本或帶有 `-y` 的動態背景套件安裝，降低供應鏈被劫持的風險。

### 🔌 v1.0.3: 擴展插件與紅隊防禦強化
*   **模組化插件架構：** 掃描器與報表輸出完全解耦，方便快速編寫自定義掃描邏輯。
*   **紅隊級安全防禦：** 內建抵禦混沌測試、繞過嘗試、本地遠端代碼執行 (RCE) 與目錄穿越攻擊的安全機制。
*   **全方位報表輸出：** 原生支援 `console`, `json`, `html`, `owasp-llm`, 以及 `sarif` 格式輸出。
*   **Shannon 熵通用機密過濾：** 引入 Shannon 熵演算法以偵測高隨機性的通用密鑰與密碼，同時最大程度降低結構化金鑰的誤報率。
*   **註解感知的 Shadow AI 排除機制：** 語法解析引擎現已支援識別程式碼註解（例如 `//`、`#` 等），以便選擇性地將特定程式碼行或區塊排除在 AI 安全審計之外。
*   **不區分大小寫的行動端 CI 設定過濾：** 行動端管線掃描器（Android/iOS CI）現已支援對配置檔案與環境變數進行不區分大小寫的樣式匹配。
*   **預過濾範圍 I/O 優化：** 在進行繁重的磁碟 I/O 操作前，先對檔案類型與掃描範圍進行高效預過濾，大幅減少大型專案中的無效檔案讀取。

### 🎯 v1.0.0: 全球首款框架感知安全性掃描器 (Universal Scanner)
*   **框架預載配置 (Framework Presets)：** 自動針對 **Next.js, Flutter, Django, FastAPI,** 及 **Terraform** 等熱門框架配置專屬偵測引擎。
*   **強韌基準線與隱式忽略：** 引入內容雜湊指紋技術 (`file:rule:hash`)。即使程式碼發生縮排調整或行號位移，已忽略的漏洞依然能被精準忽略。
*   **Preset 偵測與效能優化：** 根據專案類型自動過濾無關模組（例如：Flutter 專案不掃描 Docker，Next.js 專案加強掃描環境變數），掃描效率大幅提升。
*   **OWASP LLM Top 10 報告：** 率先支援 `--format owasp-llm`，將掃描結果自動對應至全球標準的 AI 安全分類。
*   **AI 供應鏈與 MCP 審計：** 支援 Model Context Protocol (MCP) 設定檔安全審查，防止工具中毒與越權執行。
*   **AST 驅動的機密資訊偵測：** 透過語法樹 (AST) 精準掃描 50+ 雲端業者密鑰，支援 Python, JS/TS, Go, Java, Dart 多語言環境。

---

## 📋 完整功能與指令對照表

GhostCheck 提供針對特定風險向量的專屬指令：

| 安全能力 | 執行指令 | 掃描目標 | 詳細說明 |
| :--- | :--- | :--- | :--- |
| **完整安全掃描** | `ghostcheck scan` | 整個工作區 / Git 變更 | 掃描金鑰、IaC 錯誤配置、MCP 設定以及 Agent 規則安全性。 |
| **專案規則初始化** | `ghostcheck init` | `.ghostcheckignore`, `ghostcheck.toml` | 自動偵測框架 Preset 並生成設定檔、Git Hooks (`--hook`) 或 CI 範本 (`--ci`)。 |
| **檢查模組清單** | `ghostcheck list-checks` | 內建 24 項檢查器註冊表 | 列出所有支援的 24 大安全檢查模組與說明。 |
| **本地誘捕部署** | `ghostcheck honeypot` | `.env.canary`, `aws_credentials.canary` | 一鍵部署或清理 (`--clean`) 誘捕憑證檔，偵測異常 Agent 讀取行為。 |
| **依賴項真實性檢查** | `ghostcheck check-deps` | `requirements.txt`, `package.json` | 偵測 AI 幻覺套件與不安全的安全依賴。 |
| **機密資訊偵測** | `ghostcheck check-secrets` | 日誌、純文字、源碼 | 透過 AST 語法樹分析，精準識別 API Key 與憑證。 |
| **Agent 專屬規則審核** | `ghostcheck check-rules` | `.agent/`, `.cursor/`, `.agentcortex/` | 驗證 Agent 指令檔，防止越權或篡改。 |

---

## 🛠️ 安裝與設定說明

### 📦 選項 A: 透過 GitHub 安裝 (標準安裝)
推薦給大多數使用者，可獲取最新穩定版本：
```bash
pip install git+https://github.com/KbWen/security-tools.git@v1.2.15
```

### 🔨 選項 B: 從原始碼安裝
若想直接執行或測試本倉庫的最新功能：
```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

### 💻 選項 C: 開發者與貢獻者環境設定
如果您計畫開發插件、擴充規則預設或執行測試套件：
1. 複製本專案並進入專案目錄：
   ```bash
   git clone https://github.com/KbWen/security-tools.git
   cd security-tools
   ```
2. 建立並啟動虛擬環境（推薦）：
   ```bash
   python -m venv .venv
   # Windows 環境:
   .venv\Scripts\activate
   # macOS/Linux 環境:
   source .venv/bin/activate
   ```
3. 以可編輯模式安裝開發依賴項：
   ```bash
   pip install -e ".[dev]"
   # 或使用 Makefile 快速安裝：
   make install
   ```

---

## 🚀 快速上手步驟

### 1. 初始化專案安全規則
依照當前專案類型**自動偵測並建議 Preset**，產生相對應的 `.ghostcheckignore` 與 `ghostcheck.toml` 設定檔：
```bash
ghostcheck init
```

### 2. 執行即時掃描
立即掃描工作區以識別漏洞：
```bash
# 掃描整個專案的所有風險項目
ghostcheck scan .

# 僅掃描即將 Commit 的檔案 (極速 pre-commit 模式)
ghostcheck scan --staged

# 極簡單行輸出模式 (適合 IDE 與 CI 簡報)
ghostcheck scan . --compact

# 安靜模式 (CI 流程無風險時完全靜默)
ghostcheck scan . -q
```

---

## 🧪 執行測試與驗證

透過執行 409 個單元與整合測試，驗證安裝是否完整以及核心掃描器運作是否正常。

### 使用 Pytest
在虛擬環境啟用狀態下，執行以下指令：
```bash
pytest tests/ -v
```

### 使用 Makefile (macOS/Linux)
```bash
make test
```

預期將看到所有測試通過的輸出：
```text
============================= 409 passed in 25.11s =============================
```

---

## ⚙️ 進階配置與 CI/CD 整合

GhostCheck 完美契合專業的開發工作流程，提供細粒度的配置：

*   **精準排除：** 透過 `.ghostcheckignore` 隱式排除不需要掃描的安全路徑或測試資料。
*   **規則停用與目標壓制：** 支援在 `ghostcheck.toml` 設定 `disabled_rules = ["rule_name"]` 完全關閉特定規則，或使用行內註解 `# ghostcheck-ignore: rule_name` 針對性壓制特定警告。
*   **CI 門檻與嚴重性過濾：** 支援 `--severity [CRITICAL|HIGH|MEDIUM|LOW]`。預設 `--fail-on HIGH` 僅在出現 HIGH 或 CRITICAL 風險時回傳非零退出碼。
*   **極簡單行輸出：** 使用 `--compact` 輸出簡潔單行格式 `{file}:{line}: [{severity}] {name}: {message}`。
*   **多國語言支援：** 可在 `ghostcheck.toml` 內自訂文件專用的安全關鍵字 (例如 `custom_safe_keywords = ["避免"]` 或 `custom_safe_keywords = ["нельзя"]`)，大幅降低非英文文件的誤判率。
*   **自動化就緒：** 原生支援 `--format json`、`html`、`sarif` 及 `owasp-llm`，提供標準化的合規報告輸出，便於整合至 GitHub Actions 或 GitLab CI/CD。

---

## 📄 授權條款

本專案採用 MIT 授權條款 - 詳細資訊請參閱本地的 [LICENSE](LICENSE) 檔案。

---

<div align="center">

**由 [KbWen](https://github.com/KbWen) 為 AI 社群用心開發 ❤️**

</div>
