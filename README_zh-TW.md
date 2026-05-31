<div align="center">

# 👻 GhostCheck

**為 AI 輔助開發時代量身打造的極速、零依賴安全性掃描工具。**

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg?style=flat-square)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=flat-square)](https://www.python.org/)
[![授權: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![測試狀態](https://img.shields.io/badge/tests-105%20passed-brightgreen.svg?style=flat-square)](LICENSE)

*在 AI Agent 產出的程式碼進入 CI/CD 流程前，精準識別高風險漏洞、惡意指令與「幻覺」安全性威脅。*

---

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

## 🚀 願景

AI Agent 正在重塑軟體開發，但也帶來了全新的攻擊面。**GhostCheck** 彌補了傳統靜態應用程式安全測試 (SAST) 與 AI 原生安全性之間的鴻溝，確保您的程式碼在享受 AI 速度的同時，依然保持企業級的穩固與安全。

---

## 🧠 為什麼採用 AgentCortex？

**GhostCheck** 是基於 **AgentCortex** 哲學所構建。我們堅信，AI 輔助開發必須建立在**可驗證的工程指令與規範 (Verifiable Engineering Directives)** 之上。

傳統掃描器僅針對標準的開發者漏洞（例如 SQL 注入或緩衝區溢位）。而在 AI 時代，我們面臨全新的威脅：
*   **過度授權 (Excessive Agency)：** AI 工具被賦予過高權限（如 root）執行任意指令。
*   **工具中毒 (Tool Poisoning)：** 惡意第三方工具（如 MCP 伺服器）劫持 Agent 的執行。
*   **指令注入 (Instruction Injection)：** 隱藏在文件或程式碼中的惡意指令，旨在劫持或控制 Agent 的行為。
*   **AI 供應鏈安全 (AI Supply Chain Vulnerabilities)：** AI 幻覺所產生的虛構套件引用或惡意依賴。

透過將專案約定鎖定在可驗證的約束條件中，GhostCheck 確保 AI Agent 成為安全、可靠的共同設計者。

---

## ✨ 核心功能與改版亮點

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
| **完整安全掃描** | `ghostcheck scan` | 整個工作區 / Git 變更 | 掃描金鑰、IaC 錯誤配置以及 Agent 規則安全性。 |
| **依賴項真實性檢查** | `ghostcheck check-deps` | `requirements.txt`, `package.json` | 偵測 AI 幻覺套件與不安全的安全依賴。 |
| **機密資訊偵測** | `ghostcheck check-secrets` | 日誌、純文字、源碼 | 透過 AST 語法樹分析，精準識別 API Key 與憑證。 |
| **Agent 專屬規則審核** | `ghostcheck check-rules` | `.agent/`, `.cursor/`, `.agentcortex/` | 驗證 Agent 指令檔，防止越權或篡改。 |

---

## 🛠️ 安裝與設定說明

### 📦 選項 A: 透過 PyPI 安裝 (標準安裝)
推薦給大多數使用者，可獲取最新穩定版本：
```bash
pip install ghostcheck
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
```

---

## 🧪 執行測試與驗證

透過執行 105 個單元與整合測試，驗證安裝是否完整以及核心掃描器運作是否正常。

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
============================= 105 passed in 3.95s =============================
```

---

## ⚙️ 進階配置與 CI/CD 整合

GhostCheck 完美契合專業的開發工作流程，提供細粒度的配置：

*   **精準排除：** 透過 `.ghostcheckignore` 隱式排除不需要掃描的安全路徑或測試資料。
*   **嚴重性過濾：** 支援 `--severity [CRITICAL|HIGH|MEDIUM|LOW]` 鎖定需要處理的漏洞等級。
*   **多國語言支援：** 可在 `ghostcheck.toml` 內自訂文件專用的安全關鍵字 (例如 `custom_safe_keywords = ["避免"]` 或 `custom_safe_keywords = ["нельзя"]`)，大幅降低非英文文件的誤判率。
*   **自動化就緒：** 原生支援 `--format json`、`html`、`sarif` 及 `owasp-llm`，提供標準化的合規報告輸出，便於整合至 GitHub Actions 或 GitLab CI/CD。

---

## 📄 授權條款

本專案採用 MIT 授權條款 - 詳細資訊請參閱本地的 [LICENSE](LICENSE) 檔案。

---

<div align="center">

**由 [KbWen](https://github.com/KbWen) 為 AI 社群用心開發 ❤️**

</div>
