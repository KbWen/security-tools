<div align="center">

# 👻 GhostCheck
**為 AI 輔助開發時代量身打造的極速、零依賴安全性掃描工具。**

[![版本](https://img.shields.io/badge/version-0.9.0-blue.svg?style=for-the-badge)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=for-the-badge)](https://www.python.org/)
[![授權](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*在 AI Agent 產出的內容進入 CI/CD 流程前，精準識別高風險漏洞與「幻覺」威脅。*

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

---

## 🚀 願景

AI Agent 正在重塑程式開發，但也帶來了全新的攻擊面。**GhostCheck** 彌補了傳統 SAST 與 AI 原生安全性之間的鴻溝，確保您的代碼在享受 AI 速度的同時，依然保持企業級的穩固與安全。

從「流程驅動」進化到「自我管理」的專業級 AI Agent 核心架構。

## ✨ v0.9.0 性能與安全里程碑

*   🚀 **極速並行執行引擎：** 引入 `ThreadPoolExecutor` 與單次遍歷分發架構。在大型專案中，檔案處理速度提升數倍，且大幅減少磁碟 I/O。
*   🛡️ **紅隊層級硬化 (Red Team Hardened)：** 修補了路徑遍歷漏洞，並全面實作掃描報告「自動脫敏」功能，確保 GhostCheck 產出的報告不會成為二次洩漏源。
*   🔑 **海量密鑰與威脅偵測：** 內建支援 30+ 雲端供應商 (AWS, GCP, Stripe, GitHub 等)，並結合 AST 語法樹解析抓出被拆分拼接的密鑰。
*   🖥️ **跨平台編碼自動回退：** 完美支援 Windows CP950/UTF-8 終端機環境。偵測到非 UTF-8 環境時會自動降級圖示輸出的編碼，徹底防止崩潰。
*   🤖 **AI 供應鏈與 MCP 審計：** 領先業界支援 Model Context Protocol (MCP) 設定文件審計，防止 Agent 權限過大與 Tool Poisoning 攻擊。

## 🛠️ 快速上手

### 1. 安裝

```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

### 2. 初始化專案安全規則

依照當前專案自動產生 `.ghostcheckignore` 與 `ghostcheck.toml`：
```bash
ghostcheck init
```

### 3. 立即掃描

```bash
# 掃描整個工作目錄
ghostcheck scan .

# 僅掃描即將 Commit 的檔案 (速度極快！)
ghostcheck scan --staged
```

## 📋 完整功能與指令

| 功能 | 指令 | 目標 |
| :--- | :--- | :--- |
| **完整安全掃描** | `ghostcheck scan` | 整個工作區 / Git 變更 |
| **依賴項真實性檢查** | `ghostcheck check-deps` | `requirements.txt`, `package.json` |
| **機密資訊偵測** | `ghostcheck check-secrets` | 日誌、純文字、源碼 |
| **Agent 專屬規則審核** | `ghostcheck check-rules` | `.agent/`, `.cursor/` 指令檔 |

## ⚙️ 進階配置與 CI/CD 整合

GhostCheck 完美契合專業的開發工作流程：

*   **精準排除：** 透過 `.ghostcheckignore` 隱式排除不需要掃描的安全路徑。
*   **嚴重性過濾：** 支援 `--severity [CRITICAL|HIGH|MEDIUM|LOW]` 鎖定需要處理的漏洞等級。
*   **自動化就緒：** 原生支援 `--format json` 及 `--format sarif`，可無縫串接 GitHub Advanced Security (GHAS) 與各大 IDE。

---

## 🧠 Powered by AgentCortex

### 為什麼採用 AgentCortex 架構？
本專案採用 [AgentCortex](https://github.com/KbWen/AgentCortex) 流程驅動 (Process-driven) 架構，這確保了 AI 開發過程中的高標準自治性、安全性考量，以及架構的可維護性。

<div align="center">

**由 [KbWen](https://github.com/KbWen) 為 AI 社群用心開發 ❤️**

</div>
