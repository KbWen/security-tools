<div align="center">

# 👻 GhostCheck
**為 AI 輔助開發時代量身打造的極速、零依賴安全性掃描工具。**

[![版本](https://img.shields.io/badge/version-1.0.3-blue.svg?style=for-the-badge)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=for-the-badge)](https://www.python.org/)
[![授權](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*在 AI Agent 產出的內容進入 CI/CD 流程前，精準識別高風險漏洞與「幻覺」威脅。*

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

---

## 🚀 願景

AI Agent 正在重塑程式開發，但也帶來了全新的攻擊面。**GhostCheck** 彌補了傳統 SAST 與 AI 原生安全性之間的鴻溝，確保您的代碼在享受 AI 速度的同時，依然保持企業級的穩固與安全。

從「流程驅動」進化到「自我管理」的專業級 AI Agent 核心架構。

## ✨ v1.0.3 擴展插件與紅隊防禦強化
*   🔌 **插件架構 (Plugin Architecture)：** 完全解耦掃描器與報表輸出，支援自定義擴展邏輯。
*   🛡️ **紅隊級防禦 (Red Team Hardened)：** 內建抵禦混沌測試、繞過嘗試、本地 RCE 漏洞與目錄穿越攻擊的安全機制。
*   📊 **全方位報表 (Universal Reporters)：** 原生支援 `console`, `json`, `html`, `owasp-llm`, 以及 `sarif` 格式輸出。

## ✨ v1.0.0 全球首款框架感知安全性掃描器 (Universal Scanner)
*   🚀 **框架預設策略 (Framework Presets)：** 自動針對 **Next.js, Flutter, Django, FastAPI, Terraform** 等熱門框架配置專屬偵測引擎。
*   🛡️ **強韌基準線 (Robust Baseline)：** 引入內容雜湊指紋技術 (`file:rule:hash`)。即使程式碼發生縮排調整或行號位移，已確認過的漏洞依然能被精準忽略。
*   ⚡ **Preset 偵測與效能優化：** 根據專案類型自動過濾無關模組（例如：Flutter 專案不掃描 Docker，Next.js 專案加強掃描環境變數），掃描效率提升達 40%。
*   🎯 **OWASP LLM Top 10 報告：** 率先支援 `--format owasp-llm`，將掃描結果自動對應至全球標準的 AI 安全分類。
*   🤖 **AI 供應鏈與 MCP 審計：** 領先業界支援 Model Context Protocol (MCP) 設定文件審計與 AI 依賴真實性驗證。
*   🔑 **AST 驅動的機密資訊偵測：** 透過語法樹 (AST) 精準掃描 50+ 雲端業者密鑰，支援 Python, JS/TS, Go, Java, Dart 多語言環境。


## 🛠️ 快速上手

### 1. 安裝

```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

### 2. 初始化專案安全規則

依照當前專案類型**自動偵測並建議 Preset**，產生相對應的 `.ghostcheckignore` 與 `ghostcheck.toml`：
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
*   **多國語言支援：** 可在 `ghostcheck.toml` 內自訂文件專用的安全關鍵字 (`custom_safe_keywords = ["避免"]`)，大幅降低非英文文件的誤判率。
*   **自動化就緒：** 原生支援 `--format json`、`html`、`sarif` 及 `owasp-llm`，提供標準化的合規報告輸出。

---

## 🧠 Powered by AgentCortex

### 為什麼採用 AgentCortex 架構？
本專案採用 [AgentCortex](https://github.com/KbWen/AgentCortex) 流程驅動 (Process-driven) 架構，這確保了 AI 開發過程中的高標準自治性、安全性考量，以及架構的可維護性。

<div align="center">

**由 [KbWen](https://github.com/KbWen) 為 AI 社群用心開發 ❤️**

</div>
