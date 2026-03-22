<div align="center">

# 👻 GhostCheck
**為 AI 輔助開發時代量身打造的高性能、零依賴安全性掃描工具。**

[![版本](https://img.shields.io/badge/version-0.6.0-blue.svg?style=for-the-badge)](https://github.com/KbWen/security-tools)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg?style=for-the-badge)](https://www.python.org/)
[![授權](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*在 AI Agent 產出的內容進入 CI/CD 流程前，精準識別高風險漏洞與「幻覺」威脅。*

[English](README.md) | [繁體中文](README_zh-TW.md)

</div>

---

## 🚀 願景

AI Agent 正在重塑程式開發，但也帶來了全新的攻擊面。**GhostCheck** 彌補了傳統 SAST 與 AI 原生安全性之間的鴻溝，確保您的代碼在享受 AI 速度的同時，依然保持企業級的穩固與安全。

## ✨ v0.6.0 亮點更新

*   🎯 **零配置快速上手 (Zero-Config)：** 輸入 `ghostcheck init` 就能針對您的專案技術堆疊，一秒生成最佳實踐安全配置。
*   🔍 **聰明的 Git 整合掃描：** 拒絕全局慢速掃描。現在支援針對預備提交 (`ghostcheck scan --staged`) 或尚未提交的變更 (`--diff`) 進行精準掃描。
*   🔑 **海量密鑰與威脅偵測：** 內建支援 30+ 雲端供應商 (AWS, GCP, Stripe, GitHub 等)，並結合 AST 語法樹解析抓出被拆分拼接的密鑰。
*   🛡️ **無痛的誤判排除機制：** 可透過 `ghostcheck.toml` 設定全局黑名單，或是在程式碼中加入 `# ghostcheck:disable` 進行單行白名單豁免。
*   ⚡ **uv CI 加速整合：** 工作流程全面引入 `uv` 高速依賴解析，矩陣測試與安裝速度飆升 10 倍。

## 🛠️ 快速上手

### 1. 安裝

```bash
pip install ghostcheck
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

<<<<<<< Updated upstream
=======
## 🧠 Powered by AgentCortex

### 為什麼採用 AgentCortex 架構？
本專案採用 [AgentCortex](https://github.com/KbWen/AgentCortex) 流程驅動 (Process-driven) 架構，這確保了 AI 開發過程中的高標準自治性、安全性考量，以及架構的可維護性。

<div align="center">

>>>>>>> Stashed changes
**由 [KbWen](https://github.com/KbWen) 為 AI 社群用心開發 ❤️**

</div>
