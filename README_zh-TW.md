# 👻 GhostCheck

[![版本](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/KbWen/security-tools)
[![授權](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-yellow.svg)](https://www.python.org/)

**GhostCheck** 是一個為 AI 輔助開發時代量身打造的高性能、零依賴安全性掃描工具。它能在 AI Agent 產出的內容進入 CI/CD 流程前，精準識別高風險漏洞與「幻覺」威脅。

---

## 🚀 願景

AI Agent 正在重塑世界，但也帶來了新的攻擊面。**GhostCheck** 彌補了傳統 SAST 與 AI 原生安全性之間的鴻溝，確保您的代碼在享受 AI 速度的同時依然穩如泰山。

## 🛡️ 核心能力

- **🔍 幻覺套件偵測 (Hallucination Detection)**：自動驗證依賴項，在安裝前標記 AI 虛構（幻覺）的套件。
- **🔑 情境感知金鑰掃描 (Context-Aware Secrets)**：針對終端機日誌、AI 對話記錄與源碼中的 API 金鑰與 Token 進行專業偵測。
- **📜 Agent 規則審核 (Agent Rules Linter)**：審查 `.agent`、`.cursorrules` 等指令檔，找出危險權限或指令執行風險。
- **⚡ 零基礎設施依賴**：單一文件、純 Python 引擎。無需資料庫、無需 Docker、無需外部 API。

## 🛠️ 快速上手

### 安裝

```bash
pip install -e .
```

### 立即掃描

```bash
# 掃描整個專案的安全性風險
ghostcheck scan .

# 執行互動式展示了解實際運作
ghostcheck demo
```

## 📋 功能與指令

| 功能 | 指令 | 目標 |
| :--- | :--- | :--- |
| **完整安全掃描** | `ghostcheck scan` | 整個工作區 |
| **依賴項檢查** | `ghostcheck check-deps` | `requirements.txt`, `package.json` |
| **機密資訊偵測** | `ghostcheck check-secrets` | 日誌、源碼、文件 |
| **Agent 規則審核** | `ghostcheck check-rules` | `.agent/`, `.cursor/` |

## ⚙️ 進階配置

GhostCheck 遵循專業的忽略規則：
- 建立 `.ghostcheckignore` 來排除特定路徑。
- 使用 `--severity [CRITICAL|HIGH|MEDIUM|LOW]` 過濾嚴重等級。
- 使用 `--format json` 導出結果以進行自動化整合。

---

**由 [KbWen](https://github.com/KbWen) 為 AI 社群用心開發 ❤️**
