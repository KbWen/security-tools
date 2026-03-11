# GhostCheck

**GhostCheck** 是一款專為 AI 協作開發工作流設計的 CLI 資安掃描工具。它能偵測傳統工具容易遺漏的風險：幻覺套件、AI 對話記錄中的金鑰洩漏，以及危險的 Agent 指令配置。

## 功能特性

- 🦄 **幻覺偵測 (Hallucination)**：識別 PyPI/npm 上不存在的虛擬套件。
- 🔑 **智慧金鑰掃描**：偵測 AI 日誌中的金鑰，並根據檔案類型自動調整嚴重度。
- 🛡️ **Agent 規則檢查**：掃描 `.agent/`, `.cursor/`, `.github/` 中的危險指令。
- 🚫 **忽略機制**：支援透過 `.ghostcheckignore` 排除檔案。
- 🚀 **展示模式**：透過 `ghostcheck demo` 立即體驗掃描效果。

## 安裝方式

```bash
git clone https://github.com/KbWen/security-tools.git
cd security-tools
pip install -e .
```

## 快速開始

```bash
# 執行包含範例弱點的展示掃描
ghostcheck demo

# 掃描當前目錄
ghostcheck scan .

# 檢查 requirements.txt 是否包含幻覺套件
ghostcheck check-deps requirements.txt
```

## 配置與設定

### .ghostcheckignore

在專案根目錄建立 `.ghostcheckignore` 檔案來排除特定路徑：

```text
# 忽略日誌檔
*.log
# 忽略依賴套件夾
node_modules/
```

## 授權條款

MIT
