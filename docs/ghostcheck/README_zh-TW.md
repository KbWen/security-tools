# GhostCheck

## 專為 AI 輔助開發流程設計的安全性掃描工具

GhostCheck 是一款零依賴 (Zero-dependency) 的命令列安全性掃描工具，旨在偵測 AI 模型產出中特有的風險。

## 核心功能

- **幻覺套件偵測 (Hallucination Detection)**: 標記 PyPI/npm 上不存在或過於新穎、疑似為 AI 幻覺產出的套件。
- **金鑰外洩掃描 (Secret Scanning)**: 在 AI 對話記錄（Chat Logs）或代碼中搜尋外洩的 API Key/Token，並根據檔案情境自動調整嚴重程度。
- **Agent 規則檢查 (Agent Rules Linter)**: 審核 `.agent`、`.cursor` 等 Agent 規則檔，找出具風險的權限設定或危險指令。
- **零運行時依賴**: 純 Python 實作，無需額外安裝執行環境套件。

## 安裝方式

```bash
pip install -e .
```

## 使用範例

### 執行完整掃描

```bash
ghostcheck scan .
```

### 檢查依賴套件

```bash
ghostcheck check-deps requirements.txt
ghostcheck check-deps package.json
```

### 掃描機密資訊

```bash
ghostcheck check-secrets ./docs
```

### 審查 Agent 規則

```bash
ghostcheck check-rules .agent/
```

### 即時展示

```bash
ghostcheck demo
```

## 選項說明

- `--format [console|json]`: 指定輸出格式。
- `--severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]`: 設定掃描結果的嚴重等級門檻。
- `--no-ignore`: 停用 `.ghostcheckignore` 過濾。
- `--no-color`: 停用終端機顏色顯示。

## 授權條款

MIT
