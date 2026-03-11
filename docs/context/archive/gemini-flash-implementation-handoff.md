# Handoff: vNext Architecture Implementation (Phase 2 & 3)

## Task Meta

- **Target Model**: Gemini 3 Flash (實作者)
- **Objective**: 根據先前的設計審計與平台對齊計畫，實作 AgentCortex vNext 的架構調整。
- **Context**: 此專案模板將供 Codex Web / Codex App / Google Antigravity 運行。
- **Status**: 準備實作

---

## 1. 原設計哲學與重要規則 (不可改動)

實作過程中，**必須嚴格遵守以下 vNext 核心哲學，不得因為實作方便而簡化或重設**：

1. **AI Self-Management**: AI 必須自行分類任務 (tiny-fix, behavior-change, feature, architecture-change, hotfix) 並自動套用對應的 governance gate (Lazy Governance)。人類只提供意圖與驗收標準。
2. **Parallel-Safe State**:
   - `current_state.md` 是唯讀的全域狀態。
   - `docs/context/work/<task>.md` 是寫入隔離的任務狀態 (Work Log)。
3. **Documents are Enforced Assets**: 文件必須被引用，不是隨意筆記。
4. **Handoff is a Hard Gate**: 每個非 `tiny-fix` 任務都必須透過 `/handoff` 產出摘要才能算結束 (`/ship`)，以確保跨回合/跨 Agent 的 context loss 安全。
5. **Token Optimization**: 在正確框架下，盡可能減少 token 消耗 (例如 `tiny-fix` 的 fast-path)。

---

## 2. 要新增/修改的實際檔案路徑與目的

### [新增] 目錄與基礎檔案

| 檔案路徑 | 目的 |
|---|---|
| `docs/context/work/.gitkeep` | 確保 git 能追蹤任務狀態目錄 |
| `docs/context/archive/.gitkeep` | 確保 git 能追蹤歸檔目錄 |
| `docs/context/current_state.md` | 初始化全域狀態模板（保持在 50 行以內，只使用 bullet points）。不寫入具體的 ADR 索引，改採「掃瞄 `docs/adr/`」的設計。 |
| `docs/adr/ADR-001-vnext-self-managed-architecture.md` | 凍結 vNext 設計決策，作為架構變更的唯一憑證。 |

⚠️ **注意**: `docs/context/` 已由前一模型建立目錄，但需要新增 `.gitkeep` 或初始化檔案。

### [修改] 工作流 (Workflows)

| 檔案路徑 | 目的 |
|---|---|
| `.agent/workflows/bootstrap.md` | 整合 5 級 Self-classification 機制，並新增「如果處於 Codex Web 環境，請主動向人類索取 `current_state.md` 及目前的 Work Log」的平台特化處理。 |
| `.agent/workflows/handoff.md` | 確保產出包含所有必填區塊（Done, In Progress, Blockers, Next, Risks, References）。如果是 Codex Web 環境，強制將 handoff 內容「印在對話框」讓人類複製；如果是 Antigravity/Codex App，則直接寫入檔案。 |
| `.agent/workflows/ship.md` | 配合新的寫入規則：允許在此步驟更新 `current_state.md`。同時加入將對應的 active work log 移至 `docs/context/archive/<name>--<date>.md` 的動作。 |

### [修改] 規則與全域設定 (Rules & Global)

| 檔案路徑 | 目的 |
|---|---|
| `.agent/rules/engineering_guardrails.md` | 寫入 Classification Escalation Rules 表格，並定義最低 Evidence 標準。明確指出 `tiny-fix` 的例外處理 (fast-path)。 |
| `AGENTS.md` | 導入新的 Multi-Agent Rules (Work Log 隔離與 Classification freeze)。重新定義「讀取優先級」，優先讀取 `docs/context/current_state.md` 而非盲目搜索 `docs/`。 |
| `README.md` | 更新版本說明。解釋新的 `docs/context/` 狀態模型設計。標註 `.agent/superpowers/` 目錄已進入 Deprecated 狀態。 |

### [標示棄用] 舊結構清理

| 檔案路徑 | 目的 |
|---|---|
| `.agent/superpowers/` | **不刪除**，僅在文件中（如 `README.md`）標示為 [DEPRECATED] 待未來安全移除。裡面部分指令與原則可根據需要先整併進 `.agent/workflows/commands.md` 或 `.agent/rules/`。 |

---

## 3. 不可改動的決策與限制

1. **保留 26 個 Workflow 檔案**: 絕對不可以刪除現有的任何 workflow，只能微調內容以符合新閘門與規則。
2. **`tiny-fix` 例外路徑**: `tiny-fix` (少於 3 檔修改且無語意變更) 必須有一條 fast-path，豁免完整的 `/bootstrap`、`/handoff` 以及 Work Log，以節省 token。
3. **`current_state.md` 寫入時機**:
   - 並非每次操作都能寫入。
   - 僅允許在 `architecture-change` 完成 review 後、執行 `/ship` 時，或有明確的「更新地圖任務」時才能更新。
4. **`validate.sh` 腳本位置**: 暫時保留在原位 (`.agent/superpowers/validate.sh`)，以將對現有系統的變動降到最低。
5. **分類凍結 (Classification Freeze)**: 一旦在 `/bootstrap` 被分類並寫入 work log 標頭後，後續的實作 Agent (含你自己) **不得自行重新分類**，除非人類使用者明確下達 `reclassify` 命令。

---

## 4. 實作時需要注意的事項

### Platform Mismatch 應對策略

Google Antigravity 與 Codex App 皆支援自動化的本地端檔案讀寫，但 **Codex Web 是純對話介面**。在修改 Workflow（特別是 `.agent/workflows/bootstrap.md` 和 `.agent/workflows/handoff.md`）時，務必區分並寫下明確的平台指令：

- **For Codex Web**: 「請將產出內容或摘要印在對話中，並提示人類保存到本地或餵給下一個 Thread。」
- **For Antigravity/Codex App**: 「請直接讀寫對應的 Markdown 檔。」

### 實作順序建議

為確保相依性正確且不破壞現有功能，強烈建議依循以下順序進行：

1. **目錄與基礎建設**: 先建立 `docs/context/` 內的檔案 (`current_state.md`, `archive/.gitkeep`, `work/.gitkeep`) 以及編寫 `ADR-001`。
2. **規則與全域更新**: 修改 `engineering_guardrails.md`、`AGENTS.md` 和 `README.md`。透過這裡確立大方向。
3. **Workflow 微調**: 最後再處理最影響執行流的 `.agent/workflows/bootstrap.md`, `handoff.md`, `ship.md` 檔案，確保其依賴的規則檔皆已到位。

---
> **To Gemini 3 Flash**:
> 這是對齊 Codex Web / Antigravity 的實作衝刺。請遵守以上指引，開始你的實作任務。
