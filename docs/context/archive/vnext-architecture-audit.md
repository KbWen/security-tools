# Handoff: vNext Architecture Audit & Design Decisions

## Task Meta

- Classification: **architecture-change**
- Classified by: Claude (Antigravity)
- Frozen: true
- Created: 2026-02-27
- Status: **audit complete → pending implementation**
- Expiry: 本檔在 Phase 4 (ADR 凍結) 完成後 archive

---

## 1. Task Classification

**`architecture-change`**

理由：vNext 涉及跨模組結構性變更——新增 `docs/context/` 狀態模型、重新定義 governance gates、改寫 bootstrap/handoff 流程，屬於系統邊界與資料流的根本性調整。

---

## 2. Scope

### In-Scope（本次已完成）

- ✅ 完成 vNext 設計文件的系統設計審計
- ✅ 識別 4 類問題（矛盾 / 退化 / 漏洞 / 多 agent 失效）
- ✅ 與使用者逐條確認決議（共 11 條）
- ✅ 定義多 agent 規則、token 優化策略、handoff 清理機制
- ✅ 產出最終審計報告 + 本 handoff

### In-Scope（下個模型需執行）

- 結構清理（`.agent/superpowers/` 遷移廢棄）
- 建立 `docs/context/` 目錄結構
- 26 個 workflow 微調對齊 vNext
- 規則文件更新（guardrails / AGENTS.md / README）
- ADR 凍結

### Out-of-Scope

- ❌ 不產生全新替代架構（基於 vNext 修正，不重來）
- ❌ 不改變現有 workflow 的數量（26 個全保留）
- ❌ 不實作 CI/CD 自動化（只定義規則，自動化是 follow-up）

---

## 3. Frozen Decisions（11 條，不可重新設計）

> ⚠️ 下個模型**必須遵守**以下決議。若有疑慮，向人類提出 reclassify 請求，不得自行修改。

| # | 決議 | 類型 |
|---|---|---|
| 1 | `tiny-fix` 有 fast-path：`classify → one-line scope → do → inline evidence → done`，豁免 bootstrap/handoff/work log | Gate Policy |
| 2 | Classification escalation rules：改 public API → `behavior-change`，跨模組 → `feature`，新目錄 → `feature`，改資料流 → `architecture-change` | Classification |
| 3 | ADR index 從 `current_state.md` 移除，改為目錄掃描 `docs/adr/` | State Model |
| 4 | Work log 命名 `<branch-name>.md`，ship 後 archive 到 `docs/context/archive/<name>--<date>.md` | Naming |
| 5 | Evidence 每 gate 有最低標準（見 §5 Required Gates） | Gate Policy |
| 6 | `.agent/superpowers/` 確認廢棄（Codex/Antigravity 官方不讀此路徑） | Deprecation |
| 7 | 26 個 workflow 全數保留，微調對齊 vNext 哲學 | Scope |
| 8 | Spec + Plan 合併輸出為合規行為（bootstrap 後可一次輸出兩者） | Gate Policy |
| 9 | Classification 在 bootstrap freeze 並寫入 work log header，後續 agent 不得重分類 | Multi-Agent |
| 10 | `current_state.md` 只有 `/ship` agent 可寫，其餘 agent 唯讀 | State Model |
| 11 | Handoff lifecycle：active → archived (30 天) → expired (delete) | Lifecycle |

---

## 4. Required Changes（檔案清單）

### Phase 1：結構清理

| 動作 | 路徑 | 說明 |
|---|---|---|
| MIGRATE | `.agent/superpowers/policies/` | 有價值內容遷入 `.agent/rules/` 或 `docs/` |
| MIGRATE | `.agent/superpowers/commands.md` | 合併到 `.agent/workflows/commands.md` |
| EVALUATE | `.agent/superpowers/validate.sh` | 若仍需要則搬到 `tools/`，否則刪除 |
| DELETE | `.agent/superpowers/` | 遷移完成後整目錄刪除 |
| NEW | `docs/context/current_state.md` | 全域讀取檔模板（< 50 行） |
| NEW | `docs/context/archive/.gitkeep` | Archive 目錄佔位 |

### Phase 2：Workflow 微調

| 動作 | 路徑 | 說明 |
|---|---|---|
| MODIFY | `.agent/workflows/bootstrap.md` | 加入 self-classification + escalation rules |
| MODIFY | `.agent/workflows/handoff.md` | 加入 work log reference + archive 動作 |
| MODIFY | `.agent/workflows/ship.md` | 加入 `current_state.md` 更新責任 |
| REVIEW | `.agent/workflows/*.md` (其餘) | 確認與 vNext gate 表不矛盾 |

### Phase 3：規則文件更新

| 動作 | 路徑 | 說明 |
|---|---|---|
| MODIFY | `.agent/rules/engineering_guardrails.md` | 整合 classification escalation rules |
| MODIFY | `AGENTS.md` | 引用 vNext governance model |
| MODIFY | `README.md` | 版本升級 + 新目錄結構 |

### Phase 4：凍結

| 動作 | 路徑 | 說明 |
|---|---|---|
| NEW | `docs/adr/ADR-001-vnext-self-managed-architecture.md` | 將最終設計凍結為 ADR |

---

## 5. Required Gates（流程與限制）

### Gate 表（vNext 最終版）

| Category | Mandatory Gates | 最低 Evidence 標準 |
|---|---|---|
| `tiny-fix` | classify + inline plan + inline evidence | diff summary + one-line verification |
| `behavior-change` | bootstrap + spec + plan + review + regression evidence + handoff | before/after behavior + test output |
| `feature` | bootstrap + spec + plan + review + test + handoff | test output + 可驗證 demo 步驟 |
| `architecture-change` | bootstrap + ADR + spec + plan + migration/rollback + handoff | migration plan + rollback verification |
| `hotfix` | systematic debugging + evidence + retro + handoff | root cause + fix verification + retro |

### Classification Escalation Rules

| 觸發條件 | 最低分類 |
|---|---|
| 觸及 `exports` / public API / function signature | `behavior-change` |
| 觸及 >1 module 的 import graph | `feature` |
| 新增目錄 | `feature` |
| 改變資料流 / 系統邊界 | `architecture-change` |
| 改變 config 預設值影響使用者行為 | `behavior-change` |

### Multi-Agent Rules

1. **Work Log = 一個 branch 一個**，命名 `docs/context/work/<branch-name>.md`
2. **Classification freeze**：bootstrap 凍結分類，寫入 work log header，後續 agent 不得重分類
3. **`current_state.md`**：只有 `/ship` agent 可寫，其餘唯讀
4. **Continuation**：讀 work log → 讀 `current_state.md` → 若 work log 資訊不足先補完再工作
5. **Evidence 禁令**：禁止 AI 自行生成不可驗證的聲明作為 evidence

### Token 優化規則

1. `tiny-fix` fast-path 省略 bootstrap/work log/handoff
2. Spec + Plan 允許合併輸出
3. Work log 每 section ≤ 5 bullets，禁止 copy-paste diff
4. `current_state.md` 目標 < 50 行，只用 bullet points
5. Continuation 時禁止復述 work log 內容

---

## 6. Risks / Open Questions

### Risks

| 風險 | 等級 | 緩解 |
|---|---|---|
| Workflow 微調範圍可能擴大 | 🟡 Medium | 僅修改與 vNext gate 衝突的部分，不做全面重寫 |
| `superpowers/` 遷移可能遺漏引用 | 🟡 Medium | 遷移後 grep 全倉確認無殘留引用 |
| `current_state.md` 首版內容需人類審閱 | 🟢 Low | 產出後由人類在 review 階段確認 |
| 跨模型 classification 一致性 | 🟡 Medium | 已凍結 classification freeze 機制（決策 #9） |

### Open Questions

1. **`current_state.md` 的首版內容**：system map 部分需要人類輸入（專案的 one-liner intent 和 guardrails 由人類定義）
2. **Archive 自動清理**：定義了 30 天規則，但 CI script 尚未實作。是否需要在本輪實作？（建議：先手動，後續做）
3. **Symlinks**：`.agents/skills` 是 `.agent/skills` 的 symlink。廢棄 `.agent/superpowers/` 後，是否也要清理 `.agents/` 下的對應 symlink？

---

## 7. References

### 原始設計文件

- **vNext 設計哲學**：見下方§8 完整收錄
- **審計報告**：Antigravity brain artifact `vnext_system_audit.md`（含完整問題分析、決議對照、token 策略）

### 現有專案關鍵檔案

| 檔案 | 關聯 |
|---|---|
| `README.md` | Phase 3：版本升級說明 |
| `AGENTS.md` | Phase 3：引用 vNext governance |
| `.agent/rules/engineering_guardrails.md` | Phase 3：整合 escalation rules |
| `.agent/workflows/bootstrap.md` | Phase 2：加入 self-classification |
| `.agent/workflows/handoff.md` | Phase 2：加入 archive 動作 |
| `.agent/workflows/ship.md` | Phase 2：加入 current_state.md 寫入 |
| `.agent/superpowers/` (entire dir) | Phase 1：遷移後刪除 |

---

## 8. Original Design Philosophy（vNext 原始設計哲學，完整收錄）

> 以下是專案擁有者 (Human) 與 ChatGPT 共同討論產出的 vNext 設計初衷。
> 本段為**唯讀設計意圖**，下個模型在實作時必須持續對齊此哲學，不得偏離核心原則。

### 設計三原則

1. **主要目標**：優化 AI 開發時「越做越好」——每次迭代都比上次更有效率、更少重工
2. **最重要的約束**：減少 token 消耗。如果連小工作都會增加 token 消耗，代表設計需要修正
3. **模型流水線**：Claude Opus 4.6 做第一關（設計/審計），Gemini 3.1 Pro 對齊 Codex Web / Codex App / Google Antigravity，Gemini 3 Flash 實作

### Core Philosophy

> **This system is designed so that AI manages itself.**
> Humans provide intent and review decisions — not process, not memory, not checklists.

如果人類必須：

- 記住該寫哪份文件
- 記住檔案放哪裡
- 記住哪個 gate 適用
- 記住要做 handoff

👉 **設計就失敗了。**

### Target Environment

專為以下平台設計：Codex Web / Codex App / Google Antigravity

環境約束：

- 無持久化長期記憶
- Context window 限制
- 多日 / 中斷型工作
- Agent 切換
- 並行分支

因此：**Handoff 和 state reconstruction 是必要的，conversation history 不是可靠的系統狀態。**

### Self-Management Model

AI 自行分類任務為：`tiny-fix` / `behavior-change` / `feature` / `architecture-change` / `hotfix`，並自動套用對應的 governance gate（Lazy Governance）。

### Parallel-Safe State

- **Read-Only**：`docs/context/current_state.md`（全域上下文）
- **Write-Isolated**：`docs/context/work/<task>.md`（任務狀態）

### Non-Negotiable Gates

- Bootstrap 是唯一入口
- Documents 是 enforced assets（不是筆記）
- Handoff 是 hard gate（不可跳過，`tiny-fix` 除外）
- Ship 必須先 handoff

### System Guarantees

- 人類不需要記憶流程
- AI 自主決定治理強度
- 文件必須被引用或否決
- 程式碼與文件保持對齊
- 並行分支不衝突
- Handoff 可在 context loss 後存活
- Token 使用量隨時間遞減

### Explicit Non-Goals

本系統**不是**：prompt tricks / 人類任務管理 / GitHub workflow 替代 / 文檔官僚主義

本系統**是**：Agent OS / 自我調節的 AI 工作空間 / 長期工程記憶系統

---

## Handoff 清理機制

### 生命週期

```
Created (/bootstrap) → Active (working) → Shipped (/ship) → Archived → Expired
```

### 規則

- **Active** work logs: `docs/context/work/`，無時間限制
- **Archived**: `/ship` 時 AI 自動移至 `docs/context/archive/<name>--<date>.md`
- **保留期**: 30 天或 5 個 sprint
- **Expired**: 由人類或 CI 清理
- **Token 節省**: AI 啟動時不讀取 archive 目錄

### 本檔時效

Phase 4（ADR 凍結）完成後 → archive。在此之前，**下個模型必須讀取本檔作為工作起點**。
