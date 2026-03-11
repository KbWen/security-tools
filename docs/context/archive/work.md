# Work Log: work

- Classification: medium-feature
- Classified by: codex
- Frozen: true
- Created Date: 2026-02-27

## Scope / Non-Goals

- Scope:
  - 將治理文件對齊 vNext：SSoT、狀態機、handoff/ship gate、token 治理。
  - 補齊跨平台（Codex Web/App）一致規範。
- Non-goals:
  - 不改動業務程式碼。
  - 不新增 CI 自動化腳本。

## Done

- 針對「降低讀取文件 token 消耗」補強治理條款：新增架構精神優先原則與 release 後完整檢查清單。
- 補充 `docs/CODEX_PLATFORM_GUIDE.md` 的三平台檔案放置規範（`.agent/skills` 與 `.agents/skills` 對齊）與最小檢查。
- 完成 `current_state.md` 實體化，移除 placeholder。
- 建立 canonical state machine（含唯讀指令、legacy mapping）。
- 更新 `/plan`、`/test-skeleton`、`/help`、`/handoff`、`/ship` 工作流規範。
- 新增 token 治理文件 `docs/guides/token-governance.md`。

## In Progress

- 完成 release 後巡檢與證據整理，準備 commit 與 PR。

## Blockers

- 無。

## Next

- 執行 `./.agent/superpowers/validate.sh`。
- 以 `git diff` 檢查 scope。
- commit + 建立 PR。

## Risks

- 狀態機命名切換可能造成使用習慣落差。
- hard gate 變嚴可能增加初期操作摩擦。

## Token Notes

- Round Count: 1
- Repeated Explanation: N
- Fast Lane Applied: N

## References

- Docs:
  - `docs/context/current_state.md`
  - `docs/guides/token-governance.md`
  - `docs/CODEX_PLATFORM_GUIDE.md`
  - `docs/adr/ADR-001-vnext-self-managed-architecture.md`
- Code/Config Paths:
  - `.agent/superpowers/policies/state_machine.md`
  - `.agent/workflows/plan.md`
  - `.agent/workflows/handoff.md`
  - `.agent/workflows/ship.md`
  - `.agent/rules/engineering_guardrails.md`
- Work Log:
  - `docs/context/work/work.md`
