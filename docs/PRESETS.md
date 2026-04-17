# GhostCheck Framework Presets

v1.0.0 引入了**框架預設策略 (Framework Presets)**，讓 GhostCheck 從一個通用的掃描器進階為具備「框架感知」能力的專業工具。

## 為什麼需要 Presets？

不同的開發框架（如 Next.js 或 Flutter）面臨的安全威脅截然不同：
- **Next.js**: 關注 Vercel 環境變數洩漏、API Route 權限與前端依賴幻覺。
- **Flutter**: 關注 `pub.dev` 供應鏈污染、Android/iOS 原生設定安全與 Mobile Config 洩漏。

透過 Presets，GhostCheck 可以自動過濾無關的掃描模組，並針對特定框架的高風險點進行深度檢查。

## 支援的 Presets

| Preset | 適用對象 | 重點掃描模組 |
| :--- | :--- | :--- |
| `next.js` | Next.js, React, Vercel | `hallucination`, `secrets`, `env`, `api` |
| `flutter` | Flutter (iOS/Android), Dart | `hallucination`, `mobile`, `secrets`, `rules` |
| `django` | Django Project | `secrets`, `env`, `docker`, `iac` |
| `fastapi` | FastAPI Apps | `api`, `hallucination`, `docker`, `secrets` |
| `terraform`| IaC / Cloud Infra | `iac`, `secrets`, `ci_cd` |

## 如何使用

### 1. 自動偵測
當執行 `ghostcheck init` 時，GhostCheck 會根據目錄下的文件（如 `pubspec.yaml` 或 `next.config.js`）自動建議最適合的 Preset。

### 2. 手動指定
在執行掃描時，你可以透過 `--preset` 參數強制指定：
```bash
ghostcheck scan . --preset flutter
```

### 3. 設定檔固定
你也可以在 `ghostcheck.toml` 中固定專案使用的 Preset：
```toml
preset = "next.js"
severity_threshold = "MEDIUM"
```

## 隱私與效能
使用 Preset 可以大幅減少不必要的掃描路徑，例如在 `flutter` 預設下，掃描器會更專注於 `lib/` 與原生配置目錄，提升掃描效率達 40% 以上。

---
**由 GhostCheck 研發團隊維護。**
