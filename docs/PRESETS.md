# GhostCheck Framework Presets

v1.0.0 引入了**框架預設策略 (Framework Presets)**，讓 GhostCheck 從一個通用的掃描器進階為具備「框架感知」能力的專業工具。

## 💡 為什麼要有 Presets？

因為用 Next.js 踩的雷，跟用 Flutter 踩的坑，完全是兩碼子事！如果用同套標準去掃，不是整天跳一堆無關的 False Positive，就是真正致命的漏洞沒掃到。

*   **Next.js 專案**：你最怕的可能是 API Route 權限沒設好、前端一不小心把 `.env` 密鑰打包出去，或是 npm 套件又被 AI 幻覺給坑了。
*   **Flutter 專案**：你最擔心的則是 `pub.dev` 上的套件有沒有毒、Android/iOS 原生設定（像是 `AndroidManifest.xml`）有沒有門戶大開，或者 Mobile Config 不小心洩漏。

如果每次掃描都要手動調參數，工程師絕對會直接下 `Ctrl+C` 擺爛不掃了。

透過 **Presets（框架預設配置）**，GhostCheck 就能自動看懂你的專案型態，把無關的掃描模組直接遮蔽，只針對你用的框架進行深度「健檢」，省時又精準！

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
