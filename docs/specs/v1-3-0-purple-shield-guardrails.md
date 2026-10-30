---
title: "GhostCheck v1.3.0 — Purple Shield & Agentic Boundary Guard"
status: frozen
version: "1.3.0"
created: "2026-10-30"
updated: "2026-10-30"
file_relationship: "INDEPENDENT (advances pending _product-backlog.md items E7-F1, E7-F4, E8-F1, E9-F2, E9-F3, E10-F1)"
---

# Specification: GhostCheck v1.3.0 — Purple Shield & Agentic Boundary Guard

## 1. Goal & Problem Statement

Modern agentic development introduces attack vectors across retrieved context (RAG/Vector DB/Memory), multimodal/binary inputs, and tool subprocess boundaries. Drawing architectural patterns from recent industry open-source security toolkits (**Meta Purple Llama Code Shield & Prompt Guard**, **Microsoft PyRIT** evasion converters, and **Google Magika / Mantis** boundary checks), GhostCheck v1.3.0 delivers three zero-dependency, deterministic, low-false-positive scanner plugins designed for parallel subagent implementation:

1. **`RagMemoryAuditor` (`src/ghostcheck/checks/rag_memory_auditor.py`)** — Covers Backlog `E7-F1`, `E8-F1`, `E10-F1`:
   Detects indirect prompt injection, PyRIT-style encoded jailbreak payloads (Base64 / Hex / ROT13), and dormant directive overrides across RAG knowledge documents, `.jsonl` datasets, persistent Agent Memory files (`MEMORY.md`, `*memory*.json`, `.cursor/memory*`), and Vector DB metadata ingestion calls (`Chroma`, `Pinecone`, `Qdrant`, `Weaviate`).
2. **`MultimodalPolyglotScanner` (`src/ghostcheck/checks/multimodal_polyglot_scanner.py`)** — Covers Backlog `E7-F4`:
   Provides Magika-inspired zero-dependency magic-byte header verification (detecting executables/scripts/archives masquerading behind benign image/document extensions) and parses PNG (`tEXt`/`iTXt`), JPEG (`COM`/EXIF ASCII), and SVG (`<desc>`, `<title>`, zero-opacity/zero-font hidden text) for steganographic prompt injections targeting vision-capable coding agents.
3. **`EnvEgressGuard` (`src/ghostcheck/checks/env_egress_guard.py`)** — Covers Backlog `E9-F2`, `E9-F3`:
   Audits Python and JavaScript/TypeScript AST/code for subprocess invocations (`subprocess.run`/`Popen`, `os.system`, `child_process.exec`/`spawn`) inside agent/MCP modules that leak ambient `os.environ` / `process.env` LLM credentials (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GITHUB_TOKEN`) to child processes, and audits agent container manifests (`docker-compose*.yml`, `devcontainer.json`) for dangerous `network_mode: host` or unrestricted egress in autonomous agent services.

---

## 2. Acceptance Criteria (AC)

- **AC-1 (`RagMemoryAuditor` — Indirect & Encoded Injection Detection)**:
  - Plugin `name` MUST be `"rag_memory_auditor"`.
  - Scans RAG/memory files (`*.jsonl`, `*memory*.md`, `*memory*.json`, `knowledge/**`, `rag/**`, `prompts/**`) for indirect prompt injection directives (`ignore all previous instructions`, `system override`, `<|im_start|>system`) and **PyRIT-style encoded payloads** (decodes suspicious Base64/Hex blobs >= 24 chars and checks decoded text for injection directives) → emits `rag_poisoning_encoded_payload` (`CRITICAL`) or `memory_poisoning_directive` (`HIGH`).
  - Scans Python/JS source files for Vector DB ingestion calls (`.add_texts`, `.add_documents`, `.upsert`) passing unsanitized external/raw user metadata fields without filtering → emits `vectordb_metadata_poisoning_risk` (`MEDIUM`).
  - Defensive documentation lines (e.g., lines containing negative guardrail context like `never`, `prohibited`, `detect`, `防止`, `禁止`) MUST NOT trigger false positives unless hidden zero-width characters or encoded payloads are used.

- **AC-2 (`MultimodalPolyglotScanner` — Magic-Byte Spoofing & Vision Metadata Injection)**:
  - Plugin `name` MUST be `"multimodal_polyglot_scanner"` and class attribute `supports_binary = True`.
  - **Magic-Byte / Polyglot Mismatch**: Reads up to the first 64 KB in binary mode (`'rb'`). Flags files with benign image/text extensions (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.pdf`, `.txt`, `.md`, `.csv`) whose header starts with executable or archive magic bytes (`\x7fELF`, `MZ` PE header with `PE\x00\x00` offset check, `#!/` shebang inside image extensions, or `PK\x03\x04` ZIP polyglot appended/prepended to images) → emits `polyglot_magic_byte_mismatch` (`CRITICAL`).
  - **Vision Metadata Injection**:
    - Parses PNG chunks (`tEXt`, `zTXt` via `zlib`, `iTXt`) and JPEG segments (`0xFFFE` COM comment, `0xFFE1` APP1/EXIF ASCII strings) for prompt injection directives → emits `multimodal_metadata_injection` (`CRITICAL`).
    - Scans `.svg` files for prompt injection directives inside `<desc>`, `<title>`, `<!-- comments -->`, or hidden `<text>` elements (`font-size="0"`, `opacity="0"`, `display:none`) → emits `multimodal_svg_hidden_injection` (`HIGH`).

- **AC-3 (`EnvEgressGuard` — Subprocess Secret Leakage & Agent Egress Boundary)**:
  - Plugin `name` MUST be `"env_egress_guard"`.
  - **Shadow AI Env Leakage (`E9-F3`)**: Scans Python (`ast`) and JS/TS files for subprocess execution (`subprocess.run`, `subprocess.Popen`, `subprocess.call`, `child_process.exec`, `child_process.spawn`) when the file also references LLM/Agent contexts (`mcp`, `FastMCP`, `tool`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) and either passes `env=os.environ` / `env=process.env` explicitly OR omits `env=` while executing variable/dynamic commands without an explicit allowlist dict → emits `shadow_env_subprocess_leak` (`HIGH`). Safe calls passing a literal allowlist dict (e.g., `env={"PATH": "/usr/bin"}`) MUST NOT trigger.
  - **Agent Container Egress Audit (`E9-F2`)**: Scans `docker-compose*.yml`, `compose*.yml`, and `devcontainer.json` defining AI agent services (`openhands`, `swe-agent`, `autogen`, `crewai`, `mcp`, `langchain`, `ollama`, `vllm`) that set `network_mode: host` (`CRITICAL` → `agent_egress_host_network`) or omit `internal: true` / egress isolation when mounting sensitive host workspaces (`MEDIUM` → `agent_egress_unrestricted`).

- **AC-4 (`Scanner` Binary Pass-Through, Preset Parity & OWASP LLM Top 10 Mapping)**:
  - `Scanner._process_single_file` MUST allow plugins with `getattr(plugin, 'supports_binary', False) is True` to inspect safe paths even when `_read_file_safe` returns `None` (binary file), while avoiding duplicate execution on text files (`.svg`).
  - `enabled_modules` in `Scanner._process_single_file` and application presets (`next.js`, `flutter`, `django`, `fastapi`) in `PresetManager` MUST include `"rag_memory"`, `"multimodal_polyglot"`, and `"env_egress"` (`terraform` preset MUST remain free of `docker` and `hallucination` per `tests/test_v1_0_0_presets.py`, adding `"env_egress"` only if safe).
  - `src/ghostcheck/data/owasp_mapping.json` MUST map all 7 new rule emission IDs (`LLM01: Prompt Injection` for RAG/Memory/Multimodal injections; `LLM02: Sensitive Information Disclosure` for `shadow_env_subprocess_leak`; `LLM06: Excessive Agency` for `polyglot_magic_byte_mismatch`, `agent_egress_host_network`, `agent_egress_unrestricted`).
  - `ghostcheck list-checks` in `src/ghostcheck/cli.py` MUST list `rag_memory`, `multimodal_polyglot`, and `env_egress`.

- **AC-5 (Zero False Positives & Self-Scan Grade A 100/100)**:
  - `Scanner._is_self_scan_exempt` MUST exempt pattern-definition strings inside `src/ghostcheck/checks/` and deliberate test fixtures in `tests/` for the new rule IDs while never exempting real leaked secrets.
  - Running `ghostcheck scan .` on the GhostCheck repository MUST achieve **Grade A (100/100)** with `0` actionable findings.

- **AC-6 (Test Suite, Packaging & Documentation Sync)**:
  - New TDD test suite `tests/test_v1_3_0_purple_shield.py` MUST verify happy path, benign/zero-FP path, and boundary/malformed input resilience for all 3 new plugins + `Scanner` binary pass-through + OWASP LLM mapping.
  - All existing 417 tests + new v1.3.0 tests MUST pass (`pytest`), `uv lock --check` MUST pass after bumping version to `1.3.0` across `pyproject.toml`, `src/ghostcheck/__init__.py`, `src/ghostcheck/checks/hallucination.py`, `uv.lock`, `README.md`, `README_zh-TW.md`, and `docs/specs/_product-backlog.md`.

---

## 3. Subagent Interface Contract

All three subagent modules MUST strictly adhere to `BaseScannerPlugin` (`src/ghostcheck/interfaces.py`):

```python
class <PluginClassName>(BaseScannerPlugin):
    supports_binary: bool = False  # True ONLY for MultimodalPolyglotScanner

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        # Returns list of dicts:
        # {
        #   "file": file_path,
        #   "line": int (>= 1),
        #   "name": "<exact_rule_id>",
        #   "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
        #   "message": "<clear actionable remediation hint>",
        #   "context": "<redacted/truncated snippet <= 120 chars>"
        # }
```

- **Logging & Exceptions**: Every `try...except` block MUST log via `logger = logging.getLogger(__name__); logger.debug(...)`. Bare `except Exception: pass` is strictly prohibited.
- **Thread Safety**: Plugins are shared across `ThreadPoolExecutor` workers; `scan()` MUST be pure/stateless per call (no mutable `self._current_file` attributes).

---

## 4. Non-Goals

- Do NOT add external dependencies (`pillow`, `python-magic`, `onnxruntime`, `torch`, `pyyaml`) to `pyproject.toml` — use Python standard library (`struct`, `zlib`, `base64`, `binascii`, `ast`, `re`, `xml.etree.ElementTree`) exclusively.
- Do NOT execute untrusted files or spawn containers dynamically.
- Do NOT modify `docker` or `hallucination` exclusions in the `terraform` preset.

## 5. Constraints & Rollback

- **Max File Read Ceiling**: Binary header/metadata reads MUST cap at `2 MB` (and `64 KB` for quick header checks) to guarantee sub-millisecond performance and zero OOM risk.
- **Rollback Strategy**: All 3 new checkers live in isolated files under `src/ghostcheck/checks/`; removing the 3 files and reverting the registration entries in `scanner.py`, `presets/manager.py`, `cli.py`, and `owasp_mapping.json` cleanly restores v1.2.15 behavior in <1 minute.
