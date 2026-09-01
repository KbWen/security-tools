import os
import sys
import shutil
import tempfile
import subprocess
import json
import pathlib

# Ensure we use python with ghostcheck installed or PYTHONPATH
def run_ghostcheck_cli(args, cwd):
    cmd = [sys.executable, "-m", "ghostcheck.cli"] + args
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath("src") + os.pathsep + env.get("PYTHONPATH", "")
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    return res

def simulate_realworld_projects():
    base_tmp = tempfile.mkdtemp(prefix="ghostcheck_simulation_")
    print(f"=== Starting Downstream Real-World Simulation at: {base_tmp} ===\n")
    
    results = {}

    try:
        # =====================================================================
        # Simulation Project 1: Next.js + TypeScript Modern Web App (Full Stack)
        # =====================================================================
        p1 = os.path.join(base_tmp, "nextjs_ai_app")
        os.makedirs(os.path.join(p1, "pages", "api"), exist_ok=True)
        os.makedirs(os.path.join(p1, ".next", "cache"), exist_ok=True)
        os.makedirs(os.path.join(p1, "node_modules", "somepkg"), exist_ok=True)
        
        # package.json with authorized & unauthorized deps
        with open(os.path.join(p1, "package.json"), "w", encoding="utf-8") as f:
            json.dump({
                "name": "nextjs-ai-app",
                "dependencies": {
                    "next": "14.2.0",
                    "react": "18.3.0",
                    "openai": "4.50.0"  # Unauthorized AI SDK in client/server without approval
                }
            }, f, indent=2)

        # Build cache with random hashes (should be ignored automatically)
        with open(os.path.join(p1, ".next", "cache", "build_manifest.js"), "w", encoding="utf-8") as f:
            f.write("const HASH = 'a1b2c3d4e5f678901234567890abcdef12345678';\n")

        # API Route with real leak: hardcoded OpenAI live secret
        with open(os.path.join(p1, "pages", "api", "chat.ts"), "w", encoding="utf-8") as f:
            f.write("""
// Real leak:
const API_KEY = "sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef";
import { OpenAI } from 'openai';
export default function handler(req, res) {
    const ai = new OpenAI({ apiKey: API_KEY });
    res.status(200).json({ status: 'ok' });
}
""")

        # Clean Component with false-positive candidates (Tailwind kebab-case, UUIDs, harmless doc comments)
        with open(os.path.join(p1, "pages", "index.tsx"), "w", encoding="utf-8") as f:
            f.write("""
import React from 'react';
// Tailwind class with dashes and entropy
export default function Home() {
    const componentId = "usr-profile-modal-uuid-7890-abcd-ef01";
    return <div className="bg-gradient-to-r from-blue-500 to-indigo-600 shadow-2xl p-8 rounded-xl">{componentId}</div>;
}
""")

        def parse_findings(stdout_str):
            try:
                data = json.loads(stdout_str)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    return data.get("findings", [])
                return []
            except Exception:
                return []

        res1 = run_ghostcheck_cli(["scan", ".", "--format", "json"], cwd=p1)
        findings1 = parse_findings(res1.stdout)
        
        # Verify: Caught the real secret and unauthorized SDK, ignored .next cache, 0 FP on index.tsx
        found_secret = any("secret" in str(f.get("name") or f.get("pattern_name", "")).lower() for f in findings1)
        found_ai = any("unauthorized" in str(f.get("name") or f.get("pattern_name", "")).lower() for f in findings1)
        fp_in_next = any(".next" in str(f.get("file", "")) for f in findings1)
        fp_in_index = any("index.tsx" in str(f.get("file", "")) for f in findings1)

        results["NextJS_Simulation"] = {
            "Total_Findings": len(findings1),
            "Caught_Real_Secret": found_secret,
            "Caught_Shadow_AI": found_ai,
            "Ignored_Next_Cache": not fp_in_next,
            "Zero_FP_on_Clean_TSX": not fp_in_index
        }

        # =====================================================================
        # Simulation Project 2: FastAPI + Agentic AI Backend (Python)
        # =====================================================================
        p2 = os.path.join(base_tmp, "agentic_backend")
        os.makedirs(os.path.join(p2, "app", "routers"), exist_ok=True)
        os.makedirs(os.path.join(p2, ".venv", "lib"), exist_ok=True)
        
        # requirements.txt
        with open(os.path.join(p2, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("fastapi==0.111.0\nuvicorn==0.30.0\nlangchain==0.2.5\n")

        # Fake venv file (must be ignored)
        with open(os.path.join(p2, ".venv", "lib", "dummy.py"), "w", encoding="utf-8") as f:
            f.write("DUMMY_KEY = 'AKIA1234567890123456'\n")

        # Router with obfuscated AI import and Local LLM URL
        with open(os.path.join(p2, "app", "routers", "agent.py"), "w", encoding="utf-8") as f:
            f.write("""
import os
import importlib
# Obfuscated dynamic import:
ai_pkg = importlib.import_module('lan' + 'gchain')
# Local unapproved Ollama URL:
LOCAL_LLM = "http://127.0.0.1:11434/api/generate"

def run_task():
    return {"status": "running"}
""")

        # Clean utility with normal regex, mathematical formulas, and safe variable names
        with open(os.path.join(p2, "app", "utils.py"), "w", encoding="utf-8") as f:
            f.write("""
import math
# Safe doc comments in Chinese:
# 這是系統核心工具函式，用來計算 Shannon 資訊熵與文字正規化
def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy
""")

        res2 = run_ghostcheck_cli(["scan", ".", "--format", "json"], cwd=p2)
        findings2 = parse_findings(res2.stdout)

        caught_obfuscated = any("unauthorized" in str(f.get("name") or f.get("pattern_name", "")).lower() for f in findings2)
        caught_local_llm = any("local_llm" in str(f.get("name") or f.get("pattern_name", "")).lower() for f in findings2)
        fp_in_venv = any(".venv" in str(f.get("file", "")) for f in findings2)
        fp_in_utils = any("utils.py" in str(f.get("file", "")) for f in findings2)

        results["FastAPI_Simulation"] = {
            "Total_Findings": len(findings2),
            "Caught_Obfuscated_AI_Import": caught_obfuscated,
            "Caught_Local_LLM_Endpoint": caught_local_llm,
            "Ignored_Venv": not fp_in_venv,
            "Zero_FP_on_Math_Chinese_Doc": not fp_in_utils
        }

        # =====================================================================
        # Simulation Project 3: Production Clean Monorepo (Strict Zero False Positive Check)
        # =====================================================================
        p3 = os.path.join(base_tmp, "clean_enterprise_repo")
        os.makedirs(os.path.join(p3, "src"), exist_ok=True)
        os.makedirs(os.path.join(p3, "docs"), exist_ok=True)
        os.makedirs(os.path.join(p3, ".github", "workflows"), exist_ok=True)

        with open(os.path.join(p3, "src", "service.py"), "w", encoding="utf-8") as f:
            f.write("""
import os
# Safely reading environment variable (no hardcoded secrets)
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_ENDPOINT = "https://api.mycompany.internal/v1/health"

class ServiceHandler:
    def __init__(self, token: str = None):
        self.token = token or os.getenv("APP_TOKEN")
""")

        with open(os.path.join(p3, "docs", "README.md"), "w", encoding="utf-8") as f:
            f.write("""
# Project Documentation
To run tests locally:
```bash
export API_KEY="your-api-key-here"
pytest
```
""")

        with open(os.path.join(p3, ".github", "workflows", "ci.yml"), "w", encoding="utf-8") as f:
            f.write("""
name: CI
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38
""")

        res3 = run_ghostcheck_cli(["scan", ".", "--format", "json"], cwd=p3)
        findings3 = parse_findings(res3.stdout)
        
        # Only INFO level logs allowed on clean production repo (0 Security Warnings)
        warning_findings = [f for f in findings3 if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        if warning_findings:
            print("WARNING FINDINGS in Clean Enterprise Repo:", json.dumps(warning_findings, indent=2))

        results["Clean_Enterprise_Repo"] = {
            "Total_Findings": len(findings3),
            "Security_Warnings_Count": len(warning_findings),
            "Zero_False_Positives": len(warning_findings) == 0
        }

    finally:
        shutil.rmtree(base_tmp, ignore_errors=True)

    print("=== Simulation Results ===")
    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    simulate_realworld_projects()
