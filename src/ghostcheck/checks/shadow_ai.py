import re
import os
import json

DEFAULT_AI_SDKS_PYTHON = {
    'openai', 'anthropic', 'langchain', 'llamaindex', 'google.generativeai',
    'google_generativeai', 'chromadb', 'groq', 'cohere', 'transformers',
    'huggingface_hub', 'instructor'
}

DEFAULT_AI_SDKS_JS = {
    '@google/generative-ai', 'openai', 'llamaindex', 'langchain',
    '@langchain/core', '@langchain/community', '@anthropic-ai/sdk',
    'chromadb', 'groq', 'cohere-ai'
}

DEFAULT_IDE_EXTENSIONS = {
    'github.copilot', 'github.copilot-chat', 'tabnine.tabnine-vscode',
    'codeium.codeium', 'supermaven.supermaven', 'cursor.cursor'
}

class ShadowAIDetector:
    def __init__(self, config=None):
        self.config = config or {}
        shadow_config = self.config.get("shadow_ai", {})
        
        # Load custom controls, normalizing to lowercase
        self.allowed_sdks = {x.lower() for x in shadow_config.get("allowed_sdks", [])}
        self.blocked_sdks = {x.lower() for x in shadow_config.get("blocked_sdks", [])}
        self.allowed_endpoints = {x.lower() for x in shadow_config.get("allowed_endpoints", [])}
        self.blocked_extensions = {x.lower() for x in shadow_config.get("blocked_extensions", [])}

        # Regexes
        self.python_import_pattern = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z0-9_-]+)')
        self.js_import_pattern = re.compile(
            r'(?:require\s*\(\s*["\']([^"\']+)["\']\s*\)|from\s+["\']([^"\']+)["\'])'
        )
        self.local_url_pattern = re.compile(
            r'(https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(?:11434|8080|8000|5000)(?:/[a-zA-Z0-9_.-]+)*)',
            re.IGNORECASE
        )
        self.local_env_vars = ['OLLAMA_HOST', 'OLLAMA_BASE_URL', 'LOCAL_LLM_URL', 'LLAMA_API_BASE', 'VLLM_API_KEY', 'OLLAMA_API_BASE']

    def is_sdk_python_unauthorized(self, sdk_name):
        sdk_lower = sdk_name.lower()
        if sdk_lower in self.allowed_sdks:
            return False
        if sdk_lower in self.blocked_sdks:
            return True
        if not self.blocked_sdks:
            return sdk_lower in DEFAULT_AI_SDKS_PYTHON
        return False

    def is_sdk_js_unauthorized(self, sdk_name):
        sdk_lower = sdk_name.lower()
        if sdk_lower in self.allowed_sdks:
            return False
        if sdk_lower in self.blocked_sdks:
            return True
        if not self.blocked_sdks:
            if sdk_lower in DEFAULT_AI_SDKS_JS:
                return True
            # Match namespaces (e.g. @google/generative-ai or @langchain/*)
            if any(sdk_lower.startswith(x) for x in ['@google/generative-ai', 'langchain', '@langchain/']):
                return True
        return False

    def is_extension_unauthorized(self, ext_id):
        ext_lower = ext_id.lower()
        if ext_lower in self.blocked_extensions:
            return True
        if not self.blocked_extensions:
            return ext_lower in DEFAULT_IDE_EXTENSIONS
        return False

    def scan_file(self, filepath, content):
        findings = []
        path_lower = filepath.replace('\\', '/').lower()
        filename = os.path.basename(path_lower)
        lines = content.split('\n')

        # 1. Manifest / Config files
        if filename == 'package.json':
            findings.extend(self._scan_package_json(filepath, content))
            return findings
        elif filename == 'requirements.txt':
            findings.extend(self._scan_requirements_txt(filepath, content, lines))
            return findings
        elif filename == 'pyproject.toml':
            findings.extend(self._scan_pyproject_toml(filepath, content, lines))
            return findings
        elif filename == 'extensions.json' and '.vscode' in path_lower:
            findings.extend(self._scan_extensions_json(filepath, content, lines))
            return findings

        # 2. Source Code Checks (Python)
        if filename.endswith('.py'):
            for i, line in enumerate(lines):
                # Python imports (GSA-01)
                match = self.python_import_pattern.match(line)
                if match:
                    pkg = match.group(1)
                    if self.is_sdk_python_unauthorized(pkg):
                        findings.append({
                            "name": "unauthorized_ai_sdk_python",
                            "rule_id": "GSA-01",
                            "severity": "MEDIUM",
                            "file": filepath,
                            "line": i + 1,
                            "message": f"Unauthorized Python AI SDK imported: '{pkg}'.",
                            "suggestion": f"Avoid using unapproved AI SDKs or add '{pkg}' to allowed_sdks in ghostcheck.toml."
                        })

        # 3. Source Code Checks (JavaScript/TypeScript)
        elif any(filename.endswith(ext) for ext in ['.js', '.ts', '.jsx', '.tsx']):
            for i, line in enumerate(lines):
                # JS imports (GSA-02)
                for match in self.js_import_pattern.finditer(line):
                    pkg = match.group(1) or match.group(2)
                    if pkg and self.is_sdk_js_unauthorized(pkg):
                        findings.append({
                            "name": "unauthorized_ai_sdk_js",
                            "rule_id": "GSA-02",
                            "severity": "MEDIUM",
                            "file": filepath,
                            "line": i + 1,
                            "message": f"Unauthorized JavaScript/TypeScript AI SDK imported: '{pkg}'.",
                            "suggestion": f"Avoid using unapproved AI SDKs or add '{pkg}' to allowed_sdks in ghostcheck.toml."
                        })

        # 4. Source Code Endpoint & Env Scans (GSA-04, GSA-05) - Run on all source files
        allowed_src_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.sh', '.bat', '.env']
        if any(filename.endswith(ext) for ext in allowed_src_exts) or filename == '.env':
            for i, line in enumerate(lines):
                # GSA-04: Local LLM URL detection
                for match in self.local_url_pattern.finditer(line):
                    url = match.group(1)
                    # Check if allowed
                    if url.lower() not in self.allowed_endpoints:
                        findings.append({
                            "name": "local_llm_endpoint",
                            "rule_id": "GSA-04",
                            "severity": "HIGH",
                            "file": filepath,
                            "line": i + 1,
                            "message": f"Hardcoded local LLM endpoint detected: '{url}'.",
                            "suggestion": "Avoid hardcoding local model base URLs. Configure allowed endpoints in ghostcheck.toml."
                        })

                # GSA-05: Local LLM environment variables
                for var_name in self.local_env_vars:
                    if var_name in line:
                        # Exclude harmless matches (e.g. comments or docs)
                        if '=' in line or 'export' in line or var_name in line.split():
                            findings.append({
                                "name": "local_llm_env_var",
                                "rule_id": "GSA-05",
                                "severity": "MEDIUM",
                                "file": filepath,
                                "line": i + 1,
                                "message": f"Local LLM configuration environment variable detected: '{var_name}'.",
                                "suggestion": "Ensure the local model server deployment is authorized under company AI policies."
                            })

        return findings

    def _scan_package_json(self, filepath, content):
        findings = []
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
            for dep_name in deps:
                if self.is_sdk_js_unauthorized(dep_name):
                    findings.append({
                        "name": "unauthorized_ai_dependency",
                        "rule_id": "GSA-03",
                        "severity": "HIGH",
                        "file": filepath,
                        "line": 1,
                        "message": f"Unauthorized AI dependency found in package.json: '{dep_name}'.",
                        "suggestion": f"Remove the dependency or add '{dep_name}' to allowed_sdks in ghostcheck.toml."
                    })
        except json.JSONDecodeError:
            # Fallback to line scanning
            lines = content.split('\n')
            for i, line in enumerate(lines):
                match = re.search(r'"([^"]+)"\s*:', line)
                if match:
                    dep_name = match.group(1)
                    if self.is_sdk_js_unauthorized(dep_name):
                        findings.append({
                            "name": "unauthorized_ai_dependency",
                            "rule_id": "GSA-03",
                            "severity": "HIGH",
                            "file": filepath,
                            "line": i + 1,
                            "message": f"Unauthorized AI dependency found in package.json (fallback scan): '{dep_name}'.",
                            "suggestion": f"Remove the dependency or add '{dep_name}' to allowed_sdks in ghostcheck.toml."
                        })
        return findings

    def _scan_requirements_txt(self, filepath, content, lines):
        findings = []
        for i, line in enumerate(lines):
            cleaned = line.split('#')[0].strip()
            if not cleaned:
                continue
            parts = re.split(r'==|>=|<=|>|<|~=|===|!=', cleaned)
            pkg = parts[0].strip()
            if self.is_sdk_python_unauthorized(pkg):
                findings.append({
                    "name": "unauthorized_ai_dependency",
                    "rule_id": "GSA-03",
                    "severity": "HIGH",
                    "file": filepath,
                    "line": i + 1,
                    "message": f"Unauthorized AI dependency found in requirements.txt: '{pkg}'.",
                    "suggestion": f"Remove the dependency or add '{pkg}' to allowed_sdks in ghostcheck.toml."
                })
        return findings

    def _scan_pyproject_toml(self, filepath, content, lines):
        findings = []
        # Simple line scanning for toml dependencies
        dep_pattern = re.compile(r'^\s*([a-zA-Z0-9_-]+)\s*=\s*["\']')
        array_dep_pattern = re.compile(r'["\']([a-zA-Z0-9_-]+)(?:>=|<=|==|>|<|~=|!=|\[)')
        
        for i, line in enumerate(lines):
            # Check for direct key definition: pkg = "^1.0.0"
            match = dep_pattern.match(line)
            if match:
                pkg = match.group(1)
                if self.is_sdk_python_unauthorized(pkg):
                    findings.append({
                        "name": "unauthorized_ai_dependency",
                        "rule_id": "GSA-03",
                        "severity": "HIGH",
                        "file": filepath,
                        "line": i + 1,
                        "message": f"Unauthorized AI dependency found in pyproject.toml: '{pkg}'.",
                        "suggestion": f"Remove the dependency or add '{pkg}' to allowed_sdks in ghostcheck.toml."
                    })
            else:
                # Check for dependencies in arrays: "openai>=1.0.0"
                for match in array_dep_pattern.finditer(line):
                    pkg = match.group(1)
                    if self.is_sdk_python_unauthorized(pkg):
                        findings.append({
                            "name": "unauthorized_ai_dependency",
                            "rule_id": "GSA-03",
                            "severity": "HIGH",
                            "file": filepath,
                            "line": i + 1,
                            "message": f"Unauthorized AI dependency found in pyproject.toml: '{pkg}'.",
                            "suggestion": f"Remove the dependency or add '{pkg}' to allowed_sdks in ghostcheck.toml."
                        })
        return findings

    def _scan_extensions_json(self, filepath, content, lines):
        findings = []
        try:
            data = json.loads(content)
            recs = data.get("recommendations", [])
            for rec in recs:
                if self.is_extension_unauthorized(rec):
                    findings.append({
                        "name": "shadow_ai_ide_extension",
                        "rule_id": "GSA-06",
                        "severity": "LOW",
                        "file": filepath,
                        "line": 1,
                        "message": f"Recommendation of unauthorized AI editor assistant detected: '{rec}'.",
                        "suggestion": f"Remove the extension or add '{rec}' to allowed_extensions in ghostcheck.toml."
                    })
        except json.JSONDecodeError:
            # Fallback to line scanning
            for i, line in enumerate(lines):
                for ext in DEFAULT_IDE_EXTENSIONS:
                    if ext in line.lower():
                        findings.append({
                            "name": "shadow_ai_ide_extension",
                            "rule_id": "GSA-06",
                            "severity": "LOW",
                            "file": filepath,
                            "line": i + 1,
                            "message": f"Recommendation of unauthorized AI editor assistant detected (fallback scan): '{ext}'.",
                            "suggestion": f"Remove the extension or add '{ext}' to allowed_extensions in ghostcheck.toml."
                        })
        return findings
