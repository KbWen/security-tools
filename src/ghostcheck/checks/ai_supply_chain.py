import re

class AISupplyChainScanner:
    def __init__(self):
        self.patterns = [
            {
                "name": "mcp_npm_package_unfixed",
                "pattern": r'("command"|"args")\s*:\s*\[??"(npx|-y|@[a-z0-9-]+/[a-z0-9-]+)(?!"|@)',
                "severity": "HIGH",
                "suggestion": "Pin MCP server versions using @version (e.g., npx @modelcontextprotocol/server-everything@0.1.0) to prevent rug pull attacks."
            },
            {
                "name": "ai_dependency_untrusted_source",
                "pattern": r'https?://(?!github\.com|npmjs\.com|pypi\.org|huggingface\.co|openai\.com|anthropic\.com)[^"\'\s]+\.(zip|tar\.gz|whl|bin|gguf|pt)',
                "severity": "MEDIUM",
                "suggestion": "AI dependencies should be loaded from trusted sources. Verify the integrity of this external resource."
            },
            {
                "name": "model_provenance_unverified",
                "pattern": r'FROM\s+(?!(gpt-|claude-|gemini-|llama|mistral|cli|library/))([a-z0-9_-]+/[a-z0-9_-]+)',
                "severity": "MEDIUM",
                "suggestion": "Using a third-party model from a personal namespace. Ensure the model creator is verified and the weights haven't been tampered with."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        is_ai_manifest = any(x in file_path.lower() for x in ['mcp.json', 'requirements.txt', 'package.json', 'modelfile', 'dockerfile'])
        
        if not is_ai_manifest:
            return []

        for i, line in enumerate(lines):
            for p in self.patterns:
                if re.search(p['pattern'], line):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
        return findings
