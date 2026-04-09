import re

class AISupplyChainScanner:
    def __init__(self):
        self.patterns = [
            {
                "name": "mcp_npm_package_unfixed",
                "pattern": r'"command"\s*:\s*"npx\s+[^@"]+(?!"|@)', # npx without @version, simplified
                "severity": "HIGH",
                "suggestion": "Pin MCP server versions using @version (e.g., npx @modelcontextprotocol/server-everything@0.1.0) to prevent rug pull attacks."
            },
            {
                "name": "ai_dependency_untrusted_source",
                "pattern": r'https?://(?!github\.com|npmjs\.com|pypi\.org|huggingface\.co)[^"\'\s]+\.(zip|tar\.gz|whl)',
                "severity": "MEDIUM",
                "suggestion": "AI dependencies should be loaded from trusted sources. Verify the integrity of this external resource."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        is_ai_manifest = any(x in file_path for x in ['mcp.json', 'requirements.txt', 'package.json'])
        
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
