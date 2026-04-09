import json
import re

class MCPAuditor:
    def __init__(self):
        self.patterns = [
            {
                "name": "mcp_insecure_binding",
                "pattern": r'"(host|address)"\s*:\s*"0\.0\.0\.0"',
                "severity": "CRITICAL",
                "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 to prevent unauthorized local network access."
            },
            {
                "name": "mcp_hardcoded_api_key",
                "pattern": r'"(API_KEY|TOKEN|SECRET)"\s*:\s*"[^"]+"',
                "severity": "CRITICAL",
                "suggestion": "Do not hardcode API keys in MCP config. Use environment variables or a secret manager."
            },
            {
                "name": "mcp_tool_poisoning_injection",
                "pattern": r'<(IMPORTANT|SYSTEM|INSTRUCTION)>|ignore\s+previous\s+instructions',
                "severity": "HIGH",
                "suggestion": "Potential tool poisoning detected in MCP description. Review for prompt injection patterns."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        is_config = any(x in file_path.replace('\\', '/') for x in ['mcp_config.json', 'mcp.json', '.cursor/mcp.json'])
        is_server_code = file_path.endswith('.py') or file_path.endswith('.ts')
        
        for i, line in enumerate(lines):
            for p in self.patterns:
                if re.search(p['pattern'], line, re.IGNORECASE):
                    # For tool poisoning, only check if it looks like a config or server code
                    if p['name'] == "mcp_tool_poisoning_injection":
                        if not (is_config or is_server_code):
                            continue
                    
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
        return findings
