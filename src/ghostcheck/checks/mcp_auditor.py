import json
import re
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class MCPAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "mcpauditor"

    @property
    def description(self) -> str:
        return "Scanner plugin for MCPAuditor"

    def scan(self, files: List[str], config: Any) -> List[Dict]:
        findings = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                findings.extend(self.scan_file(file_path, content))

            except Exception:
                pass
        return findings

    def __init__(self):
        self.patterns = [
            {
                "name": "mcp_insecure_binding",
                "pattern": r'"(host|address|bind|listen)"\s*:\s*"\s*(0\.0\.0\.0|::|\[::\]|0:0:0:0:0:0:0:0|\[0:0:0:0:0:0:0:0\]|::ffff:0\.0\.0\.0|\[::ffff:0\.0\.0\.0\])(:\d+)?\s*"',
                "severity": "CRITICAL",
                "suggestion": "Bind MCP server to 127.0.0.1 instead of 0.0.0.0 or wildcard IPv6 addresses (::) to prevent unauthorized local network access."
            },
            {
                "name": "mcp_hardcoded_api_key",
                "pattern": r'"[^"]*(API_KEY|TOKEN|SECRET)[^"]*"\s*:\s*"[^"]+"',
                "severity": "CRITICAL",
                "suggestion": "Do not hardcode API keys in MCP config. Use environment variables or a secret manager."
            },
            {
                "name": "mcp_untrusted_endpoint",
                "pattern": r'https?://(?!openai\.com|anthropic\.com|google\.com|localhost|127\.0\.0\.1|azure\.com|github\.com|schema\.org|w3\.org|json-schema\.org|schemastore\.azurewebsites\.net)[^"\'\s]+',
                "severity": "MEDIUM",
                "suggestion": "Detected non-standard AI model endpoint. Verify the trustworthiness of this service provider."
            },
            {
                "name": "mcp_tool_poisoning_injection",
                "pattern": r'<(IMPORTANT|SYSTEM|INSTRUCTION)>|ignore\s+previous\s+instructions',
                "severity": "HIGH",
                "suggestion": "Potential tool poisoning detected in MCP description. Review for prompt injection patterns."
            },
            {
                "name": "mcp_suspicious_description_length",
                "pattern": r'"description"\s*:\s*"[^"]{500,}"',
                "severity": "MEDIUM",
                "suggestion": "Abnormally long MCP tool/server description. Attackers use large descriptions to hide prompt injection payloads or bypass context windows."
            },
            {
                "name": "mcp_custom_registry",
                "pattern": r'--(registry|index-url|extra-index-url)["\']?\s*[=,:]?\s*["\']?https?://(?!npmjs\.org|pypi\.org|python\.org)[^"\'\s]+',
                "severity": "HIGH",
                "suggestion": "MCP server uses a custom package registry. This is a common vector for dependency confusion and rug pull attacks."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        
        # Only check MCP config files or MCP server code files
        is_config = any(x in file_path.replace('\\', '/') for x in ['mcp_config.json', 'mcp.json', '.cursor/mcp.json'])
        is_server_code = False
        if file_path.endswith('.py') or file_path.endswith('.ts'):
            filename = os.path.basename(file_path).lower()
            if 'mcp' in filename or 'mcp' in content:
                is_server_code = True
                
        if not (is_config or is_server_code):
            return findings

        lines = content.splitlines()
        for i, line in enumerate(lines):
            for p in self.patterns:
                match = re.search(p['pattern'], line, re.IGNORECASE)
                if match:
                    # Config-only patterns
                    if p['name'] in ["mcp_insecure_binding", "mcp_hardcoded_api_key"]:
                        if not is_config:
                            continue
                            
                    context_str = line.strip()
                    if p['name'] == "mcp_hardcoded_api_key":
                        # Redact the value part in JSON-like configuration lines
                        context_str = re.sub(r'(":\s*")[^"]+(")', r'\1********\2', context_str)
                        
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": context_str
                    })
        return findings
