import re

class LogicAuditor:
    """
    Scans for potential business logic vulnerabilities, specifically 
    around subscription-bypass, inadequate authorization checks, and 
    hardcoded admin defaults.
    """
    def __init__(self):
        self.logic_patterns = [
            {
                "name": "potential_logic_bypass",
                "pattern": r'if\s*\(.*(is_?premium|is_?pro|is_?subscribed|has_?subscription|vip_?level|is_?admin|debug|is_?dev|is_?test).*(==?|===|!=|!==)',
                "severity": "MEDIUM",
                "suggestion": "Detected sensitive logic check (subscription, admin, or debug mode). Ensure this is reinforced by server-side authorization and NOT easily bypassable via client-side state manipulation."
            },
            {
                "name": "hardcoded_identity_bypass",
                "pattern": r'if\s*\(.*(user_?id|email|username|\bid\b).*(==?|===|!=|!==)\s*["\'][^"\']+["\']',
                "severity": "HIGH",
                "suggestion": "Detected hardcoded identity comparison. This is a common pattern for 'backdoor' admin access. Use role-based access control (RBAC) instead."
            },
            {
                "name": "client_side_only_entitlement",
                "pattern": r'(localStorage|sessionStorage|cookie|document\.cookie).*(plan|tier|sub|license|premium|pro)',
                "severity": "HIGH",
                "suggestion": "Storing or reading entitlement/subscription data directly from client-side storage is high-risk. Users can manipulate these values to bypass paywalls. Use signed JWTs or server-side session checks."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        lines = content.splitlines()
        
        # Determine if file is likely client-side (frontend) or server-side (backend)
        path_lower = file_path.lower()
        is_client_side = any(path_lower.endswith(ext) for ext in ['.jsx', '.tsx', '.vue', '.svelte']) or \
                         any(folder in path_lower for folder in ['/components/', '/views/', '/pages/', '/frontend/'])
                         
        relevant_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.dart', '.java', '.kt', '.php']
        if not any(path_lower.endswith(ext) for ext in relevant_exts):
            return []

        for i, line in enumerate(lines):
            if line.strip().startswith(('#', '//', '/*', '*')):
                continue
                
            for p in self.logic_patterns:
                # If it's a generic logic check, only flag it if we suspect it's client-side, 
                # because `if user.is_premium:` is actually correct behavior on the server!
                if p['name'] == 'potential_logic_bypass' and not is_client_side:
                    continue
                    
                if re.search(p['pattern'], line, re.IGNORECASE):
                    findings.append({
                        "file": file_path,
                        "line": i + 1,
                        "name": p['name'],
                        "severity": p['severity'],
                        "suggestion": p['suggestion'],
                        "context": line.strip()
                    })
        return findings
