import json

class ConsoleReporter:
    def __init__(self, use_color=True, use_unicode=True):
        self.use_color = use_color
        self.use_unicode = use_unicode
        self.colors = {
            "CRITICAL": "\033[97;41;1m", # White on Red
            "HIGH": "\033[91;1m",        # Bold Red
            "MEDIUM": "\033[93;1m",      # Bold Yellow
            "LOW": "\033[94m",           # Blue
            "INFO": "\033[92m",          # Green
            "DIM": "\033[90m",           # Gray
            "RESET": "\033[0m"
        }

    def _color(self, text, severity):
        if not self.use_color:
            return text
        return f"{self.colors.get(severity, '')}{text}{self.colors['RESET']}"

    def report(self, findings):
        if not findings:
            icon = " [OK] " if self.use_unicode else " [OK] " # OK is already ASCII-ish, but let's keep it consistent
            # Actually line 23 used emoji before? No, it used ' [OK] '.
            # Wait, let me check line 23 again.
            print(f"\n{self._color(' [OK] ', 'INFO')} {self._color('No security issues found. Project is clean.', 'INFO')}\n")
            return

        print(f"\n{self._color(' --- GhostCheck Scan Results --- ', 'CRITICAL')}")
        print(f"{self.colors['DIM']}{'='*60}{self.colors['RESET']}")
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))

        for f in sorted_findings:
            sev = f.get('severity', 'INFO')
            title = f.get('name') or f.get('pattern_name') or f.get('rule_name') or f.get('package') or "Issue"
            loc = f"{f.get('file')}:{f.get('line')}" if f.get('line') else f.get('file', 'N/A')
            owasp = f.get('owasp_llm', 'N/A')
            
            # Header line
            print(f"{self._color(f' {sev:<10} ', sev)} {self.colors['RESET']}{title}")
            print(f"{self.colors['DIM']}Loc: {loc}{self.colors['RESET']}")
            if owasp != "N/A":
                print(f"{self.colors['DIM']}OWASP AI: {self.colors['RESET']}{self._color(owasp, 'INFO')}")
            
            if 'message' in f:
                print(f"   {f['message']}")
            if 'context' in f:
                print(f"   {self.colors['DIM']}Context: {f['context']}{self.colors['RESET']}")
            elif 'value_preview' in f:
                print(f"   {self.colors['DIM']}Context: {f['value_preview']}{self.colors['RESET']}")
            
            if 'remediation' in f:
                print(f"   {self._color('Fix:', 'INFO')} {f['remediation']}")
            elif 'suggestion' in f:
                print(f"   {self._color('Suggestion:', 'INFO')} {f['suggestion']}")
            print(f"{self.colors['DIM']}{'-'*60}{self.colors['RESET']}")

        summary = {}
        for f in findings:
            sev = f.get('severity', 'INFO')
            summary[sev] = summary.get(sev, 0) + 1
        
        print(f"\nSummary")
        summary_line = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in summary:
                summary_line.append(f"{self._color(sev, sev)}: {summary[sev]}")
        print("   " + " | ".join(summary_line))
        print(f"{self.colors['DIM']}{'='*60}{self.colors['RESET']}\n")
