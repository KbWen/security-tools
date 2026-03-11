import json

class ConsoleReporter:
    def __init__(self, use_color=True):
        self.use_color = use_color
        self.colors = {
            "CRITICAL": "\033[91;1m",  # Bold Red
            "HIGH": "\033[91m",        # Red
            "MEDIUM": "\033[93m",      # Yellow
            "LOW": "\033[94m",         # Blue
            "INFO": "\033[92m",        # Green
            "RESET": "\033[0m"
        }

    def _color(self, text, severity):
        if not self.use_color:
            return text
        return f"{self.colors.get(severity, '')}{text}{self.colors['RESET']}"

    def report(self, findings):
        if not findings:
            print("\n✅ No security issues found.\n")
            return

        print(f"\n🔍 GhostCheck found {len(findings)} issues:\n")
        
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))

        for f in sorted_findings:
            sev = f.get('severity', 'INFO')
            title = f.get('pattern_name') or f.get('rule_name') or f.get('package') or "Issue"
            loc = f"{f.get('file')}:{f.get('line')}" if f.get('line') else f.get('file', 'N/A')
            
            print(f"[{self._color(sev, sev)}] {title}")
            print(f"  Location: {loc}")
            if 'message' in f:
                print(f"  Message: {f['message']}")
            if 'remediation' in f:
                print(f"  Fix: {f['remediation']}")
            if 'value_preview' in f:
                print(f"  Value: {f['value_preview']}")
            print("")

        summary = {}
        for f in findings:
            sev = f.get('severity', 'INFO')
            summary[sev] = summary.get(sev, 0) + 1
        
        print("Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in summary:
                print(f"  {self._color(sev, sev)}: {summary[sev]}")
        print("")
