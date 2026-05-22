import json
import shutil
import sys
from ..interfaces import BaseReporterPlugin

class ConsoleReporter(BaseReporterPlugin):
    @property
    def name(self) -> str:
        return "console"

    def __init__(self, use_color=True, use_unicode=True):
        self.use_color = use_color
        self.use_unicode = use_unicode
        self.terminal_width = min(shutil.get_terminal_size((80, 20)).columns, 80)
        self._colors = {
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
        return f"{self._colors.get(severity, '')}{text}{self._colors['RESET']}"

    def _dim(self, text):
        """Helper to apply DIM color safely, respecting use_color flag."""
        if not self.use_color:
            return text
        return f"{self._colors['DIM']}{text}{self._colors['RESET']}"

    def report(self, findings, stream=None, **kwargs):
        def _print(*args, **kwargs_print):
            if stream:
                print(*args, **kwargs_print, file=stream)
            else:
                print(*args, **kwargs_print)

        if not findings:
            _print(f"\n{self._color(' [OK] ', 'INFO')} {self._color('No security issues found. Project is clean.', 'INFO')}\n")
            return

        _print(f"\n{self._color(' --- GhostCheck Scan Results --- ', 'CRITICAL')}")
        _print(self._dim('='*self.terminal_width))
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))

        for f in sorted_findings:
            sev = f.get('severity', 'INFO')
            title = f.get('name') or f.get('pattern_name') or f.get('rule_name') or f.get('package') or "Issue"
            loc = f"{f.get('file')}:{f.get('line')}" if f.get('line') else f.get('file', 'N/A')
            owasp = f.get('owasp_llm', 'N/A')
            
            # Header line
            _print(f"{self._color(f' {sev:<10} ', sev)} {title}")
            _print(self._dim(f"Loc: {loc}"))
            if owasp != "N/A":
                _print(f"{self._dim('OWASP AI:')} {self._color(owasp, 'INFO')}")
            
            if 'message' in f:
                _print(f"   {f['message']}")
            if 'context' in f:
                _print(f"   {self._dim('Context: ' + str(f.get('context', '')))}")
            elif 'value_preview' in f:
                _print(f"   {self._dim('Value: ' + str(f.get('value_preview', '')))}")
            
            if 'remediation' in f:
                _print(f"   {self._color('Fix:', 'INFO')} {f['remediation']}")
            elif 'suggestion' in f:
                _print(f"   {self._color('Suggestion:', 'INFO')} {f['suggestion']}")
            _print(self._dim('-'*self.terminal_width))

        summary = {}
        for f in findings:
            sev = f.get('severity', 'INFO')
            summary[sev] = summary.get(sev, 0) + 1
        
        _print(f"\nSummary")
        summary_line = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in summary:
                summary_line.append(f"{self._color(sev, sev)}: {summary[sev]}")
        _print("   " + " | ".join(summary_line))
        _print(self._dim('='*self.terminal_width) + "\n")
