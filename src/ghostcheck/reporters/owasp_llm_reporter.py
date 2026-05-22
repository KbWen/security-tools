import shutil
from ..interfaces import BaseReporterPlugin

class OWASPLLMReporter(BaseReporterPlugin):
    @property
    def name(self) -> str:
        return "owasp-llm"

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
            "BOLD": "\033[1m",
            "RESET": "\033[0m"
        }
        self.terminal_width = min(shutil.get_terminal_size((80, 20)).columns, 80)

    def _color(self, text, severity):
        if not self.use_color or severity not in self.colors:
            return text
        return f"{self.colors[severity]}{text}{self.colors['RESET']}"

    def report(self, findings, stream=None):
        def _print(*args, **kwargs):
            if stream:
                print(*args, **kwargs, file=stream)
            else:
                print(*args, **kwargs)

        categories = {
            "LLM01: Prompt Injection": [],
            "LLM02: Sensitive Information Disclosure": [],
            "LLM03: Supply Chain Vulnerabilities": [],
            "LLM06: Excessive Agency": [],
            "LLM09: Misinformation (Hallucination)": []
        }
        
        remediations = {
            "LLM01: Prompt Injection": "Limit agent rule length and use invisible-character detectors.",
            "LLM02: Sensitive Information Disclosure": "Move secrets to .env and audit agent disk access paths.",
            "LLM03: Supply Chain Vulnerabilities": "Pin versions in mcp.json and verify model source checksums.",
            "LLM06: Excessive Agency": "Reduce Token permissions and enforce human-in-the-loop for risky commands.",
            "LLM09: Misinformation (Hallucination)": "Verify package names on official registries before deployment."
        }

        others = []
        for f in findings:
            mapping = f.get('owasp_llm', 'N/A')
            if mapping in categories:
                categories[mapping].append(f)
            else:
                others.append(f)

        _print(f"\n{self._color(' --- OWASP LLM Top 10 Compliance Report --- ', 'CRITICAL')}")
        _print(f"{self.colors['DIM']}{'='*self.terminal_width}{self.colors['RESET']}")

        passed_count = 0
        total_categories = len(categories)

        for cat, cat_findings in categories.items():
            is_passed = len(cat_findings) == 0
            if is_passed:
                passed_count += 1
            
            status_text = " PASSED " if is_passed else " FAILED "
            status_color = "INFO" if is_passed else "CRITICAL"
            
            _print(f"\n{self.colors['BOLD']}{cat}{self.colors['RESET']} [{self._color(status_text, status_color)}]")
            
            if not is_passed:
                # Group by severity
                sorted_f = sorted(cat_findings, key=lambda x: {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "INFO":4}.get(x.get('severity'), 5))
                for f in sorted_f:
                    sev = f.get('severity', 'INFO')
                    title = f.get('name') or f.get('pattern_name') or f.get('rule_name') or f.get('package') or "Issue"
                    loc = f"{f.get('file')}:{f.get('line')}" if f.get('line') else f.get('file', 'N/A')
                    _print(f"  {self._color(f' {sev:<8} ', sev)} {title} ({loc})")
                _print(f"  {self._color('Remediation:', 'INFO')} {remediations.get(cat, 'N/A')}")
            else:
                _print(f"  {self.colors['DIM']}No violations detected.{self.colors['RESET']}")

        if others:
            _print(f"\n{self.colors['BOLD']}Other Security Findings{self.colors['RESET']}")
            for f in sorted(others, key=lambda x: x.get('severity', 'INFO'))[:10]: # Limit to 10
                sev = f.get('severity', 'INFO')
                title = f.get('name') or f.get('pattern_name') or f.get('rule_name') or "Issue"
                _print(f"  {self._color(f' {sev:<8} ', sev)} {title} ({f.get('file')})")
            if len(others) > 10:
                _print(f"  {self.colors['DIM']}... and {len(others)-10} more findings.{self.colors['RESET']}")

        compliance_pct = (passed_count / total_categories) * 100
        score_color = "INFO" if compliance_pct == 100 else ("MEDIUM" if compliance_pct > 70 else "CRITICAL")
        
        _print(f"\n{self.colors['DIM']}{'-'*self.terminal_width}{self.colors['RESET']}")
        _print(f"Compliance Ratio: {self._color(f'{compliance_pct:.1f}%', score_color)} ({passed_count}/{total_categories} Categories Passed)")
        _print(f"{self.colors['DIM']}{'='*self.terminal_width}{self.colors['RESET']}\n")
