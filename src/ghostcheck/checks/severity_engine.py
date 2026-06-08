import math
import os

class SeverityEngine:
    """
    Intelligent engine that adjusts finding severity based on context:
    - Git status (.gitignore)
    - Directory patterns (test, vendor, ai-output)
    - String entropy
    """
    
    def __init__(self, root_path):
        self.root_path = root_path

    def adjust_findings(self, findings):
        for finding in findings:
            self.adjust_finding(finding)
        return findings

    def adjust_finding(self, finding):
        # 1. Entropy-based adjustment (High entropy -> High severity/priority)
        if "value_preview" in finding:
            entropy = self._calculate_entropy(finding["value_preview"])
            if entropy < 3.0:
                # Likely false positive or very common string
                self._downgrade(finding, "low entropy")

        # 2. Path-based adjustment
        file_path = finding.get("file", "")
        if self._is_test_or_fixture(file_path):
            self._downgrade(finding, "test/fixture directory")
        elif self._is_ai_output(file_path):
            self._upgrade(finding, "AI generated output")

    def _calculate_entropy(self, s):
        if not s:
            return 0
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0
        for count in counts.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy

    def _is_test_or_fixture(self, path):
        if not path or not isinstance(path, str):
            return False
        normalized = os.path.normpath(path).lower()
        parts = normalized.split(os.sep)
        test_patterns = {'test', 'tests', 'fixture', 'fixtures', 'example', 'examples'}
        return any(p in test_patterns for p in parts)

    def _is_ai_output(self, path):
        if not path or not isinstance(path, str):
            return False
        normalized = os.path.normpath(path).lower()
        parts = normalized.split(os.sep)
        ai_patterns = {'.gemini', '.antigravity', '.cursor', 'chat_logs', 'agent_logs'}
        return any(p in ai_patterns for p in parts)

    def _downgrade(self, finding, reason):
        mapping = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO"}
        current = (finding.get("severity") or "MEDIUM").upper()
        finding["severity"] = mapping.get(current, current)
        finding["adjustment_reason"] = reason

    def _upgrade(self, finding, reason):
        mapping = {"INFO": "LOW", "LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}
        current = (finding.get("severity") or "MEDIUM").upper()
        finding["severity"] = mapping.get(current, current)
        finding["adjustment_reason"] = reason
