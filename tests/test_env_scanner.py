from ghostcheck.checks.env_scanner import EnvScanner
import os

class MockIgnoreMatcher:
    def __init__(self, ignored_files):
        self.ignored_files = ignored_files
    def is_ignored(self, path):
        return os.path.basename(path) in self.ignored_files

def test_env_unignored():
    matcher = MockIgnoreMatcher([])
    scanner = EnvScanner("/root", matcher)
    findings = scanner.scan_file("/root/.env", "API_KEY=secret")
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "Unignored Environment File"

def test_env_debug():
    matcher = MockIgnoreMatcher([".env"])
    scanner = EnvScanner("/root", matcher)
    findings = scanner.scan_file("/root/.env", "DEBUG=true")
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "Debug Enabled"

def test_env_cors_wildcard():
    matcher = MockIgnoreMatcher([".env"])
    scanner = EnvScanner("/root", matcher)
    findings = scanner.scan_file("/root/.env", "CORS_ALLOW_ORIGIN = '*'")
    assert len(findings) == 1
    assert findings[0]["pattern_name"] == "Wildcard Origin"
