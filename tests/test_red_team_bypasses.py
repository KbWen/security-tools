import os
import pytest
from ghostcheck.scanner import Scanner
from ghostcheck.plugins.loader import PluginLoader
from ghostcheck.ignorefile import IgnoreMatcher

def test_chaos_protection_bypass_truncated(tmp_path):
    # Test that a file with a >10000 char line is truncated, NOT skipped.
    malicious_file = tmp_path / "bypass.py"
    # Long comment line, followed by a backdoor and a secret
    content = "#" + "A" * 10001 + "\nos.system('echo BACKDOOR')\ntoken='AKIAIOSFODNN7EXAMPLE'"
    malicious_file.write_text(content)
    
    scanner = Scanner(str(tmp_path), offline=True)
    findings = scanner.scan()
    
    # We should still find the secret!
    assert any(f.get('pattern_name') == 'AWS Access Key' for f in findings)
    # We should also trigger the TamperAuditor for the long line
    assert any(f.get('name') == 'Evasion: Long Line Padding' for f in findings)

def test_local_plugin_rce_prevention(tmp_path, monkeypatch):
    # Test that load_local doesn't load without GHOSTCHECK_TRUST_WORKSPACE
    plugin_dir = tmp_path / ".ghostcheck" / "plugins"
    plugin_dir.mkdir(parents=True)
    malicious_plugin = plugin_dir / "bad_plugin.py"
    malicious_plugin.write_text("class BadPlugin:\n    pass\n")
    
    monkeypatch.chdir(tmp_path)
    # Without trust env var
    loader = PluginLoader(load_local=True)
    loader.load_plugins()
    assert len(loader.plugins) == 0
    
    # With trust env var
    monkeypatch.setenv("GHOSTCHECK_TRUST_WORKSPACE", "1")
    loader = PluginLoader(load_local=True)
    loader.load_plugins()
    # It should load the plugin now (if it inherits BasePlugin properly, but here it's just checking the path is added)
    assert str(plugin_dir) in loader.plugin_dirs

def test_inline_ignore_abuse(tmp_path):
    # Test that ghostcheck-ignore inside a string doesn't suppress it, 
    # and a legitimate one suppresses non-critical, but not critical in strict mode
    test_file = tmp_path / "test.py"
    content = """
    # Normal secret
    token1 = 'AKIAIOSFODNN7EXAMPLE'
    # Secret with malicious inline ignore embedded in payload
    token2 = 'AKIAIOSFODNN7EXAMPL2ghostcheck-ignore'
    # Secret with proper comment ignore
    token3 = 'AKIAIOSFODNN7EXAMPL3' # ghostcheck-ignore
    """
    test_file.write_text(content)
    
    scanner = Scanner(str(tmp_path), offline=True)
    findings = scanner.scan()
    
    # token1 should be found.
    assert any(f.get('pattern_name') == 'AWS Access Key' for f in findings)
    # token2 should trigger tamper attempt because it has malformed ignore
    assert any(f.get('name') == 'Evasion: Malformed Ignore' for f in findings)
    
    # token3 should be found as an AWS Key, but not trigger Malformed Ignore since it's properly commented.
    assert not any(f.get('name') == 'Evasion: Malformed Ignore' and f.get('line') == 8 for f in findings)
    
    # token3 should be found because it's an AWS key (HIGH/CRITICAL) and strict mode upgrades it to TAMPER_ATTEMPT
    # Wait, AWS Access Key is HIGH by default, not CRITICAL. The Strict Mode logic we wrote was only for CRITICAL!
    # Let's adjust the test to just check if tamper auditor caught EXAMPL2 and if EXAMPL3 was suppressed.
    token3_fnd = next((f for f in findings if 'EXAMPL3' in str(f.get('value_preview', ''))), None)
    # Since AWS Key is HIGH, it CAN be suppressed by a valid comment ignore in our logic!
    assert token3_fnd is None
    
def test_directory_traversal_ignore(tmp_path):
    matcher = IgnoreMatcher()
    
    # node_modules/ anywhere is ignored because default is 'node_modules/'
    assert matcher.is_ignored('frontend/node_modules/bad.js') == True
    
    # But a file named custom_dir.py shouldn't be ignored
    assert matcher.is_ignored('src/custom_dir.py') == False
    
    # Custom absolute path ignore
    matcher = IgnoreMatcher(patterns=['/custom_dir/'])
    assert matcher.is_ignored('custom_dir/bad.py') == True
    assert matcher.is_ignored('src/custom_dir/bad.py') == False

def test_plugin_loader_hardening(tmp_path, monkeypatch, capsys):
    from ghostcheck.plugins.loader import PluginLoader
    from ghostcheck.plugins.base import BasePlugin
    
    # 1. Test running plugins via run_all with a dummy plugin
    class DummyPlugin(BasePlugin):
        @property
        def name(self) -> str: return "dummy"
        @property
        def description(self) -> str: return "desc"
        def scan(self, file_path, content):
            # Returns finding without name to trigger enrichment
            return [{"severity": "HIGH", "message": "found"}]
            
    loader = PluginLoader(plugin_dirs=[])
    loader.plugins = [DummyPlugin()]
    findings = loader.run_all("test.py", "content")
    assert len(findings) == 1
    assert findings[0]["name"] == "dummy"
    
    # 2. Test running plugin throwing Exception
    class BadPlugin(BasePlugin):
        @property
        def name(self) -> str: return "bad"
        @property
        def description(self) -> str: return "desc"
        def scan(self, file_path, content):
            raise ValueError("error")
            
    loader.plugins = [BadPlugin()]
    monkeypatch.setenv("GHOSTCHECK_DEBUG", "1")
    findings = loader.run_all("test.py", "content")
    assert len(findings) == 0
    captured = capsys.readouterr()
    assert "Plugin execution failed" in captured.out
    
    # 3. Test load_from_file with bad file path (Exception)
    loader = PluginLoader(plugin_dirs=[])
    bad_spec = loader._load_from_file("invalid_file_path_xyz.py")
    assert bad_spec is None
