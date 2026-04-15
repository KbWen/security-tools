import pytest
import os
import json
from unittest.mock import patch, MagicMock
from ghostcheck.scanner import Scanner
from ghostcheck.config import GhostCheckConfig
from ghostcheck.checks.hallucination import HallucinationChecker
from ghostcheck.checks.vuln_scanner import VulnScanner

def test_config_robust_merge():
    """Verify that merging lists in config handles non-hashable items correctly."""
    root = "."
    config = GhostCheckConfig(root)
    
    # Simulate a config with custom_patterns as list of dicts
    project_config = {
        "custom_patterns": [{"name": "P1", "regex": "R1"}]
    }
    config._merge_config(project_config)
    
    # Add another one
    added_config = {
        "custom_patterns": [{"name": "P2", "regex": "R2"}]
    }
    config._merge_config(added_config)
    
    patterns = config.get("custom_patterns")
    assert len(patterns) == 2
    assert patterns[0]["name"] == "P1"
    assert patterns[1]["name"] == "P2"

def test_proxy_propagation():
    """Verify that proxy setting is propagated from config to checkers."""
    config_dict = {
        "proxy": "http://test-proxy:8080",
        "offline": True
    }
    
    with patch('ghostcheck.scanner.open', create=True):
        with patch('ghostcheck.scanner.json.load', return_value={}):
            scanner = Scanner(".", config=config_dict, offline=True)
            
            assert scanner.hallucination_checker.proxy == "http://test-proxy:8080"
            assert scanner.vuln_scanner.proxy == "http://test-proxy:8080"
            assert scanner.vuln_scanner.proxies["http"] == "http://test-proxy:8080"

@patch('urllib.request.install_opener')
@patch('urllib.request.build_opener')
def test_hallucination_proxy_setup(mock_build, mock_install):
    """Verify that HallucinationChecker sets up the urllib opener with proxy."""
    checker = HallucinationChecker(proxy="http://secure-proxy:3128")
    assert mock_build.called
    assert mock_install.called

def test_scanner_safe_path_windows_root(tmp_path):
    """Verify that _is_safe_path handles absolute paths correctly."""
    # Create a dummy project root
    root = str(tmp_path)
    scanner = Scanner(root)
    
    # Path inside root
    inside = os.path.join(root, "src", "file.py")
    assert scanner._is_safe_path(inside) == True
    
    # Path outside root (traversal)
    outside = os.path.abspath(os.path.join(root, "..", "evil.py"))
    assert scanner._is_safe_path(outside) == False

def test_ignore_robustness(tmp_path):
    """Verify that IgnoreMatcher correctly handles nested ignored directories."""
    from ghostcheck.ignorefile import IgnoreMatcher
    
    # Setup dummy directory structure
    root = tmp_path
    (root / "node_modules").mkdir()
    (root / "node_modules" / "some_pkg").mkdir()
    (root / "node_modules" / "some_pkg" / "index.js").write_text("console.log(1)")
    
    matcher = IgnoreMatcher(base_path=str(root), patterns=["node_modules/"])
    
    # Test nested file
    nested_file = str(root / "node_modules" / "some_pkg" / "index.js")
    assert matcher.is_ignored(nested_file) == True
    
    # Test sibling file
    sibling = str(root / "src" / "index.js")
    assert matcher.is_ignored(sibling) == False
