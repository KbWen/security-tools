import pytest
import os
from ghostcheck.checks.logic_auditor import LogicAuditor

def test_logic_bypass_detection():
    auditor = LogicAuditor()
    content = """
    if (user.is_premium == true) { // Should match
        do_pro_stuff();
    }
    
    // Some comment
    if (user.id == "ADMIN_123") { // Should match
        grant_full_access();
    }
    
    localStorage.setItem("user_tier", "pro"); // Should match
    """
    findings = auditor.scan_file("frontend/pages/test.js", content)
    
    finding_names = [f['name'] for f in findings]
    assert "potential_logic_bypass" in finding_names
    assert "hardcoded_identity_bypass" in finding_names
    assert "client_side_only_entitlement" in finding_names

def test_debug_mode_bypass():
    auditor = LogicAuditor()
    content = """
    function checkAccess() {
        if (config.isDebug == true) return true; // Danger
        return false;
    }
    """
    findings = auditor.scan_file("components/app.jsx", content)
    assert any(f['name'] == "potential_logic_bypass" for f in findings)
