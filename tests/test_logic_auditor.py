import pytest
from ghostcheck.checks.logic_auditor import LogicAuditor

def test_frontend_logic_bypass_detection():
    """Frontend file: should flag subscription, identity, and localStorage patterns."""
    auditor = LogicAuditor()
    content = """
    if (user.is_premium == true) {
        do_pro_stuff();
    }
    
    // Some comment (should be skipped)
    if (user.id == "ADMIN_123") {
        grant_full_access();
    }
    
    localStorage.setItem("user_tier", "pro");
    """
    findings = auditor.scan_file("frontend/pages/test.js", content)
    finding_names = [f['name'] for f in findings]
    assert "potential_logic_bypass" in finding_names
    assert "hardcoded_identity_bypass" in finding_names
    assert "client_side_only_entitlement" in finding_names

def test_frontend_debug_mode_bypass():
    """Frontend file: should flag debug mode checks."""
    auditor = LogicAuditor()
    content = """
    function checkAccess() {
        if (config.isDebug == true) return true;
        return false;
    }
    """
    findings = auditor.scan_file("components/app.jsx", content)
    assert any(f['name'] == "potential_logic_bypass" for f in findings)

def test_backend_does_not_flag_subscription_check():
    """Backend file: should NOT flag normal is_premium/is_admin checks (they're correct on server)."""
    auditor = LogicAuditor()
    content = """
    if (user.is_premium == True):
        return premium_content()
    """
    findings = auditor.scan_file("api/views.py", content)
    assert not any(f['name'] == "potential_logic_bypass" for f in findings)

def test_backend_still_flags_hardcoded_identity():
    """Backend file: should STILL flag hardcoded identity comparisons (backdoor risk everywhere)."""
    auditor = LogicAuditor()
    content = """
    if (request.email == "boss@company.com"):
        return admin_dashboard()
    """
    findings = auditor.scan_file("api/views.py", content)
    assert any(f['name'] == "hardcoded_identity_bypass" for f in findings)

def test_backend_still_flags_localstorage():
    """Backend file (Node.js SSR): should still flag localStorage patterns."""
    auditor = LogicAuditor()
    content = """
    const plan = localStorage.getItem("subscription_tier");
    """
    findings = auditor.scan_file("server/auth.js", content)
    assert any(f['name'] == "client_side_only_entitlement" for f in findings)

def test_skips_comments():
    """Comments should not trigger findings."""
    auditor = LogicAuditor()
    content = """
    // if (user.is_premium == true) { ... }
    # if (user.is_admin == false) { ... }
    /* localStorage.setItem("plan", "pro"); */
    """
    findings = auditor.scan_file("frontend/pages/test.js", content)
    assert len(findings) == 0

def test_skips_non_code_files():
    """Should return empty for non-code files like .md or .css."""
    auditor = LogicAuditor()
    content = "if (user.is_premium == true) { }"
    findings = auditor.scan_file("README.md", content)
    assert len(findings) == 0
    findings = auditor.scan_file("styles.css", content)
    assert len(findings) == 0

def test_triple_equals_and_not_equals():
    """Should catch strict equality and inequality operators."""
    auditor = LogicAuditor()
    content = """
    if (user.isPro !== "free") { show_pro(); }
    if (req.username === "root") { allow(); }
    """
    findings = auditor.scan_file("frontend/pages/dash.tsx", content)
    assert any(f['name'] == "potential_logic_bypass" for f in findings)
    assert any(f['name'] == "hardcoded_identity_bypass" for f in findings)
