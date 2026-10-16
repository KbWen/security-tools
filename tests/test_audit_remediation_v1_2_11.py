import io
import json
import os
import pytest
from unittest.mock import patch, MagicMock
from ghostcheck.scanner import Scanner
from ghostcheck.reporters.owasp_llm_reporter import OWASPLLMReporter
from ghostcheck.presets.manager import PresetManager
from ghostcheck.checks.hallucination import HallucinationChecker
from ghostcheck.checks.vuln_scanner import VulnScanner
from ghostcheck.checks.ci_auditor import CIAuditor
from ghostcheck.init import GhostCheckInitializer
from ghostcheck.plugins.base import BasePlugin
from ghostcheck.cli import main


def test_f01_owasp_llm_demo_fixtures_mapping():
    """F-01: Demo fixtures scan with OWASPLLMReporter must NOT report 100% compliance when CRITICAL/HIGH issues exist."""
    demo_dir = os.path.join("src", "ghostcheck", "data", "demo_fixtures")
    scanner = Scanner(demo_dir, ignore_enabled=False, offline=True)
    findings = scanner.scan()
    assert len(findings) > 0

    # Verify OWASP LLM mapping populated on findings
    mapped = [f for f in findings if f.get("owasp_llm") and f.get("owasp_llm") != "N/A"]
    assert len(mapped) >= 5, f"Expected most demo findings to map to OWASP LLM categories, got: {findings}"

    reporter = OWASPLLMReporter(use_color=False)
    stream = io.StringIO()
    reporter.report(findings, stream=stream)
    output = stream.getvalue()

    assert "100.0%" not in output
    assert "FAILED" in output


def test_f02_presets_and_list_checks_completeness(capsys):
    """F-02: Framework presets must include rules, mcp, and privilege; list-checks must list modern check categories."""
    pm = PresetManager()
    for preset_key in ["next.js", "flutter", "django", "fastapi", "terraform"]:
        preset = pm.get_preset(preset_key)
        modules = preset.get("scan_modules", [])
        assert "rules" in modules, f"Preset {preset_key} missing 'rules'"
        assert "mcp" in modules, f"Preset {preset_key} missing 'mcp'"
        assert "privilege" in modules, f"Preset {preset_key} missing 'privilege'"

    with patch("sys.argv", ["ghostcheck", "list-checks"]):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
    out, _ = capsys.readouterr()
    for expected in ["privilege", "shadow_ai", "tamper", "context_inflation", "data_exfiltration", "killswitch", "lethal_trifecta"]:
        assert expected in out


def test_f03_hallucination_file_line_and_vuln_workspace_filter(tmp_path):
    """F-03: HallucinationChecker.scan populates file & line; VulnScanner skips workspace:* and local specs."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("# comment\nrequests==2.25.1\nnon-existent-ghost-pkg-999==1.0.0\n", encoding="utf-8")

    checker = HallucinationChecker(offline=False)
    with patch.object(checker, "_check_package") as mock_check:
        def side_effect(registry, pkg):
            if "ghost-pkg" in pkg:
                return {
                    "package": pkg,
                    "registry": registry,
                    "severity": "CRITICAL",
                    "message": "Package does not exist on PyPI."
                }, False
            return None, False

        mock_check.side_effect = side_effect
        findings = checker.scan([str(req_file)], {})
        assert len(findings) == 1
        assert findings[0].get("file") == str(req_file)
        assert findings[0].get("line") == 3
        assert findings[0].get("name") == "hallucinated_package"

    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "dependencies": {
            "my-local-pkg": "workspace:*",
            "my-file-pkg": "file:../local",
            "my-git-pkg": "git+https://github.com/example/repo.git",
            "lodash": "^4.17.21"
        }
    }), encoding="utf-8")

    vscanner = VulnScanner(offline=False)
    with patch.object(vscanner, "_query_osv", return_value=None) as mock_osv:
        vscanner.scan([str(pkg_json)], {})
        called_pkgs = [call.args[0] for call in mock_osv.call_args_list]
        assert called_pkgs == ["lodash"]


def test_f04_plugin_loader_wired_in_scanner(tmp_path):
    """F-04: Custom plugins in scanner.plugin_loader must be executed during Scanner.scan()."""
    target = tmp_path / "app.py"
    target.write_text("x = 42\n", encoding="utf-8")

    class CustomAuditPlugin(BasePlugin):
        @property
        def name(self) -> str:
            return "custom_test_plugin"

        @property
        def description(self) -> str:
            return "Test plugin"

        def scan(self, file_path, content):
            if "42" in content:
                return [{"file": file_path, "line": 1, "severity": "MEDIUM", "message": "Found magic number 42"}]
            return []

    scanner = Scanner(str(tmp_path), offline=True)
    scanner.plugin_loader.plugins = [CustomAuditPlugin()]
    findings = scanner.scan()
    assert any(f.get("name") == "custom_test_plugin" for f in findings)
    assert not hasattr(scanner, "env_scanner")


def test_f05_init_ci_template_passes_ci_auditor(tmp_path):
    """F-05: Generated GitHub Action workflow from ghostcheck init --ci github must have 0 CIAuditor findings and pin version."""
    initializer = GhostCheckInitializer(str(tmp_path))
    ok, _ = initializer.generate_ci_pipeline("github")
    assert ok

    gh_yml = tmp_path / ".github" / "workflows" / "ghostcheck.yml"
    assert gh_yml.exists()
    content = gh_yml.read_text(encoding="utf-8")
    assert "@v" in content

    auditor = CIAuditor()
    ci_findings = auditor.scan([str(gh_yml)], {})
    assert ci_findings == [], f"Generated CI workflow triggered CIAuditor findings: {ci_findings}"


def test_f07_ghostcheck_toml_cyrillic_intact():
    """F-07: ghostcheck.toml must not contain corrupted '?' placeholders in Cyrillic safe keywords."""
    with open("ghostcheck.toml", "r", encoding="utf-8") as f:
        content = f.read()
    assert "нельзя" in content
    assert "запрещено" in content
    assert "нел?з?" not in content
