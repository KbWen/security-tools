import os
import json
import threading
import pytest
from unittest.mock import patch, MagicMock

from ghostcheck import __version__
from ghostcheck.scanner import Scanner
from ghostcheck.config import GhostCheckConfig
from ghostcheck.init import GhostCheckInitializer
from ghostcheck.honeypot import GhostCheckHoneypotGenerator
from ghostcheck.ignorefile import IgnoreMatcher
from ghostcheck.presets.manager import PresetManager
from ghostcheck.checks.hallucination import HallucinationChecker
from ghostcheck.checks.vuln_scanner import VulnScanner
from ghostcheck.checks.secret_validator import SecretValidator
from ghostcheck.cli import main


def test_ac1_results_cache_metadata_isolation(tmp_path):
    """AC-1: Scanner cache metadata includes offline, version, disabled_rules, and exclude_patterns."""
    cfg = GhostCheckConfig(str(tmp_path))
    cfg.config["preset"] = "generic"
    cfg.config["enabled_checks"] = ["hallucination"]
    cfg.config["disabled_rules"] = ["RULE_B", "rule_a"]
    cfg.config["exclude_patterns"] = ["node_modules", "dist"]

    scanner = Scanner(str(tmp_path), config=cfg, offline=False, version="1.2.15")
    meta = scanner._get_cache_meta()

    assert meta["version"] == "1.2.15"
    assert meta["offline"] is False
    assert meta["preset"] == "generic"
    assert meta["checks"] == ["hallucination"]
    assert meta["disabled_rules"] == ["rule_a", "rule_b"]
    assert meta["exclude_patterns"] == ["dist", "node_modules"]

    # Verify switching offline=True changes the cache metadata
    scanner_offline = Scanner(str(tmp_path), config=cfg, offline=True, version="1.2.15")
    meta_offline = scanner_offline._get_cache_meta()
    assert meta_offline["offline"] is True
    assert meta != meta_offline

    # Verify results cache validation invalidates stale cache when offline or version differs
    scanner.results_cache = {"file.py|100|200": [{"name": "fake"}]}
    scanner._save_results_cache()

    # Read with same config -> valid
    fresh_scanner = Scanner(str(tmp_path), config=cfg, offline=False, version="1.2.15")
    assert "file.py|100|200" in fresh_scanner.results_cache

    # Read with offline=True -> invalidated due to integrity mismatch
    offline_load_scanner = Scanner(str(tmp_path), config=cfg, offline=True, version="1.2.15")
    assert offline_load_scanner.results_cache == {}


def test_ac2_baseline_auto_discovery_and_ignores(tmp_path):
    """AC-2: Scanner auto-discovers .ghostcheck-baseline.json and IgnoreMatcher defaults ignore it."""
    # Verify IgnoreMatcher default ignores include both baseline formats
    matcher = IgnoreMatcher()
    assert matcher.is_ignored(".ghostcheckbaseline") is True
    assert matcher.is_ignored(".ghostcheck-baseline.json") is True
    assert matcher.is_ignored(str(tmp_path / ".ghostcheck-baseline.json")) is True

    # Write .ghostcheck-baseline.json to tmp_path
    baseline_file = tmp_path / ".ghostcheck-baseline.json"
    baseline_data = {
        "findings": [
            {
                "file": "app.py",
                "line": 42,
                "name": "hardcoded_secret",
                "robust_fingerprint": "app.py:hardcoded_secret:abc123hash"
            }
        ]
    }
    baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

    # Scanner initialized without explicit baseline_path should auto-discover .ghostcheck-baseline.json
    scanner = Scanner(str(tmp_path))
    assert scanner.baseline_path == str(baseline_file)
    assert "app.py:42:hardcoded_secret" in scanner.baseline_findings
    assert "app.py:hardcoded_secret:abc123hash" in scanner.baseline_findings


def test_ac3_init_hook_and_honeypot_clean(tmp_path):
    """AC-3: ghostcheck init --hook installs pre-commit hook and honeypot --clean removes decoy files."""
    # 1. Test init --hook
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    initializer = GhostCheckInitializer(str(tmp_path))
    ok, msg = initializer.install_pre_commit_hook()
    assert ok is True
    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.exists()
    assert "ghostcheck scan --staged" in hook_file.read_text(encoding="utf-8")

    # CLI test for init --hook when already initialized
    with patch("sys.argv", ["ghostcheck", "init", "--hook", str(tmp_path)]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0

    # 2. Test honeypot --clean
    canary_url = "https://canarytokens.com/test-clean"
    GhostCheckHoneypotGenerator.initialize(str(tmp_path), canary_url)
    assert (tmp_path / ".env.canary").exists()
    assert (tmp_path / "aws_credentials.canary").exists()
    assert (tmp_path / "id_rsa.canary").exists()
    assert ".env.canary" in (tmp_path / ".gitignore").read_text(encoding="utf-8")

    # Run clean via CLI
    with patch("sys.argv", ["ghostcheck", "honeypot", "--clean", str(tmp_path)]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0

    assert not (tmp_path / ".env.canary").exists()
    assert not (tmp_path / "aws_credentials.canary").exists()
    assert not (tmp_path / "id_rsa.canary").exists()
    assert ".env.canary" not in (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert "# GhostCheck Canary Honeypots" not in (tmp_path / ".gitignore").read_text(encoding="utf-8")


def test_ac4_exclude_patterns_wiring_and_env_preservation(tmp_path):
    """AC-4: exclude_patterns are passed to IgnoreMatcher, .env is preserved, and [tool.ghostcheck] is merged."""
    # Check exclude_patterns in Scanner
    cfg = GhostCheckConfig(str(tmp_path))
    cfg.config["exclude_patterns"] = ["*.canary", "custom_build_*", "vendor_temp/"]
    scanner = Scanner(str(tmp_path), config=cfg)

    assert scanner.ignore_matcher.is_ignored(str(tmp_path / "custom_build_out.js")) is True
    assert scanner.ignore_matcher.is_ignored(str(tmp_path / "vendor_temp" / "file.py")) is True

    # Verify .env is NOT ignored by default excludes (only *.canary is)
    assert scanner.ignore_matcher.is_ignored(str(tmp_path / ".env")) is False
    assert scanner.ignore_matcher.is_ignored(str(tmp_path / ".env.local")) is False
    assert scanner.ignore_matcher.is_ignored(str(tmp_path / ".env.canary")) is True

    # Verify [tool.ghostcheck] config merging
    toml_path = tmp_path / "ghostcheck.toml"
    toml_path.write_text(
        """
[tool.ghostcheck]
severity_threshold = "CRITICAL"
offline = true
""",
        encoding="utf-8"
    )
    custom_cfg = GhostCheckConfig(str(tmp_path))
    assert custom_cfg.get("severity_threshold") == "CRITICAL"
    assert custom_cfg.get("offline") is True


def test_ac5_cli_target_path_config_resolution(tmp_path):
    """AC-5: CLI loads GhostCheckConfig from the specified target path."""
    sub_dir = tmp_path / "subproject"
    sub_dir.mkdir()
    sub_toml = sub_dir / "ghostcheck.toml"
    sub_toml.write_text('severity_threshold = "CRITICAL"\n', encoding="utf-8")

    # Run scan on subproject via CLI
    with patch("sys.argv", ["ghostcheck", "scan", str(sub_dir), "--offline"]):
        with patch("ghostcheck.scanner.Scanner") as mock_scanner_cls:
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = []
            mock_scanner.cache_hits = 0
            mock_scanner.scoring_engine.calculate_score.return_value = ("A", 100)
            mock_scanner_cls.return_value = mock_scanner
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
            # Ensure the config passed to Scanner was resolved from sub_dir
            _, kwargs = mock_scanner_cls.call_args
            config_arg = kwargs.get("config")
            assert config_arg is not None
            assert config_arg.get("severity_threshold") == "CRITICAL"


def test_ac6_concurrency_and_atomic_cache_writes(tmp_path):
    """AC-6: HallucinationChecker and VulnScanner are thread-safe and write cache files atomically."""
    # 1. HallucinationChecker thread safety
    hchecker = HallucinationChecker(offline=False)
    hchecker.cache_dir = str(tmp_path / "h_cache_dir")
    hchecker.cache_file = str(tmp_path / "h_cache_dir" / "hallucination_v2.json")
    hchecker.cache = {}

    # Mock the internal online query helper to return clean deterministic results
    def mock_pypi_status(pkg_name):
        return (None, "OK") if "real" in pkg_name else ({"package": pkg_name, "severity": "CRITICAL"}, "NOT_FOUND")

    hchecker._check_pypi_online_status = mock_pypi_status

    errors = []
    def worker(worker_id):
        try:
            for i in range(10):
                pkg = f"pkg_{worker_id}_{i}"
                res, network_called = hchecker._check_package("PyPI", pkg)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Encountered thread concurrency errors: {errors}"
    assert os.path.exists(hchecker.cache_file)
    assert len(hchecker.cache) == 80

    # 2. VulnScanner thread safety
    vscanner = VulnScanner(offline=True)
    vscanner.cache_dir = str(tmp_path / "v_cache_dir")
    vscanner.cache_file = str(tmp_path / "v_cache_dir" / "osv_cache.json")
    vscanner.cache = {}

    v_errors = []
    def v_worker(worker_id):
        try:
            for i in range(10):
                vscanner._set_cached("PyPI", f"package_{worker_id}_{i}", "1.0.0", {"vulns": []})
                cached = vscanner._get_cached("PyPI", f"package_{worker_id}_{i}", "1.0.0")
                assert cached == {"vulns": []}
        except Exception as e:
            v_errors.append(e)

    v_threads = [threading.Thread(target=v_worker, args=(i,)) for i in range(8)]
    for t in v_threads:
        t.start()
    for t in v_threads:
        t.join()

    assert not v_errors, f"Encountered VulnScanner concurrency errors: {v_errors}"
    assert os.path.exists(vscanner.cache_file)
    assert len(vscanner.cache) == 80


def test_ac7_cross_platform_case_safe_ignore_matcher(tmp_path):
    """AC-7: IgnoreMatcher handles Windows case-insensitivity on prefix matching while preserving relative path casing."""
    base_dir = tmp_path / "MyProject"
    base_dir.mkdir()
    test_file = base_dir / "Build" / "Output" / "bundle.js"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("console.log(1);", encoding="utf-8")

    # Pattern with lowercase directory prefix
    matcher = IgnoreMatcher(base_path=str(base_dir), patterns=["build/"])

    if os.name == "nt":
        # On Windows, build/ must match Build/Output/bundle.js case-insensitively
        assert matcher.is_ignored(str(test_file)) is True
    else:
        # On POSIX, case is preserved
        assert matcher.is_ignored(str(base_dir / "build" / "bundle.js")) is True


def test_ac8_preset_completeness_and_secret_validator_opt_in(tmp_path):
    """AC-8: Presets contain entropy/vuln/tamper, and SecretValidator is opt-in and whitespace-safe."""
    pm = PresetManager()
    for name in ["next.js", "flutter", "django", "fastapi"]:
        preset = pm.get_preset(name)
        assert "entropy" in preset["scan_modules"], f"Missing entropy in preset {name}"
        assert "vuln" in preset["scan_modules"], f"Missing vuln in preset {name}"
        assert "tamper" in preset["scan_modules"], f"Missing tamper in preset {name}"

    tf = pm.get_preset("terraform")
    assert "entropy" in tf["scan_modules"]
    assert "tamper" in tf["scan_modules"]
    assert "docker" not in tf["scan_modules"]
    assert "hallucination" not in tf["scan_modules"]

    # SecretValidator opt-in in Scanner
    cfg_default = GhostCheckConfig(str(tmp_path))
    scanner_default = Scanner(str(tmp_path), config=cfg_default)
    assert scanner_default.secret_validator.enabled is False

    cfg_opt_in = GhostCheckConfig(str(tmp_path))
    cfg_opt_in.config["validate_secrets"] = True
    scanner_opt_in = Scanner(str(tmp_path), config=cfg_opt_in)
    assert scanner_opt_in.secret_validator.enabled is True

    # SecretValidator whitespace validation safety
    validator = SecretValidator(enabled=True)
    # Dirty token with newline / spaces / context fallback should return None
    assert validator.validate({"context": "sk-1234567890abcdef", "name": "openai_key"}) is None
    assert validator.validate({"_raw_value": "sk-123456\nline2", "name": "openai_key"}) is None
    assert validator.validate({"_raw_value": "sk-123 456", "name": "openai_key"}) is None
    assert validator.validate({"_raw_value": "   ", "name": "openai_key"}) is None
