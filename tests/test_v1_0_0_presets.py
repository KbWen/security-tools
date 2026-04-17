import os
import json

# Stable TOML support
_tomllib = None
try:
    import tomllib as _tomllib
except ImportError:
    try:
        import tomli as _tomllib
    except ImportError:
        pass

from ghostcheck.init import GhostCheckInitializer
from ghostcheck.scanner import Scanner
from ghostcheck.config import GhostCheckConfig

def test_preset_detection_flutter(tmp_path):
    project_dir = tmp_path / "my_flutter_app"
    project_dir.mkdir()
    (project_dir / "pubspec.yaml").write_text("name: my_app")
    
    initializer = GhostCheckInitializer(str(project_dir))
    success, msg = initializer.initialize()
    assert success
    assert "flutter" in msg.lower()
    
    config_path = project_dir / "ghostcheck.toml"
    if _tomllib:
        with open(config_path, "rb") as f:
            config_data = _tomllib.load(f)
        
        assert config_data.get("preset") == "flutter"
        # Flutter preset should enable 'mobile' scan module
        assert "mobile" in config_data.get("enabled_checks", [])
    else:
        # Fallback: check file content strings
        content = config_path.read_text()
        assert 'preset = "flutter"' in content
        assert '"mobile"' in content

def test_preset_scan_filtering(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    
    # 1. Create a Dockerfile that triggers a finding (Missing USER or Latest Tag)
    # We use a Dockerfile with latest tag and NO user.
    (project_dir / "Dockerfile").write_text("FROM alpine:latest")
    
    # 2. Add requirements.txt that triggers hallucination (if checkers are enabled)
    (project_dir / "requirements.txt").write_text("non-existent-pkg-hallucination==1.0.0")
    
    # 3. Scan with 'django' preset (has both)
    config_django = GhostCheckConfig(str(project_dir))
    config_django.config['preset'] = 'django'
    scanner_django = Scanner(str(project_dir), config=config_django)
    findings_django = scanner_django.scan()
    
    finding_names = [str(f.get('name') or f.get('pattern_name') or f.get('rule_name') or f.get('package') or "unknown") for f in findings_django]
    print(f"\nDjango findings: {finding_names}")
    for f in findings_django:
        print(f"  Finding: {f.get('file')} - {f.get('rule_name') or f.get('name')}")

    
    # Django should see Docker issues and Hallucination
    assert any("latesttag" in n.lower().replace(" ", "") or "docker" in n.lower() or "user" in n.lower() for n in finding_names)
    assert any("hal" in n.lower() or "package" in n.lower() for n in finding_names)

    # 4. Scan with 'terraform' preset (has NEITHER docker nor hallucination)
    config_tf = GhostCheckConfig(str(project_dir))
    config_tf.config['preset'] = 'terraform'
    scanner_tf = Scanner(str(project_dir), config=config_tf)
    findings_tf = scanner_tf.scan()
    
    finding_names_tf = [str(f.get('name') or f.get('pattern_name') or f.get('rule_name') or "unknown") for f in findings_tf]
    print(f"Terraform findings: {finding_names_tf}")
    
    assert not any("docker" in n.lower() or "user" in n.lower() or "latest" in n.lower() for n in finding_names_tf)
    assert not any("hal" in n.lower() or "package" in n.lower() for n in finding_names_tf)
