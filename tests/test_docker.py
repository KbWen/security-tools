import pytest
from ghostcheck.checks.docker import DockerRiskChecker

def test_docker_latest_tag():
    checker = DockerRiskChecker()
    content = "FROM python:latest\nRUN apt-get update"
    findings = checker.check_dockerfile(content)
    
    assert any("latest" in f['message'] for f in findings)
    assert any(f['severity'] == "MEDIUM" for f in findings)

def test_docker_missing_user():
    checker = DockerRiskChecker()
    content = "FROM python:3.9-slim\nRUN pip install requests"
    findings = checker.check_dockerfile(content)
    
    assert any("USER" in f['message'] for f in findings)
    assert any(f['severity'] == "HIGH" for f in findings)

def test_docker_safe_file():
    checker = DockerRiskChecker()
    content = "FROM python:3.9-slim\nUSER appuser\nCMD ['python']"
    findings = checker.check_dockerfile(content)
    
    # Should not trigger Missing USER Instruction
    assert not any(f['rule_name'] == "Missing USER Instruction" for f in findings)

def test_docker_root_user():
    checker = DockerRiskChecker()
    content = "FROM python:3.9-slim\nUSER root\nCMD ['python']"
    findings = checker.check_dockerfile(content)
    assert any(f['rule_name'] == "Root User Execution" for f in findings)

def test_docker_env_secrets():
    checker = DockerRiskChecker()
    content = """
    FROM node:20
    ENV API_KEY = "my_super_secret"
    ENV DB_PASSWORD="xyz"
    USER appuser
    """
    findings = checker.check_dockerfile(content)
    assert any(f['rule_name'] == "Hardcoded Secret" for f in findings)

def test_docker_scan_routing(tmp_path):
    # Test scan method routing for Dockerfile and docker-compose.yml
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM node:latest", encoding="utf-8")
    
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("privileged: true", encoding="utf-8")
    
    checker = DockerRiskChecker()
    findings = checker.scan([str(dockerfile), str(compose)], None)
    
    assert len(findings) >= 2
    assert any("docker-compose" in f['file'] for f in findings)
    assert any("Dockerfile" in f['file'] for f in findings)

def test_docker_scan_file_compose():
    checker = DockerRiskChecker()
    content = """
    version: '3'
    services:
      web:
        image: nginx
        privileged: true
        ports:
          - "2375:2375"
    """
    findings = checker.scan_file("docker-compose.yml", content)
    assert any(f['rule_name'] == "Privileged Container" for f in findings)
    assert any(f['rule_name'] == "Insecure Port Mapping" for f in findings)
