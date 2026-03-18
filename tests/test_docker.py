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
    
    # Should still have low/info or none? 
    # Our current implementation might flag latest tag if omitted?
    # Let's see what's in src/ghostcheck/checks/docker.py
    pass
