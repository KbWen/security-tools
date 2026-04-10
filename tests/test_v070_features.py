import pytest
from ghostcheck.checks.iac_scanner import IaCScanner
from ghostcheck.checks.ci_auditor import CIAuditor
from ghostcheck.checks.firebase_rules_auditor import FirebaseRulesAuditor

def test_iac_scanner_terraform():
    scanner = IaCScanner()
    content = """
    provider "aws" {
      access_key = "AKIAEXAMPLE123"
      secret_key = "secret_key_123"
    }
    resource "aws_security_group" "bad" {
      cidr_blocks = ["0.0.0.0/0"]
    }
    """
    findings = scanner.scan_file("main.tf", content)
    names = [f['name'] for f in findings]
    assert "hardcoded_aws_creds" in names
    assert "overly_permissive_security_group" in names
    assert all('suggestion' in f for f in findings)

def test_iac_scanner_k8s():
    scanner = IaCScanner()
    content = """
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: bad
        securityContext:
          privileged: true
      hostNetwork: true
    """
    findings = scanner.scan_file("pod.yaml", content)
    names = [f['name'] for f in findings]
    assert "privileged_container" in names
    assert "host_network_enabled" in names

def test_ci_auditor_gha():
    auditor = CIAuditor()
    content = """
    name: bad-ci
    jobs:
      scan:
        permissions: write-all
        steps:
          - uses: actions/checkout@main
          - run: echo "$MY_SECRET"
    """
    findings = auditor.scan_file(".github/workflows/bad.yml", content)
    names = [f['name'] for f in findings]
    assert "gha_write_all_permission" in names
    assert "gha_unpinned_action" in names
    assert "gha_secret_exposure_in_run" in names

def test_ci_auditor_gitlab():
    auditor = CIAuditor()
    content = """
    job1:
      tags:
        - docker
      services:
        - name: docker:dind
          privileged: true
      script:
        - echo "$CI_JOB_TOKEN"
    """
    findings = auditor.scan_file(".gitlab-ci.yml", content)
    names = [f['name'] for f in findings]
    assert "gitlab_privileged_runner" in names
    assert "gitlab_secret_exposure_in_run" in names

def test_firebase_rules():
    auditor = FirebaseRulesAuditor()
    content = """
    service cloud.firestore {
      match /databases/{database}/documents {
        match /{document=**} {
          allow read, write: if true;
        }
      }
    }
    """
    findings = auditor.scan_file("firestore.rules", content)
    names = [f['name'] for f in findings]
    assert "firebase_allow_all_read" in names
    assert "firebase_allow_all_write" in names
