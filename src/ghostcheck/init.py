import os
import json

class GhostCheckInitializer:
    DEFAULT_CONFIG_TEMPLATE = """# GhostCheck Configuration File
# For more info: https://github.com/KbWen/security-tools

severity_threshold = "{severity}"
exclude_patterns = {excludes}
enabled_checks = {checks}
offline = false
# proxy = "http://127.0.0.1:8080"

[tool.ghostcheck]
project_name = "{project_name}"
project_type = "{project_type}"
"""

    def __init__(self, project_root: str):
        self.project_root = project_root

    def detect_project_type(self):
        root = self.project_root
        
        # Priority mapping
        if os.path.exists(os.path.join(root, 'package.json')):
            return "nodejs"
        if os.path.exists(os.path.join(root, 'requirements.txt')) or os.path.exists(os.path.join(root, 'pyproject.toml')):
            return "python"
        if os.path.exists(os.path.join(root, 'go.mod')):
            return "go"
        if os.path.exists(os.path.join(root, 'Cargo.toml')):
            return "rust"
        try:
            if any(f.endswith('.tf') for f in os.listdir(root) if os.path.isfile(os.path.join(root, f))):
                return "terraform"
        except (PermissionError, OSError):
            pass
            
        if os.path.exists(os.path.join(root, 'Dockerfile')):
            return "docker"
        return "generic"

    def initialize(self, force=False):
        # Check if already in a project (upward search)
        curr = os.path.abspath(self.project_root)
        while True:
            parent_config = os.path.join(curr, "ghostcheck.toml")
            if os.path.exists(parent_config):
                if curr == os.path.abspath(self.project_root):
                    if not force:
                        return False, f"ghostcheck.toml already exists at {parent_config}. Use --force to overwrite."
                else:
                    return False, f"Project already initialized at parent directory: {curr}. No need to re-initialize here."
            
            parent = os.path.dirname(curr)
            if parent == curr:
                break
            curr = parent
            
        config_path = os.path.join(self.project_root, "ghostcheck.toml")

        project_type = self.detect_project_type()
        project_name = os.path.basename(os.path.abspath(self.project_root))

        # Default excludes based on project type
        excludes = [".git", "__pycache__", "venv", "node_modules", ".ghostcheck"]
        if project_type == "nodejs":
            excludes += ["dist", "build", ".next", ".vercel"]
        elif project_type == "python":
            excludes += ["*.pyc", ".pytest_cache"]
        elif project_type == "terraform":
            excludes += [".terraform", "*.tfstate"]

        checks = ["hallucination", "secrets", "rules", "docker"]
        if project_type == "nodejs":
            checks.append("ast_js")
        elif project_type == "python":
            checks.append("ast_python") # Note: internally these map to existing checkers

        content = self.DEFAULT_CONFIG_TEMPLATE.format(
            severity="INFO",
            excludes=json.dumps(excludes),
            checks=json.dumps(checks),
            project_name=project_name,
            project_type=project_type
        )

        with open(config_path, "w", encoding='utf-8') as f:
            f.write(content)

        # Also ensure .ghostcheckignore exists
        ignore_path = os.path.join(self.project_root, ".ghostcheckignore")
        if not os.path.exists(ignore_path):
            with open(ignore_path, "w", encoding='utf-8') as f:
                f.write("# GhostCheck Ignore File\n")
                for e in excludes:
                    f.write(f"{e}\n")

        print(f"  - 已生成設定檔: {config_path}")
        print(f"  - 已生成忽略清單: {ignore_path}")

        return True, f"成功在 {project_type} 專案中初始化 GhostCheck"

    def generate_ci_pipeline(self, provider: str):
        provider = provider.lower()
        if provider == "github":
            return self._generate_github_action()
        elif provider == "gitlab":
            return self._generate_gitlab_ci()
        return False, f"Unsupported CI provider: {provider}"

    def _generate_github_action(self):
        workflows_dir = os.path.join(self.project_root, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        
        ci_path = os.path.join(workflows_dir, "ghostcheck.yml")
        content = """name: GhostCheck Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 0 * * *' # Daily scan

jobs:
  scan:
    name: GhostCheck
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # For SARIF upload
    
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history for git-diff scan

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install GhostCheck
        run: |
          python -m pip install --upgrade pip
          pip install ghostcheck

      - name: Run GhostCheck Scan
        run: |
          # Scan everything and output SARIF for GitHub Security Tab
          ghostcheck scan . --format sarif --output ghostcheck-results.sarif
        continue-on-error: true # Don't block pipeline by default, but report to Security Tab

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ghostcheck-results.sarif
"""
        with open(ci_path, "w", encoding='utf-8') as f:
            f.write(content)
        return True, f"GitHub Action generated at {ci_path}"

    def _generate_gitlab_ci(self):
        ci_path = os.path.join(self.project_root, ".gitlab-ci.yml")
        content = """stages:
  - test
  - security

ghostcheck-scan:
  stage: security
  image: python:3.10-slim
  script:
    - pip install ghostcheck
    - ghostcheck scan . --format json --output ghostcheck-report.json
  artifacts:
    reports:
      sast: ghostcheck-report.json
    paths:
      - ghostcheck-report.json
  only:
    - main
    - merge_requests
"""
        with open(ci_path, "w", encoding='utf-8') as f:
            f.write(content)
        return True, f"GitLab CI generated at {ci_path}"
