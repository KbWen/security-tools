import os
import json

class GhostCheckInitializer:
    DEFAULT_CONFIG_TEMPLATE = """# GhostCheck Configuration File
# For more info: https://github.com/KbWen/security-tools

severity_threshold = "{severity}"
exclude_patterns = {excludes}
enabled_checks = {checks}
offline = false

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
        if any(f.endswith('.tf') for f in os.listdir(root) if os.path.isfile(os.path.join(root, f))):
            return "terraform"
        if os.path.exists(os.path.join(root, 'Dockerfile')):
            return "docker"
        return "generic"

    def initialize(self, force=False):
        config_path = os.path.join(self.project_root, "ghostcheck.toml")
        if os.path.exists(config_path) and not force:
            return False, "ghostcheck.toml already exists. Use --force to overwrite."

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

        with open(config_path, "w") as f:
            f.write(content)

        # Also ensure .ghostcheckignore exists
        ignore_path = os.path.join(self.project_root, ".ghostcheckignore")
        if not os.path.exists(ignore_path):
            with open(ignore_path, "w") as f:
                f.write("# GhostCheck Ignore File\n")
                for e in excludes:
                    f.write(f"{e}\n")

        return True, f"Successfully initialized {project_type} project in {config_path}"
