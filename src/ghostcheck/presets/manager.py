import os
import json

class PresetManager:
    """Manages framework-specific scan presets and auto-detection logic."""
    
    def __init__(self):
        self.presets = {
            "next.js": {
                "name": "Next.js",
                "description": "Optimized for Next.js, React, and Vercel environments.",
                "scan_modules": ["hallucination", "secrets", "env", "ci_cd", "api", "docker", "logic"],
                "important_files": ["package.json", "next.config.js", "vercel.json", ".env"],
                "priority_rules": ["hallucinated_package", "env_secret_found", "js_secret"]
            },
            "flutter": {
                "name": "Flutter",
                "description": "Deep scan for Flutter/Dart apps, registry verification, and mobile configs.",
                "scan_modules": ["hallucination", "secrets", "mobile", "ci_cd", "rules", "iac", "logic"],
                "important_files": ["pubspec.yaml", "AndroidManifest.xml", "Info.plist", "google-services.json"],
                "priority_rules": ["pub_dev_hallucination", "sensitive_mobile_config_found", "dart_secret"]
            },
            "django": {
                "name": "Django",
                "description": "Focused on Django settings, production security, and DB credentials.",
                "scan_modules": ["hallucination", "secrets", "env", "docker", "iac", "logic"],
                "important_files": ["settings.py", "manage.py", "wsgi.py", "requirements.txt"],
                "priority_rules": ["django_debug_enabled", "hardcoded_secret", "docker_root_user"]
            },
            "fastapi": {
                "name": "FastAPI",
                "description": "Optimized for FastAPI/Uvicorn, Pydantic, and async API security.",
                "scan_modules": ["hallucination", "secrets", "env", "api", "docker", "logic"],
                "important_files": ["main.py", "requirements.txt", "Dockerfile"],
                "priority_rules": ["api_wildcard_cors", "hardcoded_api_key", "missing_auth_dependency"]
            },
            "terraform": {
                "name": "Terraform",
                "description": "Focused on IaC security, provider blocks, and state file hygiene.",
                "scan_modules": ["iac", "secrets", "ci_cd"],
                "important_files": ["main.tf", "variables.tf", "terraform.tfstate"],
                "priority_rules": ["hardcoded_creds_in_tf", "unencrypted_s3_bucket", "open_security_group"]
            }
        }

    def get_preset(self, name):
        if not name:
            return None
        return self.presets.get(name.lower())

    def list_presets(self):
        return [(k, v['name'], v['description']) for k, v in self.presets.items()]

    def detect_preset(self, root_path):
        """Proactively identifies the project framework based on files."""
        # Simple file-based signature detection
        if os.path.exists(os.path.join(root_path, "pubspec.yaml")):
            return "flutter"
        
        if os.path.exists(os.path.join(root_path, "next.config.js")) or \
           os.path.exists(os.path.join(root_path, "next.config.mjs")):
            return "next.js"
            
        if os.path.exists(os.path.join(root_path, "manage.py")):
            return "django"
            
        if os.path.exists(os.path.join(root_path, "go.mod")):
            return "generic" # Placeholder for future go preset
            
        # Check package.json for specific dependencies if ambiguity exists
        pkg_json = os.path.join(root_path, "package.json")
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if '"next"' in content: return "next.js"
                    if '"react-native"' in content: return "react-native"
            except (IOError, json.JSONDecodeError): pass

        try:
            if any(f.endswith('.tf') for f in os.listdir(root_path) if os.path.isfile(os.path.join(root_path, f))):
                return "terraform"
        except (OSError, PermissionError):
            pass

        return "generic"
