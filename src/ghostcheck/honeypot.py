import os
from typing import Tuple

class GhostCheckHoneypotGenerator:

    DECOY_FILES = {
        ".env.decoy": (
            "# GHOSTCHECK-HONEYPOT-DECOY\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "CANARY_TOKEN_URL={url}\n"
            "DATABASE_URL=postgresql://decoy_user:decoy_pass@localhost:5432/decoy_db?token_url={url}\n"
        ),
        "aws_credentials.decoy": (
            "# GHOSTCHECK-HONEYPOT-DECOY\n"
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "aws_session_token = canary_token_url={url}\n"
        ),
        "id_rsa.decoy": (
            "# GHOSTCHECK-HONEYPOT-DECOY\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtcn\n"
            "NhAAAAAwEAAQAAAYEA0G55a1k1M3A...decoy...\n"
            "# CanaryToken Verification Callback: {url}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
    }

    @classmethod
    def _find_repo_root(cls, path: str) -> str:
        curr = os.path.abspath(path)
        while True:
            if os.path.exists(os.path.join(curr, ".git")) or os.path.exists(os.path.join(curr, "pyproject.toml")) or os.path.exists(os.path.join(curr, "ghostcheck.toml")):
                return curr
            parent = os.path.dirname(curr)
            if parent == curr:
                break
            curr = parent
        return os.path.abspath(path)

    @classmethod
    def initialize(cls, target_path: str, url: str) -> Tuple[bool, str]:
        """
        Initialize and generate decoy files embedded with CanaryToken URL.
        Automatically registers files in .gitignore and .ghostcheckignore.
        """
        if not url:
            return False, "Error: CanaryToken URL is required."

        target_abs = os.path.abspath(target_path)
        if not os.path.exists(target_abs):
            try:
                os.makedirs(target_abs, exist_ok=True)
            except Exception as e:
                return False, f"Failed to create target directory {target_path}: {str(e)}"

        created_files = []
        for filename, template in cls.DECOY_FILES.items():
            file_path = os.path.join(target_abs, filename)
            content = template.format(url=url)
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                created_files.append(filename)
            except Exception as e:
                return False, f"Failed to write decoy file {filename}: {str(e)}"

        # Update local ignores
        cls._update_ignore_file(target_abs, ".gitignore", created_files)
        cls._update_ignore_file(target_abs, ".ghostcheckignore", created_files)

        # Update root-level ignores if target_path is a subdirectory
        repo_root = cls._find_repo_root(target_abs)
        if repo_root != target_abs:
            # Calculate relative path of decoy files from root
            root_relative_files = []
            for fn in created_files:
                rel_path = os.path.relpath(os.path.join(target_abs, fn), repo_root)
                # Normalize separator to forward slash
                rel_path_str = rel_path.replace(os.sep, "/")
                root_relative_files.append(rel_path_str)
            
            cls._update_ignore_file(repo_root, ".gitignore", root_relative_files)
            cls._update_ignore_file(repo_root, ".ghostcheckignore", root_relative_files)

        return True, f"Successfully created {len(created_files)} honeypot files: {', '.join(created_files)} and registered them in ignores."

    @classmethod
    def _update_ignore_file(cls, target_path: str, ignore_filename: str, files_to_ignore: list):
        ignore_path = os.path.join(target_path, ignore_filename)
        
        # Read existing entries
        existing_lines = []
        if os.path.exists(ignore_path):
            try:
                with open(ignore_path, "r", encoding="utf-8") as f:
                    existing_lines = [line.strip() for line in f.readlines()]
            except Exception:
                pass

        # Append missing files
        missing_ignores = []
        for fn in files_to_ignore:
            # check both filename and relative path formats
            if fn not in existing_lines and f"./{fn}" not in existing_lines and f"/{fn}" not in existing_lines:
                missing_ignores.append(fn)

        if missing_ignores:
            try:
                with open(ignore_path, "a", encoding="utf-8") as f:
                    # add newline if not at start of line
                    if existing_lines and not existing_lines[-1] == "":
                        f.write("\n")
                    f.write("# GhostCheck Decoy Honeypots\n")
                    for fn in missing_ignores:
                        f.write(f"{fn}\n")
            except Exception:
                pass

