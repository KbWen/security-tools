import os
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class GhostCheckHoneypotGenerator:

    DECOY_FILES = {
        ".env.canary": (
            "# GHOSTCHECK-HONEYPOT-CANARY\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "CANARY_TOKEN_URL={url}\n"
            "DATABASE_URL=postgresql://decoy_user:decoy_pass@localhost:5432/decoy_db?token_url={url}\n"
        ),
        "aws_credentials.canary": (
            "# GHOSTCHECK-HONEYPOT-CANARY\n"
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "aws_session_token = canary_token_url={url}\n"
        ),
        "id_rsa.canary": (
            "# GHOSTCHECK-HONEYPOT-CANARY\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtcn\n"
            "NhAAAAAwEAAQAAAYEA0G55a1k1M3A...canary...\n"
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
        
        # Validate URL format to prevent injection
        if not url.startswith(('http://', 'https://')):
            return False, "Error: CanaryToken URL must start with http:// or https://"

        target_abs = os.path.abspath(target_path)
        if not os.path.exists(target_abs):
            try:
                os.makedirs(target_abs, exist_ok=True)
            except Exception as e:
                return False, f"Failed to create target directory {target_path}: {str(e)}"

        created_files = []
        for filename, template in cls.DECOY_FILES.items():
            file_path = os.path.join(target_abs, filename)
            content = template.replace("{url}", url)
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
    def clean(cls, target_path: str) -> Tuple[bool, str]:
        """
        Remove deployed decoy canary files and clean ignore entries.
        """
        target_abs = os.path.abspath(target_path)
        removed = []
        if os.path.exists(target_abs):
            for filename in cls.DECOY_FILES.keys():
                file_path = os.path.join(target_abs, filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        removed.append(filename)
                    except Exception as e:
                        logger.debug(f"Failed to remove honeypot file {file_path}: {e}")

        # Clean from local ignores
        local_entries = list(cls.DECOY_FILES.keys())
        cls._clean_ignore_file(target_abs, ".gitignore", local_entries)
        cls._clean_ignore_file(target_abs, ".ghostcheckignore", local_entries)

        # Clean from root-level ignores if target_path is subdirectory
        repo_root = cls._find_repo_root(target_abs)
        if repo_root != target_abs:
            root_relative_entries = []
            for fn in cls.DECOY_FILES.keys():
                rel_path = os.path.relpath(os.path.join(target_abs, fn), repo_root).replace(os.sep, "/")
                root_relative_entries.append(rel_path)
            cls._clean_ignore_file(repo_root, ".gitignore", root_relative_entries)
            cls._clean_ignore_file(repo_root, ".ghostcheckignore", root_relative_entries)

        return True, f"Cleaned {len(removed)} honeypot file(s)."

    @classmethod
    def _clean_ignore_file(cls, target_dir: str, ignore_filename: str, entries_to_remove: list):
        ignore_path = os.path.join(target_dir, ignore_filename)
        if not os.path.exists(ignore_path):
            return
        try:
            with open(ignore_path, "r", encoding="utf-8") as f:
                lines = [line.rstrip("\r\n") for line in f]

            remove_set = set()
            for e in entries_to_remove:
                remove_set.add(e)
                remove_set.add(f"./{e}")
                remove_set.add(f"/{e}")

            new_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped in remove_set:
                    continue
                new_lines.append(line)

            # Remove isolated "# GhostCheck Canary Honeypots" header if no canary entries remain
            cleaned_lines = []
            for i, line in enumerate(new_lines):
                if line.strip() == "# GhostCheck Canary Honeypots":
                    has_canary = False
                    for next_line in new_lines[i+1:]:
                        st = next_line.strip()
                        if st.startswith("#"):
                            break
                        if any(k in st for k in cls.DECOY_FILES.keys()):
                            has_canary = True
                            break
                    if not has_canary:
                        continue
                cleaned_lines.append(line)

            content = "\n".join(cleaned_lines)
            if cleaned_lines and not content.endswith("\n"):
                content += "\n"
            with open(ignore_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            logger.debug(f"Failed to clean ignore file {ignore_path}: {e}")

    @classmethod
    def _update_ignore_file(cls, target_path: str, ignore_filename: str, files_to_ignore: list):
        ignore_path = os.path.join(target_path, ignore_filename)
        
        # Read existing entries
        existing_lines = []
        if os.path.exists(ignore_path):
            try:
                with open(ignore_path, "r", encoding="utf-8") as f:
                    existing_lines = [line.strip() for line in f.readlines()]
            except Exception as e:
                logger.debug(f"Failed to read ignore file {ignore_path}: {e}")

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
                    f.write("# GhostCheck Canary Honeypots\n")
                    for fn in missing_ignores:
                        f.write(f"{fn}\n")
            except Exception as e:
                logger.debug(f"Failed to append to ignore file {ignore_path}: {e}")
