import subprocess
import os
import shutil
import re
import logging

logger = logging.getLogger(__name__)

class GitDiffScanner:
    def __init__(self, project_root: str):
        self.project_root = project_root

    def _is_within(self, path: str, parent: str) -> bool:
        try:
            p_norm = os.path.normcase(os.path.realpath(path))
            parent_norm = os.path.normcase(os.path.realpath(parent))
            return os.path.commonpath([p_norm, parent_norm]) == parent_norm
        except (ValueError, OSError):
            return False

    def _get_secure_git(self):
        git_path = shutil.which("git")
        if not git_path:
            return None
        cwd = os.getcwd()
        project_abs = os.path.abspath(self.project_root)
        if os.path.isfile(project_abs):
            project_abs = os.path.dirname(project_abs) or "."
        if self._is_within(git_path, cwd) or self._is_within(git_path, project_abs):
            # Scan PATH manually excluding current/project folders, subdirectories, and relative entries
            path_env = os.environ.get("PATH", "")
            paths = path_env.split(os.pathsep)
            exts = [".exe", ".cmd", ".bat"] if os.name == "nt" else [""]
            for p in paths:
                p_clean = p.strip().strip('"')
                if not p_clean or not os.path.isabs(p_clean):
                    continue
                if self._is_within(p_clean, cwd) or self._is_within(p_clean, project_abs):
                    continue
                for ext in exts:
                    candidate = os.path.join(p_clean, f"git{ext}")
                    if self._is_within(candidate, cwd) or self._is_within(candidate, project_abs):
                        continue
                    if os.path.isfile(candidate) and (os.name == "nt" or os.access(candidate, os.X_OK)):
                        return candidate
            return None
        return git_path

    def _safe_git_env(self):
        safe_env = os.environ.copy()
        for var in (
            "GIT_EXTERNAL_DIFF",
            "GIT_PAGER",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG",
            "GIT_EXEC_PATH",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
        ):
            safe_env.pop(var, None)
        return safe_env

    def _run_git(self, args):
        try:
            cwd = os.path.abspath(self.project_root)
            if os.path.isfile(cwd):
                cwd = os.path.dirname(cwd)

            git_bin = self._get_secure_git()
            if not git_bin:
                return []

            # Clean sensitive git environment variables to prevent RCE
            safe_env = self._safe_git_env()

            def decode_bytes(b):
                try:
                    return b.decode('utf-8')
                except UnicodeDecodeError:
                    import locale
                    encoding = locale.getpreferredencoding()
                    return b.decode(encoding, errors='replace')

            hardening_flags = [
                "-c", "core.quotePath=false",
                "-c", "core.fsmonitor=false",
                "-c", "core.hooksPath=/dev/null",
                "-c", "diff.external=false",
            ]

            # AC-H1: 使用 Bytes 處理以避免 Windows 下的編碼崩潰
            # Get repo root to handle relative paths correctly
            root_res = subprocess.run(
                [git_bin] + hardening_flags + ["rev-parse", "--show-toplevel"],
                cwd=cwd,
                capture_output=True,
                check=True,
                timeout=15,
                env=safe_env
            )
            repo_root = decode_bytes(root_res.stdout).strip()
            
            result = subprocess.run(
                [git_bin] + hardening_flags + args,
                cwd=cwd,
                capture_output=True,
                check=True,
                timeout=15,
                env=safe_env
            )
            output = decode_bytes(result.stdout)
            
            files = output.splitlines()
            resolved_files = []
            for f in files:
                f = f.strip().strip('"').strip("'")
                if not f:
                    continue
                abs_path = os.path.join(repo_root, f)
                if os.path.exists(abs_path) and os.path.isfile(abs_path):
                    resolved_files.append(abs_path)
            return resolved_files
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug("GitDiffScanner git command failed: %s", e)
            return []

    def get_staged_files(self):
        """Returns list of absolute paths for staged files in the project root."""
        return self._run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "--", "."])

    def get_diff_files(self, ref: str):
        """Returns list of absolute paths for files changed since specific ref in the project root."""
        if not ref or not re.match(r'^[a-zA-Z0-9_/.:~^@{}\-]+$', ref) or ref.startswith('-'):
            return []
        return self._run_git(["diff", ref, "--name-only", "--diff-filter=ACMR", "--", "."])

    def is_git_repo(self):
        try:
            git_bin = self._get_secure_git()
            if not git_bin:
                return False
            safe_env = self._safe_git_env()
            cwd = os.path.dirname(os.path.abspath(self.project_root)) or "." if os.path.isfile(self.project_root) else self.project_root
            subprocess.run(
                [git_bin, "rev-parse", "--is-inside-work-tree"],
                cwd=cwd,
                capture_output=True,
                check=True,
                timeout=15,
                env=safe_env
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug("GitDiffScanner is_git_repo failed: %s", e)
            return False

