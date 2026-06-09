import subprocess
import os
import shutil
import re

class GitDiffScanner:
    def __init__(self, project_root: str):
        self.project_root = project_root

    def _get_secure_git(self):
        git_path = shutil.which("git")
        if not git_path:
            return None
        abs_git = os.path.abspath(git_path)
        cwd = os.getcwd()
        project_abs = os.path.abspath(self.project_root)
        if abs_git.startswith(cwd) or abs_git.startswith(project_abs):
            # Scan PATH manually excluding current folder or relative entries
            path_env = os.environ.get("PATH", "")
            paths = path_env.split(os.pathsep)
            for p in paths:
                if not p or p.strip() in [".", ""]:
                    continue
                p_abs = os.path.abspath(p)
                if p_abs == cwd or p_abs == project_abs:
                    continue
                for ext in ["", ".exe", ".cmd", ".bat"]:
                    candidate = os.path.join(p, f"git{ext}")
                    if os.path.exists(candidate) and os.path.isfile(candidate):
                        return candidate
            return None
        return git_path

    def _run_git(self, args):
        try:
            cwd = os.path.abspath(self.project_root)
            if os.path.isfile(cwd):
                cwd = os.path.dirname(cwd)

            git_bin = self._get_secure_git()
            if not git_bin:
                return []

            # AC-H1: 使用 Bytes 處理以避免 Windows 下的編碼崩潰
            # Get repo root to handle relative paths correctly
            root_res = subprocess.run([git_bin, "-c", "core.quotePath=false", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, check=True)
            repo_root = root_res.stdout.decode('utf-8').strip()
            
            result = subprocess.run(
                [git_bin, "-c", "core.quotePath=false"] + args,
                cwd=cwd,
                capture_output=True,
                check=True
            )
            # 優先嘗試 UTF-8
            try:
                output = result.stdout.decode('utf-8')
            except UnicodeDecodeError:
                import locale
                encoding = locale.getpreferredencoding()
                output = result.stdout.decode(encoding, errors='replace')
            
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
        except (subprocess.CalledProcessError, FileNotFoundError):
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
            subprocess.run(
                [git_bin, "rev-parse", "--is-inside-work-tree"],
                cwd=self.project_root,
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            return False

