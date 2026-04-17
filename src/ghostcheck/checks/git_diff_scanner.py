import subprocess
import os

class GitDiffScanner:
    def __init__(self, project_root: str):
        self.project_root = project_root

    def _run_git(self, args):
        try:
            # AC-H1: 使用 Bytes 處理以避免 Windows 下的編碼崩潰
            # Get repo root to handle relative paths correctly
            root_res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=self.project_root, capture_output=True, check=True)
            repo_root = root_res.stdout.decode('utf-8').strip()
            
            result = subprocess.run(
                ["git"] + args,
                cwd=self.project_root,
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
            # Return absolute paths relative to repo root if needed, or join with repo_root
            return [os.path.join(repo_root, f) for f in files]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

    def get_staged_files(self):
        """Returns list of absolute paths for staged files in the project root."""
        return self._run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "--", "."])

    def get_diff_files(self, ref: str):
        """Returns list of absolute paths for files changed since specific ref in the project root."""
        return self._run_git(["diff", ref, "--name-only", "--diff-filter=ACMR", "--", "."])

    def is_git_repo(self):
        try:
            subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=self.project_root,
                capture_output=True,
                check=True
            )
            return True
        except:
            return False
