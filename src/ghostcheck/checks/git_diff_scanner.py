import subprocess
import os

class GitDiffScanner:
    def __init__(self, project_root: str):
        self.project_root = project_root

    def _run_git(self, args):
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.splitlines()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

    def get_staged_files(self):
        """Returns list of absolute paths for staged files."""
        files = self._run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        return [os.path.abspath(os.path.join(self.project_root, f)) for f in files]

    def get_diff_files(self, ref: str):
        """Returns list of absolute paths for files changed since specific ref."""
        files = self._run_git(["diff", ref, "--name-only", "--diff-filter=ACMR"])
        return [os.path.abspath(os.path.join(self.project_root, f)) for f in files]

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
