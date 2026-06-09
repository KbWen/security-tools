import os
import re
import shutil
import subprocess
import threading
import logging
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

class AIMarker(BaseScannerPlugin):
    def __init__(self, root_path: str = None):
        self.root_path = os.path.realpath(root_path) if root_path else os.getcwd()
        self._git_scanned = False
        self._git_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "ai_marker_logic_scanner"

    @property
    def description(self) -> str:
        return "Scans codebase comments and Git commit metadata to track AI-generated contributions"

    def _is_safe_path(self, file_path: str) -> bool:
        try:
            abs_path = os.path.normpath(os.path.realpath(file_path))
            root_abs = os.path.normpath(self.root_path)
            return os.path.commonpath([root_abs, abs_path]) == root_abs
        except (ValueError, OSError):
            return False

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Scan individual file comments
        for file_path in files:
            # Boundary Check: Path Traversal prevention (CWE-22)
            if not self._is_safe_path(file_path):
                logger.debug("AIMarker skipped unsafe path: %s", file_path)
                continue

            ext = os.path.splitext(file_path)[1].lower()
            # Only scan standard source files
            if ext not in ('.py', '.js', '.ts', '.tsx', '.go', '.java', '.cpp', '.c', '.h', '.sh', '.bat', '.ps1', '.sql'):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                findings.extend(self.scan_file_comments(file_path, content))
            except Exception as e:
                logger.debug("Error reading source file %s in AIMarker: %s", file_path, e)

        # 2. Programmatically audit Git history (once per scan invocation)
        # Protect with thread lock to avoid race conditions in parallel scans
        with self._git_lock:
            if not self._git_scanned:
                findings.extend(self.scan_git_history())
                self._git_scanned = True

        return findings

    def scan_file_comments(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        # Regex patterns to detect AI tool signatures in various comment formats:
        # Standard: //, #, /*, <!--
        # SQL: --
        # Batch: REM, ::
        # PowerShell block comments: <# ... #> (basic check)
        ai_comment_patterns = [
            (re.compile(r'(?://|#|/\*|<!--|--|^\s*rem\b|^\s*::)\s*(?:Generated|Auto-generated)\s+by\s+(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)', re.IGNORECASE), "ai_comment_signature"),
            (re.compile(r'(?://|#|/\*|<!--|--|^\s*rem\b|^\s*::)\s*AI-assisted\b', re.IGNORECASE), "ai_comment_signature"),
            (re.compile(r'(?://|#|/\*|<!--|--|^\s*rem\b|^\s*::)\s*Created\s+by\s+(Tabnine|Copilot|Aider|Claude|Gemini|ChatGPT|DeepSeek)', re.IGNORECASE), "ai_comment_signature"),
            (re.compile(r'<\#\s*(?:Generated|Auto-generated)\s+by\s+(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)', re.IGNORECASE), "ai_comment_signature")
        ]

        for idx, line in enumerate(lines):
            line_num = idx + 1
            for pattern, name in ai_comment_patterns:
                match = pattern.search(line)
                if match:
                    tool = match.group(1) if match.groups() and match.group(1) else "AI Tool"
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": name,
                        "severity": "INFO",
                        "suggestion": f"This code block is marked as generated or assisted by {tool}. Verify that proper human review has been performed. If this is a discussion or false positive, rephrase the comment or add inline comment '# ghostcheck-ignore ai_comment_signature'.",
                        "context": line.strip()
                    })
                    break
        return findings

    def scan_git_history(self) -> List[Dict[str, Any]]:
        findings = []
        # Find if we are inside a git tree without relying on a direct root .git directory
        # (Since root_path could be a subdirectory under a git repo)
        
        # Security Hardening (CWE-427): Use absolute resolved path to git executable 
        # to prevent binary planting on Windows, and do NOT set cwd to untrusted root_path.
        # Instead, we run git relative to the safe system/workspace cwd and use -C to target the repo.
        git_executable = shutil.which("git")
        if not git_executable:
            return findings

        # Format using standard ASCII control characters:
        # %H: Commit Hash
        # %x1f: Unit Separator (\x1f)
        # %ae: Author Email
        # %x1f: Unit Separator
        # %B: Raw Body
        # %x1e: Record Separator (\x1e)
        cmd = [git_executable, "-C", self.root_path, "-c", "core.quotePath=false", "log", "--format=%H%x1f%ae%x1f%B%x1e", "-n", "100"]
        
        try:
            # Enforce 10s timeout to prevent hanging, and process bytes directly to avoid CP950 decoding crashes
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode != 0:
                return findings
            stdout = result.stdout.decode('utf-8', errors='replace')
        except Exception as e:
            logger.debug("AIMarker failed to run git subprocess: %s", e)
            return findings

        # Regex to detect AI email domains or usernames in co-author trailers
        coauthor_pattern = re.compile(
            r'Co-authored-by:\s*(?:GitHub\s+)?(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)\b', 
            re.IGNORECASE
        )
        
        # Regex to detect AI tool names mentioned in commit subject/body
        msg_pattern = re.compile(
            r'\b(?:generated|created|assisted|written|refactored|prompted)\s+by\s+(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)\b',
            re.IGNORECASE
        )

        # Split into records (commits)
        raw_commits = stdout.split('\x1e')
        for raw_c in raw_commits:
            raw_c = raw_c.strip()
            if not raw_c:
                continue
                
            # Split into fields
            fields = raw_c.split('\x1f', 2)
            if len(fields) < 3:
                continue
                
            commit_hash, author_email, body = fields
            body_lower = body.lower()
            
            # Identify AI contributions
            coauthors = coauthor_pattern.findall(body)
            msg_mentions = msg_pattern.findall(body)
            
            # Target specific bot accounts rather than the entire developer domain
            is_ai_email = any(bot_id in author_email.lower() for bot_id in [
                "copilot@github.com", 
                "noreply@anthropic.com", 
                "aider@aider.chat", 
                "tabnine", 
                "cursor", 
                "windsurf",
                "gemini"
            ])
            
            if coauthors or msg_mentions or is_ai_email:
                # Case-insensitive check for human review trailers
                has_review = any(x in body_lower for x in ("reviewed-by:", "approved-by:", "signed-off-by:"))
                
                if not has_review:
                    tool_name = "AI Tool"
                    if coauthors:
                        tool_name = coauthors[0]
                    elif msg_mentions:
                        tool_name = msg_mentions[0]
                    elif "copilot" in author_email.lower():
                        tool_name = "Copilot"
                    elif "anthropic" in author_email.lower():
                        tool_name = "Claude"
                    elif "aider" in author_email.lower():
                        tool_name = "Aider"
                        
                    findings.append({
                        "file": "",  # Represents repository/git level finding
                        "line": 0,
                        "name": "ai_unreviewed_commit",
                        "severity": "MEDIUM",
                        "suggestion": f"Commit {commit_hash[:8]} was authored or assisted by {tool_name} but lacks human review trailers (e.g. 'Reviewed-by:'). "
                                      f"If this is a human author named {tool_name}, add a 'Reviewed-by: DevName' trailer to your commit message, or add the commit hash to ignore lists.",
                        "context": f"Commit {commit_hash[:8]}: {body.splitlines()[0] if body.splitlines() else ''}"
                    })
        return findings
