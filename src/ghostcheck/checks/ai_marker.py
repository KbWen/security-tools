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
        if not self._git_scanned:
            with self._git_lock:
                if not self._git_scanned:
                    findings.extend(self.scan_git_history())
                    self._git_scanned = True

        return findings

    def scan_file_comments(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Broad multi-line / block comment structures (C-style, HTML, python docstrings, PowerShell block comments)
        # We search these first in the whole file to prevent bypass where comment delimiters and AI keywords are on separate lines.
        multiline_patterns = [
            # /* ... */
            re.compile(r'/\*([\s\S]*?)\*/'),
            # <!-- ... -->
            re.compile(r'<!--([\s\S]*?)-->'),
            # """ ... """
            re.compile(r'"""([\s\S]*?)"""'),
            # ''' ... '''
            re.compile(r"'''([\s\S]*?)'''"),
            # <# ... #>
            re.compile(r'<\#([\s\S]*?)\#>')
        ]
        
        ai_keywords_pattern = re.compile(
            r'\b(?:Generated|Auto-generated|Created|Assisted)\s+by\s+(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)\b'
            r'|\bAI-assisted\b', 
            re.IGNORECASE
        )
        
        detected_lines = set()
        
        for p in multiline_patterns:
            for match in p.finditer(content):
                block_content = match.group(1)
                keyword_match = ai_keywords_pattern.search(block_content)
                if keyword_match:
                    start_offset = match.start()
                    line_num = content.count('\n', 0, start_offset) + 1
                    detected_lines.add(line_num)
                    tool = keyword_match.group(1) if keyword_match.groups() and keyword_match.group(1) else "AI Tool"
                    
                    # Extract snippet context (first non-empty line of match or the keyword match line)
                    snippet_lines = match.group(0).splitlines()
                    snippet = next((l.strip() for l in snippet_lines if l.strip()), "")
                    
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "ai_comment_signature",
                        "severity": "INFO",
                        "suggestion": f"This code block is marked as generated or assisted by {tool}. Verify that proper human review has been performed. If this is a discussion or false positive, rephrase the comment or add inline comment '# ghostcheck-ignore ai_comment_signature'.",
                        "context": snippet
                    })

        # 2. Standard single-line checks (for //, #, --, rem, ::)
        # Scan line by line, skipping lines that were already flagged by block comments
        lines = content.splitlines()
        single_line_patterns = [
            (re.compile(r'(?://|#|--|^\s*rem\b|^\s*::)\s*(?:Generated|Auto-generated)\s+by\s+(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)', re.IGNORECASE), "ai_comment_signature"),
            (re.compile(r'(?://|#|--|^\s*rem\b|^\s*::)\s*AI-assisted\b', re.IGNORECASE), "ai_comment_signature"),
            (re.compile(r'(?://|#|--|^\s*rem\b|^\s*::)\s*Created\s+by\s+(Tabnine|Copilot|Aider|Claude|Gemini|ChatGPT|DeepSeek)', re.IGNORECASE), "ai_comment_signature")
        ]

        for idx, line in enumerate(lines):
            line_num = idx + 1
            if line_num in detected_lines:
                continue
            for pattern, name in single_line_patterns:
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
        git_executable = shutil.which("git")
        if not git_executable:
            return findings

        cmd = [
            git_executable, "-C", self.root_path,
            "-c", "core.quotePath=false",
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.pager=cat",
            "log", "--format=%H%x1f%ae%x1f%B%x1e", "-n", "100"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode != 0:
                return findings
            stdout = result.stdout.decode('utf-8', errors='replace')
        except Exception as e:
            logger.debug("AIMarker failed to run git subprocess: %s", e)
            return findings

        coauthor_pattern = re.compile(
            r'Co-authored-by:\s*(?:GitHub\s+)?(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)\b', 
            re.IGNORECASE
        )
        
        msg_pattern = re.compile(
            r'\b(?:generated|created|assisted|written|refactored|prompted)\s+by\s+(Copilot|Claude|Aider|Tabnine|Cursor|Windsurf|Gemini|ChatGPT|GPT-4|DeepSeek|Mistral|Qwen|Llama|AI)\b',
            re.IGNORECASE
        )

        raw_commits = stdout.split('\x1e')
        for raw_c in raw_commits:
            raw_c = raw_c.strip()
            if not raw_c:
                continue
                
            fields = raw_c.split('\x1f', 2)
            if len(fields) < 3:
                continue
                
            commit_hash, author_email, body = fields
            
            coauthors = coauthor_pattern.findall(body)
            msg_mentions = msg_pattern.findall(body)
            
            author_email_lower = author_email.lower().strip()
            ai_email_exacts = [
                "copilot@github.com",
                "noreply@anthropic.com",
                "aider@aider.chat"
            ]
            ai_email_domains = [
                "@tabnine.com",
                "@cursor.com",
                "@cursor.sh",
                "@windsurf.ai",
                "@gemini.ai",
                "@openai.com"
            ]
            is_ai_email = (author_email_lower in ai_email_exacts or 
                           any(author_email_lower.endswith(dom) for dom in ai_email_domains))
            
            if coauthors or msg_mentions or is_ai_email:
                # Strictly parse Git trailers from the very last block of the commit body
                blocks = [b.strip() for b in body.strip().split('\n\n') if b.strip()]
                has_human_review = False
                if blocks:
                    last_block = blocks[-1]
                    lines = last_block.splitlines()
                    is_trailer_block = True
                    parsed_trailers = []
                    for line in lines:
                        match_tr = re.match(r'^([a-zA-Z0-9_-]+):\s*(.*)$', line.strip())
                        if not match_tr:
                            is_trailer_block = False
                            break
                        parsed_trailers.append((match_tr.group(1).lower(), match_tr.group(2)))
                    
                    if is_trailer_block:
                        for key, val in parsed_trailers:
                            if key in ["reviewed-by", "approved-by", "signed-off-by"]:
                                val_lower = val.lower()
                                # Ensure reviewer is a human (use word boundaries to prevent false positives)
                                is_reviewer_ai = any(
                                    re.search(r'\b' + re.escape(bot) + r'\b', val_lower)
                                    for bot in [
                                        "copilot", "claude", "aider", "tabnine", "cursor", 
                                        "windsurf", "gemini", "chatgpt", "gpt-4", "deepseek", 
                                        "mistral", "qwen", "llama", "bot", "ai"
                                    ]
                                )
                                if not is_reviewer_ai:
                                    has_human_review = True
                                    break
                
                if not has_human_review:
                    tool_name = "AI Tool"
                    if coauthors:
                        tool_name = coauthors[0]
                    elif msg_mentions:
                        tool_name = msg_mentions[0]
                    elif "copilot" in author_email_lower:
                        tool_name = "Copilot"
                    elif "anthropic" in author_email_lower:
                        tool_name = "Claude"
                    elif "aider" in author_email_lower:
                        tool_name = "Aider"
                        
                    findings.append({
                        "file": "",  
                        "line": 0,
                        "name": "ai_unreviewed_commit",
                        "severity": "MEDIUM",
                        "suggestion": f"Commit {commit_hash[:8]} was authored or assisted by {tool_name} but lacks human review trailers (e.g. 'Reviewed-by:'). "
                                      f"If this is a human author named {tool_name}, add a 'Reviewed-by: DevName' trailer to your commit message, or add the commit hash to ignore lists.",
                        "context": f"Commit {commit_hash[:8]}: {body.splitlines()[0] if body.splitlines() else ''}"
                    })
        return findings
