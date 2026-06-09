import re

import json
import os

def _has_keyword(text: str, keyword: str) -> bool:
    keyword_lower = keyword.lower()
    text_lower = text.lower()
    if any(ord(char) > 0x2e80 for char in keyword_lower):
        return keyword_lower in text_lower
        
    # Build boundary check pattern dynamically based on whether boundary characters are alphanumeric
    left_boundary = r'(?<![a-zA-Z0-9])' if keyword_lower[0].isalnum() else ''
    right_boundary = r'(?![a-zA-Z0-9])' if keyword_lower[-1].isalnum() else ''
    
    pattern = left_boundary + re.escape(keyword_lower) + right_boundary
    return bool(re.search(pattern, text_lower))


class ContextAuditor:
    """
    Analyzes the context around a finding to determine if it's instructional,
    negative constraint, or example code, primarily for documentation files.
    """
    def __init__(self, config=None):
        # Load multilingual keywords from data file
        data_path = os.path.join(os.path.dirname(__file__), "..", "data", "context_keywords.json")
        try:
            with open(data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.negative_keywords = data.get("negative_keywords", [])
                self.example_keywords = data.get("example_keywords", [])
        except Exception:
            # Fallback to English and Chinese if file is missing
            self.negative_keywords = ["forbidden", "don't", "do not", "never", "avoid", "避免", "嚴禁", "不可", "請勿", "禁止"]
            self.example_keywords = ["example:", "sample:", "placeholder", "mock", "例如", "範例", "如："]

        if config:
            custom_negative = config.get("custom_safe_keywords", [])
            custom_example = config.get("custom_example_keywords", [])
            self.negative_keywords.extend(custom_negative)
            self.example_keywords.extend(custom_example)
        
    def _is_doc_file(self, filename: str) -> bool:
        doc_exts = ['.md', '.mdc', '.txt', '.rst']
        filename_lower = filename.lower()
        if any(filename_lower.endswith(ext) for ext in doc_exts):
            return True
            
        # Ensure we don't treat code files (e.g. rules.py) as documentation
        source_exts = ['.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.kt', '.php', '.rb', '.cs', '.swift', '.cpp', '.c', '.h', '.sh', '.bat', '.ps1', '.sql']
        ext = os.path.splitext(filename_lower)[1]
        if ext in source_exts:
            return False
            
        if "readme" in filename_lower or "rules" in filename_lower:
            return True
        return False

    def is_safe_context(self, file_path: str, content: str, line_num: int) -> bool:
        """
        Determines if the finding at line_num is in a safe context (e.g., inside an example
        or a negative constraint rule in a documentation file).
        """
        if not self._is_doc_file(file_path):
            return False
            
        if not content or line_num <= 0:
            return False
            
        lines = content.splitlines()
        if line_num > len(lines):
            return False
            
        target_idx = line_num - 1
        target_line = lines[target_idx].lower()
        
        # 1. Same-line context check
        if any(_has_keyword(target_line, kw) for kw in self.negative_keywords):
            return True
        if any(_has_keyword(target_line, kw) for kw in self.example_keywords):
            return True
            
        # 2. Block/List Context Check (Look back up to 100 lines)
        start_idx = max(0, target_idx - 100)
        context_window = lines[start_idx:target_idx]
        
        # Are we in a code block?
        code_block_count = sum(1 for i in range(target_idx) if lines[i].strip().startswith("```"))
        in_code_block = code_block_count % 2 != 0
        
        non_blank_count = 0
        for prev_line in reversed(context_window):
            stripped = prev_line.strip()
            
            # If we were in a code block, and we hit the opening block markdown ```
            # We check the lines immediately before this code block, but stop traversing further to avoid cross-boundary false positives.
            if in_code_block and stripped.startswith("```"):
                try:
                    line_pos = lines.index(prev_line)
                    above_window = lines[max(0, line_pos - 5):line_pos]
                    for ab_line in reversed(above_window):
                        if ab_line.strip():
                            if any(_has_keyword(ab_line.lower(), kw) for kw in self.negative_keywords + self.example_keywords):
                                return True
                            if re.match(r'^#+\s', ab_line) or ab_line.strip().startswith("```"):
                                break
                except ValueError:
                    pass
                break
                
            if not stripped:
                continue
                
            # Stop walk-back if we hit structural elements
            if stripped.startswith("```") or re.match(r'^#+\s', prev_line) or stripped == "---":
                break
                
            prev_lower = prev_line.lower()
            
            # If we hit a list parent item or preceding text containing a keyword, it's safe
            if any(_has_keyword(prev_lower, kw) for kw in self.negative_keywords + self.example_keywords):
                return True
                
            # Limit the number of non-blank context lines we traverse to prevent carrying context across unrelated paragraphs
            non_blank_count += 1
            if non_blank_count > 10:
                break
            
        return False
