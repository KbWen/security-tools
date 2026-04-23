import re

import json
import os

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
        if any(kw in target_line for kw in self.negative_keywords):
            return True
        if any(kw in target_line for kw in self.example_keywords):
            return True
            
        # 2. Block/List Context Check (Look back up to 15 lines)
        # We look for the parent list item or the nearest text outside a code block.
        start_idx = max(0, target_idx - 15)
        context_window = lines[start_idx:target_idx]
        
        # Are we in a code block?
        # A simple heuristic: count ``` before the target line
        code_block_count = sum(1 for i in range(target_idx) if lines[i].strip().startswith("```"))
        in_code_block = code_block_count % 2 != 0
        
        context_line = ""
        for prev_line in reversed(context_window):
            stripped = prev_line.strip()
            if not stripped or stripped.startswith("```"):
                continue
                
            prev_lower = prev_line.lower()
            
            # If we hit a list parent item or preceding text containing a keyword, it's safe
            if any(kw in prev_lower for kw in self.negative_keywords + self.example_keywords):
                return True
                
            # If it's a major structural element (header), we stop looking further
            if re.match(r'^#+\s', prev_line):
                break
            
        return False
