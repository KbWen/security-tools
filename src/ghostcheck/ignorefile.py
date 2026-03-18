import fnmatch
import os

class IgnoreMatcher:
    def __init__(self, ignore_file_path=None, base_path=None):
        self.patterns = []
        self.base_path = os.path.abspath(base_path) if base_path else None
        if ignore_file_path and os.path.exists(ignore_file_path):
            with open(ignore_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.patterns.append(line)

    def is_ignored(self, path):
        # Normalize and make relative to base_path if possible
        abs_path = os.path.abspath(path)
        if self.base_path and abs_path.startswith(self.base_path):
            path = os.path.relpath(abs_path, self.base_path)
        
        path = path.replace(os.sep, '/')
        if path.startswith('./'):
            path = path[2:]
            
        for pattern in self.patterns:
            negate = pattern.startswith('!')
            p = pattern[1:] if negate else pattern
            
            # Basic glob matching
            if fnmatch.fnmatch(path, p) or fnmatch.fnmatch(os.path.basename(path), p):
                return not negate
                
            # Directory match
            if p.endswith('/') and path.startswith(p):
                return not negate
                
        return False
