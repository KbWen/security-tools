import fnmatch
import os

class IgnoreMatcher:
    def __init__(self, ignore_file_path=None):
        self.patterns = []
        if ignore_file_path and os.path.exists(ignore_file_path):
            with open(ignore_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.patterns.append(line)

    def is_ignored(self, path):
        # Normalize path for matching
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
