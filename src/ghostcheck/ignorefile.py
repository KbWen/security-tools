import fnmatch
import os

class IgnoreMatcher:
    def __init__(self, ignore_file_path=None, base_path=None, patterns=None):
        self.patterns = patterns or []
        # AC-H5: 預設忽略二進位快取與版本控制目錄
        default_ignores = [
            '__pycache__/', '*.pyc', '*.pyo', '*.pyd',
            '.git/', '.svn/', '.hg/',
            'node_modules/', 'vendor/',
            '.DS_Store', 'Thumbs.db'
        ]
        for p in default_ignores:
            if p not in self.patterns:
                self.patterns.append(p)
                
        self.base_path = os.path.realpath(base_path) if base_path else None
        if ignore_file_path and os.path.exists(ignore_file_path):
            with open(ignore_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line not in self.patterns:
                            self.patterns.append(line)

    def is_ignored(self, path):
        # 標準化路徑
        abs_path = os.path.realpath(path)
        if self.base_path and os.path.commonpath([self.base_path, abs_path]) == self.base_path:
            path = os.path.relpath(abs_path, self.base_path)
        
        path = path.replace(os.sep, '/')
        if path.startswith('./'):
            path = path[2:]
            
        for pattern in self.patterns:
            negate = pattern.startswith('!')
            p = pattern[1:] if negate else pattern
            
            # AC-H4: 增強比對邏輯，支援父目錄比對
            if fnmatch.fnmatch(path, p) or \
               fnmatch.fnmatch(os.path.basename(path), p) or \
               any(fnmatch.fnmatch(part, p) for part in path.split('/')):
                return not negate
                
            # Directory match
            if p.endswith('/') and path.startswith(p):
                return not negate
                
        return False
