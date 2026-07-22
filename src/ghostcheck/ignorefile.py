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
            '.DS_Store', 'Thumbs.db',
            '.ghostcheckbaseline', '.ghostcheckignore'
        ]
        for p in default_ignores:
            if p not in self.patterns:
                self.patterns.append(p)
                
        self.base_path = os.path.normcase(os.path.realpath(base_path)) if base_path else None
        if ignore_file_path and os.path.exists(ignore_file_path):
            with open(ignore_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line not in self.patterns:
                            self.patterns.append(line)

    def is_ignored(self, path):
        # 標準化路徑（normcase 解決 Windows 磁碟機代號大小寫差異）
        abs_path = os.path.normcase(os.path.realpath(path))
        try:
            if self.base_path and os.path.commonpath([self.base_path, abs_path]) == self.base_path:
                path = os.path.relpath(abs_path, self.base_path)
        except (ValueError, OSError):
            pass
        
        path = path.replace(os.sep, '/')
        if path.startswith('./'):
            path = path[2:]
            
        for pattern in self.patterns:
            negate = pattern.startswith('!')
            p = pattern[1:] if negate else pattern
            
            p_stripped = p.rstrip('/')
            
            # Absolute matching from root if starts with /
            if p.startswith('/'):
                match_p = p[1:]
                if fnmatch.fnmatch(path, match_p) or path.startswith(match_p.rstrip('/') + '/'):
                    return not negate
            else:
                # Basic filename or full path match
                if fnmatch.fnmatch(path, p) or fnmatch.fnmatch(os.path.basename(path), p):
                    return not negate
                
                # Match directories anywhere ONLY if pattern has no intermediate slashes
                if '/' not in p_stripped:
                    if any(fnmatch.fnmatch(part, p_stripped) for part in path.split('/')):
                        return not negate
                
                # Prefix matching
                if p.endswith('/') and path.startswith(p):
                    return not negate
                    
        return False
