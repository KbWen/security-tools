import fnmatch
import os

class IgnoreMatcher:
    def __init__(self, ignore_file_path=None, base_path=None, patterns=None):
        self.patterns = list(patterns) if patterns else []
        # AC-H5: 預設忽略二進位快取、編譯產物、套件與版本控制目錄
        default_ignores = [
            '__pycache__/', '*.pyc', '*.pyo', '*.pyd',
            '.git/', '.svn/', '.hg/',
            'node_modules/', 'vendor/', 'dist/', '.next/', 'build/',
            '.venv/', 'venv/', 'env/', '.pytest_cache/', '.mypy_cache/',
            '.turbo/', '.nuxt/',
            '.DS_Store', 'Thumbs.db',
            '.ghostcheckbaseline', '.ghostcheck-baseline.json', '.ghostcheckignore'
        ]
        for p in default_ignores:
            if p not in self.patterns:
                self.patterns.append(p)
                
        self.base_path = os.path.realpath(base_path) if base_path else None
        self.base_path_norm = os.path.normcase(self.base_path) if self.base_path else None
        if ignore_file_path and os.path.exists(ignore_file_path):
            with open(ignore_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line not in self.patterns:
                            self.patterns.append(line)

    def is_ignored(self, path):
        real_path = os.path.realpath(path)
        abs_path_norm = os.path.normcase(real_path)

        path_norm = path.replace('\\', '/')
        if path_norm.startswith('./'):
            path_norm = path_norm[2:]
        if path_norm.startswith('/'):
            path_norm = path_norm[1:]
            
        try:
            if self.base_path and self.base_path_norm and os.path.commonpath([self.base_path_norm, abs_path_norm]) == self.base_path_norm:
                rel = os.path.relpath(real_path, self.base_path).replace('\\', '/')
                if rel.startswith('./'):
                    rel = rel[2:]
                if rel.startswith('/'):
                    rel = rel[1:]
                if rel and rel != '.':
                    path_norm = rel
        except (ValueError, OSError):
            pass

        matched_status = False
        is_nt = (os.name == 'nt')

        for pattern in self.patterns:
            negate = pattern.startswith('!')
            p = pattern[1:] if negate else pattern
            p = p.replace('\\', '/')
            p_stripped = p.rstrip('/')
            
            is_match = False
            # Absolute matching from root if starts with /
            if p.startswith('/'):
                match_p = p[1:]
                prefix_check = path_norm.lower().startswith((match_p.rstrip('/') + '/').lower()) if is_nt else path_norm.startswith(match_p.rstrip('/') + '/')
                if fnmatch.fnmatch(path_norm, match_p) or prefix_check:
                    is_match = True
            else:
                # Basic filename or full path match
                prefix_check = path_norm.lower().startswith(p.lower()) if is_nt else path_norm.startswith(p)
                if fnmatch.fnmatch(path_norm, p) or fnmatch.fnmatch(os.path.basename(path_norm), p):
                    is_match = True
                elif '/' not in p_stripped and any(fnmatch.fnmatch(part, p_stripped) for part in path_norm.split('/')):
                    # Match directories anywhere ONLY if pattern has no intermediate slashes
                    is_match = True
                elif p.endswith('/') and prefix_check:
                    # Prefix matching
                    is_match = True

            if is_match:
                matched_status = not negate

        return matched_status
