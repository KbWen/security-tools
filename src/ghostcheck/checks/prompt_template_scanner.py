import os
import re
import logging
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

class PromptTemplateScanner(BaseScannerPlugin):
    def __init__(self, root_path: str = None):
        self.root_path = os.path.realpath(root_path) if root_path else os.getcwd()

    @property
    def name(self) -> str:
        return "prompt_template_supplychain_scanner"

    @property
    def description(self) -> str:
        return "Statically checks prompt templates for injection, layout, and delimiter risks"

    def _is_safe_path(self, file_path: str) -> bool:
        try:
            abs_path = os.path.normpath(os.path.realpath(file_path))
            root_abs = os.path.normpath(self.root_path)
            return os.path.commonpath([root_abs, abs_path]) == root_abs
        except (ValueError, OSError):
            return False

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            # Boundary Check: Path Traversal prevention (CWE-22)
            if not self._is_safe_path(file_path):
                logger.debug("PromptTemplateScanner skipped unsafe path: %s", file_path)
                continue

            filepath_lower = file_path.lower().replace('\\', '/')
            filename = os.path.basename(file_path).lower()
            
            # Identify prompt template files
            is_prompt_file = (
                file_path.endswith('.prompt') or
                file_path.endswith('.jinja2') or
                file_path.endswith('.jinja') or
                file_path.endswith('.tmpl') or
                file_path.endswith('.template') or
                ('prompts/' in filepath_lower and (
                    file_path.endswith('.md') or 
                    file_path.endswith('.txt') or 
                    file_path.endswith('.yaml') or 
                    file_path.endswith('.yml')
                ))
            )
            
            if not is_prompt_file:
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                findings.extend(self.scan_content(file_path, content))
            except Exception as e:
                # AC-S11 / Exception Handling: Use debug logging instead of silent pass
                logger.debug("Error reading prompt template file %s: %s", file_path, e)
        return findings

    def scan_content(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        # Cache splitlines to prevent O(M*N) CPU resource exhaustion
        lines = content.splitlines()

        # Rule 1: High-risk placeholder names (using word-boundary check for nested expressions)
        high_risk_re = re.compile(r'\b(system|instruction|instructions|prompt|rules|directive|directives|role|roles)\b', re.IGNORECASE)
        
        # Regexes capturing the full expression inside brackets (preventing ReDoS by avoiding nested/overlapping spaces)
        fstring_placeholder_re = re.compile(r'(?<!{){([^{}]+)}(?!})')
        jinja_placeholder_re = re.compile(r'{{([^{}]+)}}')

        # Check line by line for context
        for idx, line in enumerate(lines):
            line_num = idx + 1
            
            # Find f-string style placeholders
            for match in fstring_placeholder_re.finditer(line):
                # Ensure it's not a double brace (which is escaped in f-strings)
                start, end = match.span()
                if start > 0 and line[start-1] == '{':
                    continue
                if end < len(line) and line[end] == '}':
                    continue
                
                expr = match.group(1).strip()
                high_risk_match = high_risk_re.search(expr)
                if high_risk_match:
                    var_name = high_risk_match.group(1)
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "high_risk_placeholder_name",
                        "severity": "HIGH",
                        "suggestion": f"Placeholder '{expr}' contains name '{var_name}' reserved for LLM system directives. An attacker could exploit this to override instructions. Rename the variable (e.g. to 'user_role' or 'organization_rules') or add inline comment '# ghostcheck-ignore high_risk_placeholder_name' if this is a false positive.",
                        "context": line.strip()
                    })

            # Find jinja style placeholders
            for match in jinja_placeholder_re.finditer(line):
                expr = match.group(1).strip()
                high_risk_match = high_risk_re.search(expr)
                if high_risk_match:
                    var_name = high_risk_match.group(1)
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "high_risk_placeholder_name",
                        "severity": "HIGH",
                        "suggestion": f"Jinja2 placeholder '{{{{ {expr} }}}}' contains name '{var_name}' reserved for LLM system directives. An attacker could exploit this to override instructions. Rename the variable or add inline comment '# ghostcheck-ignore high_risk_placeholder_name' if this is a false positive.",
                        "context": line.strip()
                    })

        # Rule 2: Missing Delimiters / Input Boundary Constraints
        all_placeholders = []
        
        # We need offsets to calculate "before" and "after" context
        for match in fstring_placeholder_re.finditer(content):
            start, end = match.span()
            if start > 0 and content[start-1] == '{':
                continue
            if end < len(content) and content[end] == '}':
                continue
            all_placeholders.append((match.group(1).strip(), start, end))

        for match in jinja_placeholder_re.finditer(content):
            all_placeholders.append((match.group(1).strip(), match.start(), match.end()))

        # 1. Positional format placeholders like {} or {0} (preventing ReDoS by avoiding nested/overlapping spaces)
        pos_placeholder_re = re.compile(r'(?<!{){(\d*)}(?!})')
        for match in pos_placeholder_re.finditer(content):
            start, end = match.span()
            if start > 0 and content[start-1] == '{':
                continue
            if end < len(content) and content[end] == '}':
                continue
            all_placeholders.append((match.group(0), start, end))

        # 2. printf-style %s or %(name)s
        percent_placeholder_re = re.compile(r'(?<!%)%(\([a-zA-Z0-9_]+\))?[sSdD]')
        for match in percent_placeholder_re.finditer(content):
            var_name = match.group(1).strip("()").strip() if match.group(1) else match.group(0)
            all_placeholders.append((var_name, match.start(), match.end()))

            # Also check if it's a high-risk name
            high_risk_match = high_risk_re.search(var_name)
            if high_risk_match:
                line_num = content.count('\n', 0, match.start()) + 1
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "high_risk_placeholder_name",
                    "severity": "HIGH",
                    "suggestion": f"Printf placeholder '{match.group(0)}' contains name '{high_risk_match.group(1)}' reserved for LLM system directives. Rename it or use environment/safe variables.",
                    "context": lines[line_num - 1].strip() if line_num <= len(lines) else ""
                })

        # 3. string.Template style $name or ${name}
        dollar_placeholder_re = re.compile(r'\$(?:([a-zA-Z_][a-zA-Z0-9_]*)|{([a-zA-Z_][a-zA-Z0-9_]*)})')
        for match in dollar_placeholder_re.finditer(content):
            var_name = (match.group(1) or match.group(2) or match.group(0)).strip()
            all_placeholders.append((var_name, match.start(), match.end()))

            # Also check if it's a high-risk name
            high_risk_match = high_risk_re.search(var_name)
            if high_risk_match:
                line_num = content.count('\n', 0, match.start()) + 1
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "high_risk_placeholder_name",
                    "severity": "HIGH",
                    "suggestion": f"Template placeholder '{match.group(0)}' contains name '{high_risk_match.group(1)}' reserved for LLM system directives. Rename it or use safe configuration keys.",
                    "context": lines[line_num - 1].strip() if line_num <= len(lines) else ""
                })

        for var_name, start, end in all_placeholders:
            if high_risk_re.search(var_name):
                continue
                
            # Extract local window of context
            before = content[max(0, start - 100):start]
            after = content[end:min(len(content), end + 100)]
            
            line_num = content.count('\n', 0, start) + 1
            placeholder_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""

            # Check for delimiters (with attribute tolerance):
            # 1. XML tags: e.g. <tag id="foo">...{placeholder}... </tag>
            xml_before = re.search(r'<([a-zA-Z0-9_-]+)(?:\s+[^>]+)?/?>\s*$', before.strip())
            xml_after = re.search(r'^\s*</([a-zA-Z0-9_-]+)>', after.strip())
            has_xml = xml_before and xml_after and xml_before.group(1) == xml_after.group(1)
            
            # 2. Triple quotes
            has_triple_quotes = before.strip().endswith('"""') and after.strip().startswith('"""')
            
            # 3. Triple backticks (code blocks) with optional language specifier
            has_code_block = bool(re.search(r'```[a-zA-Z0-9_-]*$', before.strip())) and after.strip().startswith('```')

            # 4. Markdown horizontal rules/separators
            lines_before = before.strip().splitlines()
            lines_after = after.strip().splitlines()
            has_separator = False
            if lines_before and lines_after:
                last_line_before = lines_before[-1].strip()
                first_line_after = lines_after[0].strip()
                if (last_line_before in ('---', '===', '***') or last_line_before.startswith('---')) and \
                   (first_line_after in ('---', '===', '***') or first_line_after.startswith('---')):
                    has_separator = True

            if not (has_xml or has_triple_quotes or has_code_block or has_separator):
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "missing_input_delimiter",
                    "severity": "MEDIUM",
                    "suggestion": f"Placeholder '{var_name}' is interpolated without clear delimiters. "
                                  f"Wrap user input in XML tags (e.g. <input>{{{var_name}}}</input>), "
                                  f"triple quotes (\"\"\"), or horizontal rules (---) to isolate it from system instructions. "
                                  f"If this is a simple template where injection is not a concern, add inline comment '# ghostcheck-ignore missing_input_delimiter' to bypass.",
                    "context": placeholder_line
                })

        # Rule 3: Insecure Jinja2 filters (e.g., safe) anywhere in a filter chain
        jinja_safe_re = re.compile(r'{{\s*([^}]+?)\|\s*safe\b[^}]*}}')
        for idx, line in enumerate(lines):
            line_num = idx + 1
            match = jinja_safe_re.search(line)
            if match:
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "insecure_jinja_safe_filter",
                    "severity": "HIGH",
                    "suggestion": f"Use of '| safe' filter with placeholder '{match.group(1).strip()}'. "
                                  f"This disables HTML escaping and can lead to cross-site scripting (XSS) or injection if rendered in a web/UI context. "
                                  f"If you intentionally want to bypass escaping for trusted input, add inline comment '# ghostcheck-ignore insecure_jinja_safe_filter'.",
                    "context": line.strip()
                })

        # Rule 3a: Jinja2 block-level escape overrides (filter safe or autoescape false/off)
        block_override_re = re.compile(r'{%\s*(filter\s+safe|autoescape\s+(false|off|False))\s*%}', re.IGNORECASE)
        for idx, line in enumerate(lines):
            line_num = idx + 1
            match = block_override_re.search(line)
            if match:
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "insecure_jinja_autoescape_override",
                    "severity": "HIGH",
                    "suggestion": f"Insecure block-level autoescape override detected: '{match.group(1)}'. "
                                  f"This disables autoescaping for all contents inside the block and can lead to injection or XSS. "
                                  f"If you intentionally want to bypass escaping for trusted input, add inline comment '# ghostcheck-ignore insecure_jinja_autoescape_override'.",
                    "context": line.strip()
                })

        # Rule 4: Suspicious Jailbreak Phrasing (with basic synonym checking and multiline awareness)
        suspicious_words = ["ignore", "disregard", "bypass", "override"]
        target_words = ["previous", "above", "preceding", "system", "instruction", "instructions"]
        
        flagged_jailbreak_lines = set()
        # Check line-by-line first
        for idx, line in enumerate(lines):
            line_num = idx + 1
            line_lower = line.lower()
            if any(w in line_lower for w in suspicious_words) and any(t in line_lower for t in target_words):
                flagged_jailbreak_lines.add(line_num)
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "suspicious_jailbreak_phrasing",
                    "severity": "MEDIUM",
                    "suggestion": f"Suspicious instruction override phrasing detected: '{line.strip()}'. "
                                  f"Ensure this is not a hardcoded prompt injection vulnerability or bad example. "
                                  f"If this is a defensive instruction or test fixture, add inline comment '# ghostcheck-ignore suspicious_jailbreak_phrasing'.",
                    "context": line.strip()
                })

        # Rule 4a: Check multiline jailbreak phrasing using distance-bounded regex
        multiline_jailbreak_re1 = re.compile(
            r'\b(ignore|disregard|bypass|override)\b[\s\S]{0,100}?\b(previous|above|preceding|system|instructions?)\b',
            re.IGNORECASE
        )
        multiline_jailbreak_re2 = re.compile(
            r'\b(previous|above|preceding|system|instructions?)\b[\s\S]{0,100}?\b(ignore|disregard|bypass|override)\b',
            re.IGNORECASE
        )

        for pattern in [multiline_jailbreak_re1, multiline_jailbreak_re2]:
            for match in pattern.finditer(content):
                start_offset = match.start()
                line_num = content.count('\n', 0, start_offset) + 1
                if line_num in flagged_jailbreak_lines:
                    continue
                flagged_jailbreak_lines.add(line_num)
                
                match_text = match.group(0).strip()
                first_line = match_text.splitlines()[0] if match_text else ""
                if len(first_line) > 100:
                    first_line = first_line[:97] + "..."
                    
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "suspicious_jailbreak_phrasing",
                    "severity": "MEDIUM",
                    "suggestion": f"Suspicious multiline instruction override phrasing detected: '{first_line}'. "
                                  f"Ensure this is not a hardcoded prompt injection vulnerability or bad example. "
                                  f"If this is a defensive instruction or test fixture, add inline comment '# ghostcheck-ignore suspicious_jailbreak_phrasing'.",
                    "context": first_line
                })

        return findings
