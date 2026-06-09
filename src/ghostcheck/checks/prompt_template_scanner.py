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

        # Rule 1: High-risk placeholder names
        high_risk_names = {'system', 'instruction', 'instructions', 'prompt', 'rules', 'directive', 'directives', 'role', 'roles'}
        
        # Regexes supporting optional whitespace and trailing expressions/lookups (e.g. { system.content }, { system['rules'] })
        fstring_placeholder_re = re.compile(r'(?<!{){\s*([a-zA-Z_][a-zA-Z0-9_]*)(?:\[[^\]]*\]|\.[a-zA-Z0-9_]+)*\s*}')
        jinja_placeholder_re = re.compile(r'{{\s*([a-zA-Z_][a-zA-Z0-9_]*)(?:\[[^\]]*\]|\.[a-zA-Z0-9_]+)*\s*}}')

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
                
                var_name = match.group(1).strip()
                if var_name.lower() in high_risk_names:
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "high_risk_placeholder_name",
                        "severity": "HIGH",
                        "suggestion": f"Placeholder '{var_name}' uses a name reserved for instructions. An attacker could exploit this to override system prompts.",
                        "context": line.strip()
                    })

            # Find jinja style placeholders
            for match in jinja_placeholder_re.finditer(line):
                var_name = match.group(1).strip()
                if var_name.lower() in high_risk_names:
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "name": "high_risk_placeholder_name",
                        "severity": "HIGH",
                        "suggestion": f"Jinja2 placeholder '{{{{ {var_name} }}}}' uses a name reserved for instructions. An attacker could exploit this to override system prompts.",
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
            all_placeholders.append((match.group(1), start, end))

        for match in jinja_placeholder_re.finditer(content):
            all_placeholders.append((match.group(1), match.start(), match.end()))

        for var_name, start, end in all_placeholders:
            if var_name.lower() in high_risk_names:
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
            # Split striped content to avoid empty lines with newlines
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
                                  f"triple quotes (\"\"\"), or horizontal rules (---) to isolate it from system instructions.",
                    "context": placeholder_line
                })

        # Rule 3: Insecure Jinja2 filters (e.g., safe) anywhere in a filter chain
        # Excludes matching cross-braces boundaries via [^}]
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
                                  f"This disables HTML escaping and can lead to cross-site scripting (XSS) or injection if rendered in a web/UI context.",
                    "context": line.strip()
                })

        # Rule 4: Suspicious Jailbreak Phrasing (with basic synonym checking and multiline awareness)
        suspicious_words = ["ignore", "disregard", "bypass", "override"]
        target_words = ["previous", "above", "preceding", "system", "instruction", "instructions"]
        
        # Check line-by-line first
        for idx, line in enumerate(lines):
            line_num = idx + 1
            line_lower = line.lower()
            if any(w in line_lower for w in suspicious_words) and any(t in line_lower for t in target_words):
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "name": "suspicious_jailbreak_phrasing",
                    "severity": "MEDIUM",
                    "suggestion": f"Suspicious instruction override phrasing detected: '{line.strip()}'. "
                                  f"Ensure this is not a hardcoded prompt injection vulnerability or bad example.",
                    "context": line.strip()
                })

        return findings
