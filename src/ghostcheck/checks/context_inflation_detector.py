import re
import os
from typing import List, Dict, Any
from collections import Counter
from ..interfaces import BaseScannerPlugin

class ContextInflationDetector(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "context_inflation_detector"

    @property
    def description(self) -> str:
        return "Detects Context Inflation and Prompt Flooding attacks designed to bypass system prompts."

    def _read_file_safely(self, file_path: str, max_size: int = 10 * 1024 * 1024) -> str:
        """Reads file with path safety checks, size limits, binary pre-filtering, and streaming-based line truncation."""
        try:
            if not os.path.exists(file_path):
                return ""
            size = os.path.getsize(file_path)
            # Read first block for binary detection
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
            
            # Robust binary density check (prevents null-byte evasion)
            if len(chunk) > 0:
                control_chars = sum(1 for b in chunk if b < 32 and b not in (9, 10, 13))
                if control_chars > 0.02 * len(chunk):
                    return ""
            
            # Read content up to ceiling
            read_ceiling = min(size, max_size)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(read_ceiling)

            # Chaos Protection: Split long lines (>10,000 chars) to prevent ReDoS via regex replace
            content = re.sub(r'([^\n]{10000})', r'\1\n', content)
            return content
        except Exception:
            return ""

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        # Exclude common large structured/tokenizer files to prevent false positives on repetitive patterns
        excluded_extensions = ['.csv', '.tsv', '.log', '.vocab', '.model', '.lock', '.yaml', '.yml', '.toml', '.ini', '.xml']
        for file_path in files:
            filename = os.path.basename(file_path).lower()
            ext = os.path.splitext(filename)[1]
            
            # Skip media, binary, and large compiled files entirely
            if ext in ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll', '.so', '.pyc']:
                continue
            
            # Skip minified files, which naturally contain high repetition boilerplate
            if '.min.' in filename:
                continue

            # Determine if this file should only run partial scans (only check ZW and padding tokens, skip word/line repetitions)
            partial_scan = False
            if ext == '.json' and filename != 'package.json':
                partial_scan = True
            elif ext in excluded_extensions:
                partial_scan = True
            elif 'tokenizer' in filename or 'vocab' in filename:
                partial_scan = True

            content = self._read_file_safely(file_path)
            if not content:
                continue

            findings.extend(self._scan_content(file_path, content, partial_scan))
        return findings

    def _scan_content(self, file_path: str, content: str, partial_scan: bool = False) -> List[Dict[str, Any]]:
        findings = []

        # 1. Invisible Character Flooding Detection
        # Combined Unicode range class to eliminate expensive alternation backtracking (including Hangul Fillers)
        zw_chars_class = r'[\u200b-\u200f\ufeff\u202a-\u202e\u2060-\u2069\u180e\u00ad\ufe00-\ufe0f\u200a\u202f\u205f\u3000\u3164\u115f\u1160\U000e0020-\U000e007f\U000e0100-\U000e01ef\U0001d173-\U0001d17a]'
        
        consecutive_zw_match = re.search(zw_chars_class + r'{51,}', content)
        if consecutive_zw_match:
            idx = consecutive_zw_match.start()
            line = content[:idx].count('\n') + 1
            findings.append({
                "file": file_path,
                "line": line,
                "name": "context_inflation_invisible_chars",
                "severity": "CRITICAL",
                "message": f"Context Inflation: Detected {len(consecutive_zw_match.group(0))} consecutive invisible/zero-width Unicode characters.",
                "suggestion": "Remove zero-width/invisible characters used for prompt obfuscation or context padding.",
                "context": content[max(0, idx-20):idx] + "[ZW_CHARS_FLOOD]" + content[idx+len(consecutive_zw_match.group(0)):idx+len(consecutive_zw_match.group(0))+20]
            })
        else:
            # Optimize: only run count if we know there is at least one ZW character!
            if re.search(zw_chars_class, content):
                # Count matches using finditer to avoid list memory allocation, breaking early on threshold
                zw_count = 0
                for _ in re.finditer(zw_chars_class, content):
                    zw_count += 1
                    if zw_count > 200:
                        findings.append({
                            "file": file_path,
                            "line": 1,
                            "name": "context_inflation_invisible_chars",
                            "severity": "CRITICAL",
                            "message": "Context Inflation: Detected excessive total zero-width/invisible characters (>200) in file.",
                            "suggestion": "Remove zero-width/invisible characters used for prompt obfuscation or context padding."
                        })
                        break

        if not partial_scan:
            # 2. Whitespace Padding / Large Gap Detection
            whitespace_match = re.search(r'\s{1001,}', content)
            if whitespace_match:
                idx = whitespace_match.start()
                line = content[:idx].count('\n') + 1
                findings.append({
                    "file": file_path,
                    "line": line,
                    "name": "context_inflation_whitespace_padding",
                    "severity": "MEDIUM",
                    "message": f"Context Inflation: Detected large whitespace padding block ({len(whitespace_match.group(0))} characters).",
                    "suggestion": "Remove excessive consecutive whitespaces/newlines intended to push text off-screen.",
                    "context": "[WHITESPACE_PADDING_BLOCK]"
                })

            # 3. Word/Phrase Repetition Flooding Detection (Zero Allocations, CJK support, lazy tokenization)
            words = []
            cjk_regex = re.compile(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]')
            
            token_iter = re.finditer(r'\b\w+\b|[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', content)
            for m in token_iter:
                raw_token = m.group(0).lower()
                if cjk_regex.match(raw_token):
                    for char in raw_token:
                        words.append(char)
                        if len(words) >= 50000:
                            break
                else:
                    if not (raw_token.isdigit() or raw_token in ('true', 'false', 'null', '0', '1')):
                        words.append(raw_token)
                if len(words) >= 50000:
                    break

            words_len = len(words)

            # Mathematical Pre-filter: if the single most frequent word appears <= 30 times,
            # it is impossible to have any word/phrase repeated consecutively > 30 times.
            if words_len >= 30:
                word_counts = Counter(words)
                if word_counts and word_counts.most_common(1)[0][1] > 30:
                    for n in range(1, 11):  # Search for repetitions from 1-gram up to 10-gram phrases
                        triggered = False
                        i = 0
                        run_count = 1
                        while i < words_len - 2 * n + 1:
                            # Hybrid comparison: C-speed matching, fast path mismatch bypass (no allocations)
                            if words[i] == words[i + n] and words[i : i + n] == words[i + n : i + 2 * n]:
                                run_count += 1
                                if run_count > 30:
                                    phrase_str = " ".join(words[i : i + n])
                                    
                                    # Filter out short English phrases (e.g. single variables like 'x', 'i', 'a')
                                    # to prevent false positives on repetitive variable assignments.
                                    is_cjk_phrase = any(cjk_regex.match(char) for char in phrase_str)
                                    if not is_cjk_phrase:
                                        if n == 1 and all(len(w) < 3 for w in words[i : i + n]):
                                            i += 1
                                            continue
                                        elif n > 1 and all(len(w) < 2 for w in words[i : i + n]):
                                            i += 1
                                            continue

                                    findings.append({
                                        "file": file_path,
                                        "line": 1,
                                        "name": "context_inflation_word_repetition",
                                        "severity": "HIGH",
                                        "message": f"Context Inflation: Pattern '{phrase_str}' is repeated consecutively {run_count} times.",
                                        "suggestion": "Remove highly repetitive words/phrases designed to flood the LLM context."
                                    })
                                    triggered = True
                                    break
                                i += n
                            else:
                                run_count = 1
                                i += 1
                        if triggered:
                            break

            # 4. Repetitive Line Flooding Detection
            lines = content.splitlines()
            if len(lines) >= 15:
                curr_line = ""
                run_count = 0
                start_line_idx = 0
                for idx, line_raw in enumerate(lines):
                    line_stripped = line_raw.strip()
                    if not line_stripped:
                        continue
                    # Skip empty braces/brackets
                    if line_stripped in ('}', ']', ')', '{', '[', '('):
                        continue
                    
                    # Strip comment prefixes to analyze repeated text inside comments (including SQL comments '--')
                    comment_stripped = re.sub(r'^(#|//|/\*|\*|-->|rem|::|--)\s*', '', line_stripped).strip()
                    # Strip comment suffixes (e.g. trailing */ or -->)
                    comment_stripped = re.sub(r'\s*(\*/|-->)$', '', comment_stripped).strip()
                    if not comment_stripped:
                        continue

                    # Ignore pure symbol divider lines (e.g. ############# or // ---------)
                    if not re.search(r'[a-zA-Z0-9\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', comment_stripped):
                        continue
                    
                    if comment_stripped == curr_line:
                        run_count += 1
                        if run_count > 15:
                            findings.append({
                                "file": file_path,
                                "line": start_line_idx + 1,
                                "name": "context_inflation_line_repetition",
                                "severity": "HIGH",
                                "message": f"Context Inflation: Line '{curr_line}' is repeated consecutively {run_count} times (possibly within comments).",
                                "suggestion": "Remove highly repetitive lines designed to flood the LLM context.",
                                "context": curr_line
                            })
                            break
                    else:
                        curr_line = comment_stripped
                        run_count = 1
                        start_line_idx = idx

        # 5. Padding Token Spamming Detection
        filename_lower = os.path.basename(file_path).lower()
        is_tokenizer_or_vocab = 'tokenizer' in filename_lower or 'vocab' in filename_lower
        if not is_tokenizer_or_vocab:
            # Combine all 22 padding patterns into a single compiled regex for a 22x faster single-pass scan
            pad_tokens_regex = re.compile(
                r'\[pad\]|\<pad\>|\<unk\>|\<s\>|\<\/s\>|\<\|endoftext\|\>|\<\|eot_id\|\>|\<\|end_of_text\|\>|'
                r'\<\|fim_prefix\|\>|\<\|fim_middle\|\>|\<\|fim_suffix\|\>|\<\|im_start\|\>|\<\|im_end\|\>|'
                r'\[INST\]|\[\/INST\]|\<\|assistant\|\>|\[TURN\]|\<\|user\|\>|\<\|system\|\>|\<\|plugin\|\>|'
                r'\<\|call\|\>|\<\|respond\|\>', 
                re.IGNORECASE
            )
            total_pad_tokens = len(pad_tokens_regex.findall(content))
                
            if total_pad_tokens > 50:
                findings.append({
                    "file": file_path,
                    "line": 1,
                    "name": "context_inflation_padding_tokens",
                    "severity": "MEDIUM",
                    "message": f"Context Inflation: Detected excessive padding tokens ({total_pad_tokens} occurrences).",
                    "suggestion": "Avoid using large quantities of padding tokens which waste the LLM's context window."
                })
            else:
                # Check other divider spam (..., ---, ***, ===) repeating excessively
                # Skip code and structured formats to avoid false positives on comment banners/header dividers
                ext = os.path.splitext(filename_lower)[1]
                is_common_code_or_struct = ext in [
                    '.py', '.js', '.ts', '.go', '.java', '.tf', '.md', 
                    '.json', '.yml', '.yaml', '.html', '.css', '.xml', '.toml',
                    '.c', '.cpp', '.h', '.hpp', '.cs', '.rs', '.sh', '.bat', '.ps1'
                ] or filename_lower in ['dockerfile', 'makefile', 'jenkinsfile', 'gemfile', 'pipfile', 'readme', 'license']
                if not is_common_code_or_struct:
                    divider_spam_patterns = [
                        ('...', "ellipsis"),
                        ('---', "dash dividers"),
                        ('***', "asterisk dividers"),
                        ('===', "equal dividers")
                    ]
                    for divider_str, label in divider_spam_patterns:
                        count = content.count(divider_str)
                        if count > 100:  # Threshold set to 100 for safer checks
                            findings.append({
                                "file": file_path,
                                "line": 1,
                                "name": "context_inflation_padding_tokens",
                                "severity": "MEDIUM",
                                "message": f"Context Inflation: Detected excessive occurrences of {label} ({count} times).",
                                "suggestion": "Avoid repeating dividers excessively to prevent context inflation."
                            })
                            break

        return findings
