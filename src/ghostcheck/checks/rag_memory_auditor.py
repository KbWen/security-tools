import os
import re
import ast
import json
import base64
import binascii
import codecs
import logging
from typing import List, Dict, Any, Optional, Set

from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

# Constants for detection patterns
INJECTION_PAYLOAD_PATTERN = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior)"
    r"|system\s*(?:prompt\s*)?override"
    r"|<\|im_start\|>\s*system"
    r"|developer\s+mode"
    r"|(?:curl|wget)\s+https?://"
    r"|exfiltrate)",
    re.IGNORECASE,
)

PLAINTEXT_DIRECTIVE_PATTERN = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|system\s*prompt\s*override"
    r"|<\|im_start\|>\s*system"
    r"|\[system\s*override\]"
    r"|new\s+primary\s+directive\s*:)",
    re.IGNORECASE,
)

BASE64_CANDIDATE_PATTERN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HEX_CANDIDATE_PATTERN = re.compile(r"\b(?:0x)?((?:[0-9a-fA-F]{2}){12,})\b")

ROT13_CANONICAL_STRINGS = (
    "vtaber nyy cerivbhf",
    "vtaber cerivbhf vafgehpgvbaf",
    "flfgrz bireevqr",
    "qvferneq nyy cerivbhf",
)

DEFENSIVE_WORDS = (
    "never",
    "prohibited",
    "do not",
    "don't",
    "must not",
    "detect",
    "prevent",
    "scanner",
    "example",
    "禁止",
    "防止",
    "偵測",
    "請勿",
    "範例",
)

HIDDEN_UNICODE_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")

def _is_rule_suppressed(line: str, rule_id: str, allow_bare: bool) -> bool:
    """
    Checks if a line contains an inline suppression directive for a specific rule.
    Format:
        # ghostcheck-ignore
        # ghostcheck-ignore: rule1, rule2
        // ghostcheck-ignore: rule1
        <!-- ghostcheck-ignore: rule1 -->
        /* ghostcheck-ignore: rule1 */
        -- ghostcheck-ignore: rule1
    """
    m = re.search(
        r"(?:#|//|/\*|<!--|--)\s*ghostcheck-ignore(?::\s*([^\r\n*#]+))?",
        line,
        re.IGNORECASE,
    )
    if not m:
        return False
    rule_spec = m.group(1)
    if rule_spec is None:
        return allow_bare

    cleaned = rule_spec
    for trailer in ("-->", "*/"):
        if trailer in cleaned:
            cleaned = cleaned.split(trailer)[0]
    targets = [t.strip().lower() for t in cleaned.split(",") if t.strip()]
    return rule_id.lower() in targets

VECTOR_DB_IDENTIFIERS = (
    "chromadb",
    "PersistentClient",
    "HttpClient",
    "pinecone",
    "Pinecone",
    "qdrant",
    "QdrantClient",
    "weaviate",
    "milvus",
    "PGVector",
    "Chroma",
    "FAISS",
)

VECTOR_DB_INGEST_CALLS = (
    "add_texts",
    "add_documents",
    "from_documents",
    "upsert",
)

UNTRUSTED_INDICATORS = (
    "request.",
    "req.",
    "user_input",
    "raw_",
    "untrusted",
    "webhook",
    "scraped",
    "body[",
    "payload",
)

SANITIZATION_INDICATORS = (
    "sanitize",
    "clean",
    "validate",
    "allowlist",
    "strip_",
    "escape",
    "filter_metadata",
)

CALL_REGEX = re.compile(
    r"\.(?:add_texts|add_documents|from_documents|upsert)\s*\(", re.IGNORECASE
)


class RagMemoryAuditor(BaseScannerPlugin):
    """
    Audits RAG corpora, persistent agent memory files, and Vector DB metadata
    ingestion for indirect, encoded prompt injections and poisonings.
    """

    supports_binary: bool = False

    @property
    def name(self) -> str:
        return "rag_memory_auditor"

    @property
    def description(self) -> str:
        return "Audits RAG corpora, persistent agent memory files, and Vector DB metadata ingestion for indirect and encoded prompt injections."

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for file_path in files:
            try:
                findings.extend(self._scan_single_file(file_path))
            except Exception as e:
                logger.debug("Unexpected error scanning file %s: %s", file_path, e)
        return findings

    def _is_rag_or_memory_file(self, file_path: str) -> bool:
        path_norm = file_path.replace("\\", "/").lower()
        basename = os.path.basename(path_norm)
        ext = os.path.splitext(basename)[1]

        # 1. Ends with .jsonl
        if path_norm.endswith(".jsonl"):
            return True

        # 2. Basename matches *memory*.md, *memory*.json, memory.txt, .cursorrules.memory, .cursor/memory*
        if (
            basename == "memory.txt"
            or basename == ".cursorrules.memory"
            or basename.endswith(".cursorrules.memory")
            or "/.cursor/memory" in ("/" + path_norm.lstrip("/"))
        ):
            return True
        if "memory" in basename and ext in (".md", ".json"):
            return True

        # 3. Path contains /memory/, /memories/, /rag/, /knowledge/, /corpus/, /prompts/ with valid extension
        valid_exts = (".md", ".txt", ".json", ".jsonl", ".csv")
        if ext in valid_exts:
            padded_path = "/" + path_norm.lstrip("/")
            rag_dir_markers = (
                "/memory/",
                "/memories/",
                "/rag/",
                "/knowledge/",
                "/corpus/",
                "/prompts/",
            )
            if any(marker in padded_path for marker in rag_dir_markers):
                return True

        return False

    def _is_vectordb_target_file(self, file_path: str) -> bool:
        basename = os.path.basename(file_path).lower()
        ext = os.path.splitext(basename)[1]
        return ext in (".py", ".js", ".ts", ".tsx", ".jsx")

    def _read_file_safe(self, file_path: str) -> Optional[str]:
        try:
            if not os.path.isfile(file_path):
                return None
            # Check first 1024 bytes for binary indicators
            with open(file_path, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    logger.debug("Skipping binary file with null byte: %s", file_path)
                    return None
                if header:
                    control_chars = sum(
                        1 for b in header if b < 32 and b not in (9, 10, 13)
                    )
                    if (control_chars / len(header)) > 0.02:
                        logger.debug(
                            "Skipping binary file (control chars > 2%%): %s", file_path
                        )
                        return None

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(2 * 1024 * 1024)
        except Exception as e:
            logger.debug("Failed safe read of %s: %s", file_path, e)
            return None

    def _scan_single_file(self, file_path: str) -> List[Dict[str, Any]]:
        is_rag_mem = self._is_rag_or_memory_file(file_path)
        is_vdb = self._is_vectordb_target_file(file_path)

        if not is_rag_mem and not is_vdb:
            return []

        content = self._read_file_safe(file_path)
        if content is None:
            return []

        # Truncate lines > 10,000 chars for safety
        raw_lines = content.splitlines()
        lines = [line[:10000] for line in raw_lines]

        findings: List[Dict[str, Any]] = []

        if is_rag_mem:
            findings.extend(self._scan_rag_memory(file_path, lines))

        if is_vdb:
            if any(ident in content for ident in VECTOR_DB_IDENTIFIERS):
                findings.extend(self._scan_vectordb(file_path, content, lines))

        return findings

    def _scan_rag_memory(
        self, file_path: str, lines: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for idx, line in enumerate(lines):
            line_num = idx + 1

            line_lower = line.lower()
            emitted_rules: Set[str] = set()

            # Rule 1a: Encoded Payload Detection (CRITICAL)
            # 1a-1: Base64 candidates
            for match in BASE64_CANDIDATE_PATTERN.finditer(line):
                cand = match.group(0)
                raw = cand.rstrip("=")
                rem = len(raw) % 4
                if rem == 1:
                    continue
                pad_needed = (4 - rem) % 4
                padded = raw + ("=" * pad_needed)
                try:
                    decoded_bytes = base64.b64decode(padded, validate=False)
                    decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                    if decoded_text:
                        printable_count = sum(
                            1
                            for ch in decoded_text
                            if (32 <= ord(ch) <= 126) or ch in ("\t", "\n", "\r")
                        )
                        if (printable_count / len(decoded_text)) >= 0.8:
                            if INJECTION_PAYLOAD_PATTERN.search(decoded_text):
                                rule = "rag_poisoning_encoded_payload"
                                if rule not in emitted_rules:
                                    if not _is_rule_suppressed(
                                        line, rule, allow_bare=False
                                    ):
                                        emitted_rules.add(rule)
                                        findings.append(
                                            {
                                                "file": file_path,
                                                "line": line_num,
                                                "name": rule,
                                                "severity": "CRITICAL",
                                                "message": "Detected PyRIT-style encoded injection payload (Base64) in RAG/memory corpus",
                                                "context": line.strip()[:120],
                                            }
                                        )
                                break
                except Exception as e:
                    logger.debug(
                        "Base64 candidate decode error on %s line %d: %s",
                        file_path,
                        line_num,
                        e,
                    )

            # 1a-2: Hex candidates
            if "rag_poisoning_encoded_payload" not in emitted_rules:
                for match in HEX_CANDIDATE_PATTERN.finditer(line):
                    hex_str = match.group(1)
                    try:
                        decoded_bytes = bytes.fromhex(hex_str)
                        decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                        if decoded_text:
                            printable_count = sum(
                                1
                                for ch in decoded_text
                                if (32 <= ord(ch) <= 126) or ch in ("\t", "\n", "\r")
                            )
                            if (printable_count / len(decoded_text)) >= 0.8:
                                if INJECTION_PAYLOAD_PATTERN.search(decoded_text):
                                    rule = "rag_poisoning_encoded_payload"
                                    if not _is_rule_suppressed(
                                        line, rule, allow_bare=False
                                    ):
                                        emitted_rules.add(rule)
                                        findings.append(
                                            {
                                                "file": file_path,
                                                "line": line_num,
                                                "name": rule,
                                                "severity": "CRITICAL",
                                                "message": "Detected PyRIT-style encoded injection payload (Hex) in RAG/memory corpus",
                                                "context": line.strip()[:120],
                                            }
                                        )
                                    break
                    except Exception as e:
                        logger.debug(
                            "Hex candidate decode error on %s line %d: %s",
                            file_path,
                            line_num,
                            e,
                        )

            # 1a-3: ROT13 candidates
            if "rag_poisoning_encoded_payload" not in emitted_rules:
                rot13_triggered = "rot13" in line_lower or any(
                    s in line_lower for s in ROT13_CANONICAL_STRINGS
                )
                if rot13_triggered:
                    try:
                        decoded_rot13 = codecs.decode(line, "rot_13")
                        if INJECTION_PAYLOAD_PATTERN.search(decoded_rot13):
                            rule = "rag_poisoning_encoded_payload"
                            if not _is_rule_suppressed(
                                line, rule, allow_bare=False
                            ):
                                emitted_rules.add(rule)
                                findings.append(
                                    {
                                        "file": file_path,
                                        "line": line_num,
                                        "name": rule,
                                        "severity": "CRITICAL",
                                        "message": "Detected PyRIT-style encoded injection payload (ROT13) in RAG/memory corpus",
                                        "context": line.strip()[:120],
                                    }
                                )
                    except Exception as e:
                        logger.debug(
                            "ROT13 decode error on %s line %d: %s",
                            file_path,
                            line_num,
                            e,
                        )

            # Rule 1b: Plaintext Directive Override (HIGH)
            if "memory_poisoning_directive" not in emitted_rules:
                has_hidden_unicode = bool(HIDDEN_UNICODE_PATTERN.search(line))
                # Strip hidden unicode to detect evasion attempts that break regex tokens
                line_unhidden = HIDDEN_UNICODE_PATTERN.sub("", line) if has_hidden_unicode else line

                if PLAINTEXT_DIRECTIVE_PATTERN.search(line_unhidden):
                    line_unhidden_lower = line_unhidden.lower()
                    has_defensive = any(dw in line_unhidden_lower for dw in DEFENSIVE_WORDS)

                    # Defensive zero-FP guard: exempt only if defensive words exist without hidden unicode
                    if not has_defensive or has_hidden_unicode:
                        rule = "memory_poisoning_directive"
                        if not _is_rule_suppressed(
                            line, rule, allow_bare=False
                        ):
                            emitted_rules.add(rule)
                            findings.append(
                                {
                                    "file": file_path,
                                    "line": line_num,
                                    "name": rule,
                                    "severity": "HIGH",
                                    "message": "Detected prompt injection or directive override in persistent agent memory/knowledge document",
                                    "context": line.strip()[:120],
                                }
                            )

        return findings

    def _scan_vectordb(
        self, file_path: str, content: str, lines: List[str]
    ) -> List[Dict[str, Any]]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".py":
            try:
                return self._scan_vectordb_python_ast(file_path, content, lines)
            except Exception as e:
                logger.debug(
                    "ast.parse failed on %s: %s; falling back to regex window scan",
                    file_path,
                    e,
                )
                return self._scan_vectordb_regex(file_path, lines)
        else:
            return self._scan_vectordb_regex(file_path, lines)

    def _scan_vectordb_python_ast(
        self, file_path: str, content: str, lines: List[str]
    ) -> List[Dict[str, Any]]:
        tree = ast.parse(content, filename=file_path)
        findings: List[Dict[str, Any]] = []

        # Map call nodes to enclosing function if any
        call_contexts: Dict[ast.Call, ast.AST] = {}
        target_calls: List[ast.Call] = []

        class CallFinder(ast.NodeVisitor):
            def __init__(self):
                self._current_func: Optional[ast.AST] = None

            def visit_FunctionDef(self, node: ast.FunctionDef):
                prev = self._current_func
                self._current_func = node
                self.generic_visit(node)
                self._current_func = prev

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                prev = self._current_func
                self._current_func = node
                self.generic_visit(node)
                self._current_func = prev

            def visit_Call(self, node: ast.Call):
                func_name = None
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in VECTOR_DB_INGEST_CALLS:
                    target_calls.append(node)
                    if self._current_func:
                        call_contexts[node] = self._current_func
                self.generic_visit(node)

        visitor = CallFinder()
        visitor.visit(tree)

        for call_node in target_calls:
            call_line = getattr(call_node, "lineno", 1)
            end_line = getattr(call_node, "end_lineno", call_line)

            # Check inline suppression on call lines
            is_suppressed = False
            for line_idx in range(call_line - 1, min(len(lines), end_line)):
                if _is_rule_suppressed(
                    lines[line_idx], "vectordb_metadata_poisoning_risk", allow_bare=True
                ):
                    is_suppressed = True
                    break
            if is_suppressed:
                continue

            # Analyze if metadata passes untrusted input
            is_untrusted_meta = False
            try:
                for kw in call_node.keywords:
                    if kw.arg and kw.arg.lower() in (
                        "metadata",
                        "metadatas",
                        "points",
                        "vectors",
                    ):
                        kw_val_str = ast.unparse(kw.value).lower()
                        if any(u in kw_val_str for u in UNTRUSTED_INDICATORS):
                            is_untrusted_meta = True
                            break
                    else:
                        kw_val_str = ast.unparse(kw.value).lower()
                        if any(
                            p in kw_val_str
                            for p in ("metadata", "metadatas", "points", "vectors")
                        ) and any(u in kw_val_str for u in UNTRUSTED_INDICATORS):
                            is_untrusted_meta = True
                            break

                if not is_untrusted_meta:
                    for arg in call_node.args:
                        arg_str = ast.unparse(arg).lower()
                        if any(
                            p in arg_str
                            for p in ("metadata", "metadatas", "points", "vectors")
                        ) and any(u in arg_str for u in UNTRUSTED_INDICATORS):
                            is_untrusted_meta = True
                            break
            except Exception as e:
                logger.debug(
                    "Error inspecting AST arguments on %s line %d: %s",
                    file_path,
                    call_line,
                    e,
                )

            if not is_untrusted_meta:
                continue

            # Check sanitization in enclosing function
            is_sanitized = False
            func_node = call_contexts.get(call_node)
            if func_node:
                try:
                    func_text = ast.unparse(func_node).lower()
                    if any(s in func_text for s in SANITIZATION_INDICATORS):
                        is_sanitized = True
                except Exception as e:
                    logger.debug(
                        "Error inspecting enclosing function AST on %s: %s",
                        file_path,
                        e,
                    )

            # Check sanitization in ±15 lines window
            if not is_sanitized:
                win_start = max(0, call_line - 16)
                win_end = min(len(lines), call_line + 15)
                win_text = "\n".join(lines[win_start:win_end]).lower()
                if any(s in win_text for s in SANITIZATION_INDICATORS):
                    is_sanitized = True

            if not is_sanitized:
                context_line = lines[call_line - 1] if call_line <= len(lines) else ""
                findings.append(
                    {
                        "file": file_path,
                        "line": call_line,
                        "name": "vectordb_metadata_poisoning_risk",
                        "severity": "MEDIUM",
                        "message": "Vector DB ingestion passes untrusted external metadata without sanitization (±15 line window)",
                        "context": context_line.strip()[:120],
                    }
                )

        return findings

    def _scan_vectordb_regex(
        self, file_path: str, lines: List[str]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for idx, line in enumerate(lines):
            line_num = idx + 1

            if CALL_REGEX.search(line):
                # Extract call text forward up to 25 lines or balanced parentheses
                paren_depth = 0
                found_open = False
                call_end_idx = idx
                is_call_suppressed = _is_rule_suppressed(
                    line, "vectordb_metadata_poisoning_risk", allow_bare=True
                )

                for j in range(idx, min(len(lines), idx + 25)):
                    curr_line = lines[j]
                    if _is_rule_suppressed(
                        curr_line, "vectordb_metadata_poisoning_risk", allow_bare=True
                    ):
                        is_call_suppressed = True
                    for ch in curr_line:
                        if ch == "(":
                            paren_depth += 1
                            found_open = True
                        elif ch == ")":
                            paren_depth -= 1
                            if found_open and paren_depth <= 0:
                                call_end_idx = j
                                break
                    if found_open and paren_depth <= 0:
                        break
                else:
                    call_end_idx = min(len(lines) - 1, idx + 20)

                if is_call_suppressed:
                    continue

                call_text = "\n".join(lines[idx : call_end_idx + 1]).lower()

                has_target_param = bool(
                    re.search(
                        r"\b(?:metadata|metadatas|points|vectors)\b", call_text
                    )
                )
                has_untrusted = any(u in call_text for u in UNTRUSTED_INDICATORS)

                if has_target_param and has_untrusted:
                    # Check window ±15 lines for sanitization
                    win_start = max(0, idx - 15)
                    win_end = min(len(lines), idx + 16)
                    win_text = "\n".join(lines[win_start:win_end]).lower()

                    if not any(s in win_text for s in SANITIZATION_INDICATORS):
                        findings.append(
                            {
                                "file": file_path,
                                "line": line_num,
                                "name": "vectordb_metadata_poisoning_risk",
                                "severity": "MEDIUM",
                                "message": "Vector DB ingestion passes untrusted external metadata without sanitization (±15 line window)",
                                "context": line.strip()[:120],
                            }
                        )

        return findings
