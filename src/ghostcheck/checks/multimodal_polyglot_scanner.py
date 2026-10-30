import os
import re
import struct
import zlib
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from ..interfaces import BaseScannerPlugin

logger = logging.getLogger(__name__)

# Extensions targeted for magic-byte spoofing & polyglot mismatch
IMAGE_DOC_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf'}
TEXT_EXTENSIONS = {'.txt', '.md', '.csv'}
ALL_MAGIC_TARGET_EXTENSIONS = IMAGE_DOC_EXTENSIONS | TEXT_EXTENSIONS
BINARY_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

# Shared Prompt Injection detection patterns
INJECTION_PATTERNS = [
    re.compile(r'(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b'),
    re.compile(r'(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b'),
    re.compile(r'(?i)\bsystem\s*(?:prompt\s*)?override\b'),
    re.compile(r'(?i)<\|im_start\|>\s*system'),
    re.compile(r'(?i)\[system\s*override\]'),
    re.compile(r'(?i)\b(?:curl|wget)\s+https?://\S+'),
    re.compile(r'(?i)\bexfiltrate\s+(?:secrets|env|keys|credentials|tokens)\b'),
]

ZERO_WIDTH_RE = re.compile(r'[\u200b-\u200f\u202a-\u202e\ufeff]')
AGENT_KEYWORD_RE = re.compile(r'(?i)\b(?:ignore|execute|system|override)\b')

# SVG hidden text attributes & styles
SVG_HIDDEN_ATTR_RE = re.compile(
    r'(?:'
    r'font-size\s*[:=]\s*["\']?0(?:px|pt|em|rem|%)?["\']?|'
    r'(?:fill-)?opacity\s*[:=]\s*["\']?0(?:\.0+)?["\']?|'
    r'display\s*:\s*none|'
    r'visibility\s*:\s*hidden'
    r')',
    re.IGNORECASE
)

# Sensitive commands / directives inside SVG hidden elements
SVG_HIDDEN_COMMAND_RE = re.compile(
    r'(?i)\b(?:ignore|system|override|execute|exfiltrate)\b|\.env\b|id_rsa\b|~/\.ssh\b'
)

# Specific ignore directive to prevent untrusted self-suppression
SVG_IGNORE_DIRECTIVE = 'ghostcheck-ignore: multimodal_svg_hidden_injection'

# PNG multi-chunk limits
MAX_PNG_CHUNKS = 1024
MAX_TOTAL_DECOMPRESSED = 512 * 1024  # 512 KB cumulative


def _detect_prompt_injection(text: str) -> Optional[str]:
    """
    Checks decoded text for known prompt injection directives or zero-width evasion.
    Returns matched substring or description, or None if clean.
    """
    if not text:
        return None

    # 1. Direct regex match
    for pat in INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)

    # 2. Zero-width / bidi character detection combined with agent keywords
    if ZERO_WIDTH_RE.search(text):
        kw_match = AGENT_KEYWORD_RE.search(text)
        if kw_match:
            return f"zero-width/bidi with keyword '{kw_match.group(0)}'"
        # Check if stripping zero-width reveals an injection payload
        cleaned = ZERO_WIDTH_RE.sub('', text)
        for pat in INJECTION_PATTERNS:
            m = pat.search(cleaned)
            if m:
                return f"zero-width hidden payload: {m.group(0)}"

    return None


def _approx_line(content: str, text: str) -> int:
    """Finds approximate 1-based line number for a text snippet in content."""
    stripped = text.strip()
    if stripped:
        pos = content.find(stripped)
        if pos != -1:
            return content[:pos].count('\n') + 1
    return 1


class MultimodalPolyglotScanner(BaseScannerPlugin):
    """
    Detects polyglot magic-byte file spoofing and hidden prompt injections
    in image/SVG multimodal assets.
    """

    supports_binary: bool = True

    @property
    def name(self) -> str:
        return "multimodal_polyglot_scanner"

    @property
    def description(self) -> str:
        return "Detects polyglot magic-byte file spoofing and hidden prompt injections in image/SVG multimodal assets."

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for file_path in files:
            try:
                if not os.path.isfile(file_path):
                    continue
                file_size = os.path.getsize(file_path)
                if file_size == 0:
                    continue
            except OSError as e:
                logger.debug("Failed checking file stats for %s: %s", file_path, e)
                continue

            ext = os.path.splitext(file_path)[1].lower()

            # Dispatch based on extension
            if ext == '.svg':
                findings.extend(self._scan_svg(file_path))
            elif ext in ALL_MAGIC_TARGET_EXTENSIONS:
                findings.extend(self._scan_binary_and_metadata(file_path, ext))

        return findings

    def _scan_binary_and_metadata(self, file_path: str, ext: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        try:
            with open(file_path, 'rb') as f:
                data = f.read(2 * 1024 * 1024)
        except OSError as e:
            logger.debug("Failed opening binary file %s: %s", file_path, e)
            return findings

        if not data:
            return findings

        header = data[:65536]

        # -------------------------------------------------------------
        # AC-2 Check 1: Magic-Byte Spoofing & Polyglot Mismatch
        # -------------------------------------------------------------
        polyglot_mismatch = False

        # a) ELF executable header on any target extension
        if header.startswith(b'\x7fELF'):
            polyglot_mismatch = True
            findings.append({
                "file": file_path,
                "line": 1,
                "name": "polyglot_magic_byte_mismatch",
                "severity": "CRITICAL",
                "message": f"File with extension '{ext}' has ELF executable magic bytes (potential polyglot spoofing).",
                "context": f"ELF header: {header[:16]!r}"[:120],
            })

        # b) Windows PE executable header check
        elif header.startswith(b'MZ'):
            is_pe = False
            if len(header) >= 0x40:
                try:
                    pe_off = struct.unpack('<I', header[0x3C:0x40])[0]
                    if 0 < pe_off <= len(header) - 4 and header[pe_off:pe_off+4] == b'PE\x00\x00':
                        is_pe = True
                except struct.error as e:
                    logger.debug("PE offset unpack failed for %s: %s", file_path, e)

            if not is_pe and ext in BINARY_IMAGE_EXTENSIONS and header.startswith(b'MZ\x90\x00'):
                is_pe = True

            if is_pe:
                polyglot_mismatch = True
                findings.append({
                    "file": file_path,
                    "line": 1,
                    "name": "polyglot_magic_byte_mismatch",
                    "severity": "CRITICAL",
                    "message": f"File with extension '{ext}' has Windows PE executable header (potential polyglot spoofing).",
                    "context": f"PE header: {header[:16]!r}"[:120],
                })

        # c) Shebang or ZIP masquerading as an image
        elif ext in BINARY_IMAGE_EXTENSIONS and (header.startswith(b'#!') or header.startswith(b'PK\x03\x04')):
            polyglot_mismatch = True
            sig_type = "Shebang script" if header.startswith(b'#!') else "ZIP/JAR archive"
            findings.append({
                "file": file_path,
                "line": 1,
                "name": "polyglot_magic_byte_mismatch",
                "severity": "CRITICAL",
                "message": f"Image file '{ext}' has {sig_type} header magic bytes (potential polyglot spoofing).",
                "context": f"Header bytes: {header[:16]!r}"[:120],
            })

        # d) True image with appended polyglot
        if not polyglot_mismatch:
            # PNG trailer check
            if data.startswith(b'\x89PNG\r\n\x1a\n'):
                iend_needle = b'IEND\xaeB`\x82'
                idx = data.rfind(iend_needle)
                if idx != -1:
                    trailing = data[idx + len(iend_needle):]
                else:
                    iend_pos = data.rfind(b'IEND')
                    trailing = data[iend_pos + 8:] if (iend_pos != -1 and iend_pos + 8 <= len(data)) else b''

                if any(sig in trailing for sig in (b'PK\x03\x04', b'\x7fELF', b'#!/bin/')):
                    findings.append({
                        "file": file_path,
                        "line": 1,
                        "name": "polyglot_magic_byte_mismatch",
                        "severity": "CRITICAL",
                        "message": "Valid PNG image contains appended executable or archive polyglot after IEND trailer.",
                        "context": f"Appended trailer: {trailing[:32]!r}"[:120],
                    })

            # JPEG trailer check
            elif data.startswith(b'\xff\xd8'):
                eoi_pos = data.rfind(b'\xff\xd9')
                if eoi_pos != -1:
                    trailing = data[eoi_pos + 2:]
                    if any(sig in trailing for sig in (b'PK\x03\x04', b'\x7fELF', b'#!/bin/')):
                        findings.append({
                            "file": file_path,
                            "line": 1,
                            "name": "polyglot_magic_byte_mismatch",
                            "severity": "CRITICAL",
                            "message": "Valid JPEG image contains appended executable or archive polyglot after EOI marker.",
                            "context": f"Appended trailer: {trailing[:32]!r}"[:120],
                        })

        # -------------------------------------------------------------
        # AC-2 Check 2: PNG & JPEG Vision Metadata Prompt Injection
        # -------------------------------------------------------------
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            findings.extend(self._scan_png_chunks(file_path, data))
        elif data.startswith(b'\xff\xd8'):
            findings.extend(self._scan_jpeg_segments(file_path, data))

        return findings

    def _scan_png_chunks(self, file_path: str, data: bytes) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        offset = 8
        total_len = len(data)
        chunk_count = 0
        total_decompressed = 0

        while offset + 8 <= total_len:
            chunk_count += 1
            if chunk_count > MAX_PNG_CHUNKS:
                logger.debug("PNG chunk limit (%d) exceeded in %s", MAX_PNG_CHUNKS, file_path)
                break

            try:
                length, chunk_type = struct.unpack('>I4s', data[offset:offset+8])
            except struct.error as e:
                logger.debug("Failed unpacking PNG chunk at %d in %s: %s", offset, file_path, e)
                break

            if offset + 12 + length > total_len:
                logger.debug("Corrupt PNG chunk length %d exceeds file length at %d in %s", length, offset, file_path)
                break

            chunk_data = data[offset+8 : offset+8+length]
            extracted_text: Optional[str] = None

            if chunk_type == b'tEXt':
                extracted_text = chunk_data.replace(b'\x00', b': ').decode('utf-8', errors='ignore')

            elif chunk_type == b'zTXt':
                parts = chunk_data.split(b'\x00', 1)
                if len(parts) == 2:
                    keyword = parts[0].decode('latin-1', errors='ignore')
                    rest = parts[1]
                    if len(rest) >= 2 and rest[0] == 0:
                        remaining_budget = max(0, MAX_TOTAL_DECOMPRESSED - total_decompressed)
                        if remaining_budget == 0:
                            logger.debug("PNG decompression budget (%d) exhausted in %s", MAX_TOTAL_DECOMPRESSED, file_path)
                            break
                        try:
                            decomp_cap = min(65536, remaining_budget)
                            decomp = zlib.decompressobj().decompress(rest[1:], decomp_cap)
                            total_decompressed += len(decomp)
                            text = decomp.decode('utf-8', errors='ignore')
                            extracted_text = f"{keyword}: {text}"
                        except Exception as e:
                            logger.debug("zTXt decompression failed in %s: %s", file_path, e)

            elif chunk_type == b'iTXt':
                try:
                    null1 = chunk_data.find(b'\x00')
                    if null1 != -1 and null1 + 3 <= len(chunk_data):
                        keyword = chunk_data[:null1].decode('utf-8', errors='ignore')
                        comp_flag = chunk_data[null1 + 1]
                        # comp_method = chunk_data[null1 + 2]
                        null2 = chunk_data.find(b'\x00', null1 + 3)
                        if null2 != -1:
                            null3 = chunk_data.find(b'\x00', null2 + 1)
                            if null3 != -1:
                                trans_kw = chunk_data[null2 + 1 : null3].decode('utf-8', errors='ignore')
                                raw_text = chunk_data[null3 + 1:]
                                if comp_flag == 1:
                                    remaining_budget = max(0, MAX_TOTAL_DECOMPRESSED - total_decompressed)
                                    if remaining_budget == 0:
                                        logger.debug("PNG decompression budget (%d) exhausted in %s", MAX_TOTAL_DECOMPRESSED, file_path)
                                        break
                                    try:
                                        decomp_cap = min(65536, remaining_budget)
                                        decomp = zlib.decompressobj().decompress(raw_text, decomp_cap)
                                        total_decompressed += len(decomp)
                                        text = decomp.decode('utf-8', errors='ignore')
                                    except Exception as e:
                                        logger.debug("iTXt decompression failed in %s: %s", file_path, e)
                                        text = ""
                                else:
                                    text = raw_text.decode('utf-8', errors='ignore')
                                extracted_text = f"{keyword} {trans_kw}: {text}"
                except Exception as e:
                    logger.debug("iTXt parsing failed in %s: %s", file_path, e)

            if extracted_text:
                match_snip = _detect_prompt_injection(extracted_text)
                if match_snip:
                    chunk_name = chunk_type.decode('ascii', errors='ignore')
                    findings.append({
                        "file": file_path,
                        "line": 1,
                        "name": "multimodal_metadata_injection",
                        "severity": "CRITICAL",
                        "message": f"Detected prompt injection inside PNG {chunk_name} chunk: {match_snip}",
                        "context": extracted_text.strip()[:120],
                    })

            if chunk_type == b'IEND':
                break

            offset += 12 + length

        return findings

    def _scan_jpeg_segments(self, file_path: str, data: bytes) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        pos = 2
        total_len = len(data)

        while pos < total_len:
            # Skip padding 0xFF bytes
            while pos < total_len and data[pos] == 0xFF:
                pos += 1
            if pos >= total_len:
                break

            marker = data[pos]
            pos += 1

            # Stop walking at SOS (0xDA) or EOI (0xD9)
            if marker in (0xDA, 0xD9):
                break

            # Standalone markers without length: RST0-RST7 (0xD0-0xD7) or TEM (0x01)
            if (0xD0 <= marker <= 0xD7) or marker == 0x01:
                continue

            if pos + 2 > total_len:
                logger.debug("JPEG segment truncated before length at %d in %s", pos, file_path)
                break

            try:
                seg_len = struct.unpack('>H', data[pos:pos+2])[0]
            except struct.error as e:
                logger.debug("JPEG segment length unpack failed at %d in %s: %s", pos, file_path, e)
                break

            if seg_len < 2 or pos + seg_len > total_len:
                logger.debug("JPEG segment length invalid (%d) at %d in %s", seg_len, pos, file_path)
                break

            seg_data = data[pos+2 : pos+seg_len]
            pos += seg_len

            # Check COM (0xFE) and APP1 (0xE1) segments
            if marker in (0xFE, 0xE1):
                text = seg_data.decode('utf-8', errors='ignore')
                match_snip = _detect_prompt_injection(text)
                if match_snip:
                    marker_name = "COM" if marker == 0xFE else "APP1"
                    findings.append({
                        "file": file_path,
                        "line": 1,
                        "name": "multimodal_metadata_injection",
                        "severity": "CRITICAL",
                        "message": f"Detected prompt injection inside JPEG {marker_name} segment: {match_snip}",
                        "context": text.strip()[:120],
                    })

        return findings

    # -----------------------------------------------------------------
    # AC-2 Check 3: SVG Hidden Prompt Injection
    # -----------------------------------------------------------------
    def _scan_svg(self, file_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2 * 1024 * 1024)
        except OSError as e:
            logger.debug("Failed opening SVG file %s: %s", file_path, e)
            return findings

        if not content:
            return findings

        # 1. Linear O(N) scan for XML comments <!-- ... -->
        comment_idx = 0
        content_len = len(content)
        while comment_idx < content_len:
            start = content.find('<!--', comment_idx)
            if start == -1:
                break
            end = content.find('-->', start + 4)
            if end == -1:
                break
            comment_body = content[start + 4 : end]
            # Red Team Fix: Only skip if explicit rule directive is present
            if SVG_IGNORE_DIRECTIVE not in comment_body:
                snip = _detect_prompt_injection(comment_body)
                if snip:
                    line_no = content[:start].count('\n') + 1
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "name": "multimodal_svg_hidden_injection",
                        "severity": "HIGH",
                        "message": f"Detected prompt injection inside SVG XML comment: {snip}",
                        "context": comment_body.strip()[:120],
                    })
            comment_idx = end + 3

        # 2. Element parsing via ElementTree with inheritance + safe O(N) fallback
        reported: set = set()

        # Guard against XML entity expansion / billion laughs
        if '<!ENTITY' in content:
            logger.debug("SVG in %s contains <!ENTITY; using safe bounded fallback", file_path)
            self._scan_svg_fallback(file_path, content, findings, reported)
            return findings

        # Strip <!DOCTYPE ...> before ET.fromstring
        clean_xml = content
        dt_start = clean_xml.find('<!DOCTYPE')
        if dt_start != -1:
            dt_bracket = clean_xml.find('[', dt_start)
            dt_end = clean_xml.find('>', dt_start)
            if dt_bracket != -1 and dt_bracket < dt_end:
                dt_bracket_end = clean_xml.find(']>', dt_bracket)
                if dt_bracket_end != -1:
                    clean_xml = clean_xml[:dt_start] + clean_xml[dt_bracket_end + 2:]
                else:
                    clean_xml = clean_xml[:dt_start]
            elif dt_end != -1:
                clean_xml = clean_xml[:dt_start] + clean_xml[dt_end + 1:]

        try:
            raw_lines = content.splitlines()
            root = ET.fromstring(clean_xml)
            self._traverse_svg_element(file_path, root, content, raw_lines, inherited_hidden=False, findings=findings, reported=reported)
        except ET.ParseError as e:
            logger.debug("SVG XML parse error in %s: %s; using safe bounded fallback", file_path, e)
            self._scan_svg_fallback(file_path, content, findings, reported)
        except Exception as e:
            logger.debug("Unexpected error parsing SVG XML in %s: %s; using safe bounded fallback", file_path, e)
            self._scan_svg_fallback(file_path, content, findings, reported)

        return findings

    def _traverse_svg_element(
        self,
        file_path: str,
        elem: Any,
        content: str,
        raw_lines: List[str],
        inherited_hidden: bool,
        findings: List[Dict[str, Any]],
        reported: set
    ) -> None:
        tag = elem.tag
        local_tag = tag.split('}')[-1].lower() if isinstance(tag, str) else ''

        # Hidden check on current element attributes
        is_hidden_self = False
        if elem.attrib:
            # Check style
            style_val = elem.attrib.get('style', '')
            if style_val and SVG_HIDDEN_ATTR_RE.search(style_val):
                is_hidden_self = True
            if not is_hidden_self:
                for k in ('font-size', 'opacity', 'fill-opacity', 'display', 'visibility'):
                    if k in elem.attrib:
                        pair = f"{k}={elem.attrib[k]}"
                        if SVG_HIDDEN_ATTR_RE.search(pair):
                            is_hidden_self = True
                            break

        is_hidden = inherited_hidden or is_hidden_self

        # Check explicit rule-scoped suppression (bare ghostcheck-ignore is NOT honored)
        elem_text = elem.text or ""
        is_ignored = (SVG_IGNORE_DIRECTIVE in elem_text.lower()) or any(SVG_IGNORE_DIRECTIVE in str(v).lower() for v in elem.attrib.values())

        if not is_ignored:
            if local_tag in ('desc', 'title'):
                full_desc = "".join(elem.itertext()).strip()
                if full_desc and (SVG_IGNORE_DIRECTIVE not in full_desc.lower()):
                    snip = _detect_prompt_injection(full_desc)
                    if snip:
                        line_no = _approx_line(content, full_desc)
                        raw_line = raw_lines[line_no - 1] if 1 <= line_no <= len(raw_lines) else ""
                        if SVG_IGNORE_DIRECTIVE not in raw_line.lower():
                            rep_key = (line_no, local_tag, snip)
                            if rep_key not in reported:
                                reported.add(rep_key)
                                findings.append({
                                    "file": file_path,
                                    "line": line_no,
                                    "name": "multimodal_svg_hidden_injection",
                                    "severity": "HIGH",
                                    "message": f"Detected prompt injection inside SVG <{local_tag}> metadata: {snip}",
                                    "context": full_desc[:120],
                                })

            elif local_tag in ('text', 'tspan') and is_hidden:
                # Text for this element specifically
                direct_text = (elem.text or "").strip()
                if direct_text and (SVG_IGNORE_DIRECTIVE not in direct_text.lower()):
                    snip = _detect_prompt_injection(direct_text)
                    cmd_match = SVG_HIDDEN_COMMAND_RE.search(direct_text)
                    if snip or cmd_match:
                        line_no = _approx_line(content, direct_text)
                        raw_line = raw_lines[line_no - 1] if 1 <= line_no <= len(raw_lines) else ""
                        if SVG_IGNORE_DIRECTIVE not in raw_line.lower():
                            reason = snip if snip else cmd_match.group(0)
                            rep_key = (line_no, local_tag, reason)
                            if rep_key not in reported:
                                reported.add(rep_key)
                                findings.append({
                                    "file": file_path,
                                    "line": line_no,
                                    "name": "multimodal_svg_hidden_injection",
                                    "severity": "HIGH",
                                    "message": f"Detected prompt injection or sensitive command in visually hidden SVG element: {reason}",
                                    "context": direct_text[:120],
                                })

        # Recursively traverse children with inherited hidden status
        for child in elem:
            self._traverse_svg_element(file_path, child, content, raw_lines, inherited_hidden=is_hidden, findings=findings, reported=reported)

    def _scan_svg_fallback(
        self,
        file_path: str,
        content: str,
        findings: List[Dict[str, Any]],
        reported: set
    ) -> None:
        """
        Bounded, safe O(N) fallback scanner for malformed or entity-bearing SVGs.
        Uses str.find loops without quadratic regex backtracking.
        """
        content_lower = content.lower()
        content_len = len(content)

        # 1. Scan <desc> and <title>
        for tag in ('desc', 'title'):
            open_tag = f'<{tag}'
            close_tag = f'</{tag}>'
            pos = 0
            while pos < content_len:
                start = content_lower.find(open_tag, pos)
                if start == -1:
                    break
                tag_close = content.find('>', start + len(open_tag))
                if tag_close == -1:
                    break
                end = content_lower.find(close_tag, tag_close + 1)
                if end == -1:
                    break
                tag_text = content[tag_close + 1 : end].strip()
                if tag_text and SVG_IGNORE_DIRECTIVE not in tag_text:
                    snip = _detect_prompt_injection(tag_text)
                    if snip:
                        line_no = content[:start].count('\n') + 1
                        rep_key = (line_no, tag, snip)
                        if rep_key not in reported:
                            reported.add(rep_key)
                            findings.append({
                                "file": file_path,
                                "line": line_no,
                                "name": "multimodal_svg_hidden_injection",
                                "severity": "HIGH",
                                "message": f"Detected prompt injection inside SVG <{tag}> metadata: {snip}",
                                "context": tag_text[:120],
                            })
                pos = end + len(close_tag)

        # 2. Scan <text> and <tspan>
        for tag in ('text', 'tspan'):
            open_tag = f'<{tag}'
            pos = 0
            while pos < content_len:
                start = content_lower.find(open_tag, pos)
                if start == -1:
                    break
                next_char_idx = start + len(open_tag)
                if next_char_idx < content_len and content[next_char_idx] in (' ', '\t', '\n', '\r', '>'):
                    tag_close = content.find('>', next_char_idx)
                    if tag_close == -1:
                        break
                    attrs = content[next_char_idx:tag_close]
                    is_hidden = bool(SVG_HIDDEN_ATTR_RE.search(attrs))
                    next_tag = content.find('<', tag_close + 1)
                    text_end = next_tag if next_tag != -1 else content_len
                    elem_text = content[tag_close + 1 : text_end].strip()

                    if is_hidden and elem_text and (SVG_IGNORE_DIRECTIVE not in elem_text):
                        snip = _detect_prompt_injection(elem_text)
                        cmd_match = SVG_HIDDEN_COMMAND_RE.search(elem_text)
                        if snip or cmd_match:
                            line_no = content[:start].count('\n') + 1
                            reason = snip if snip else cmd_match.group(0)
                            rep_key = (line_no, tag, reason)
                            if rep_key not in reported:
                                reported.add(rep_key)
                                findings.append({
                                    "file": file_path,
                                    "line": line_no,
                                    "name": "multimodal_svg_hidden_injection",
                                    "severity": "HIGH",
                                    "message": f"Detected prompt injection or sensitive command in visually hidden SVG element: {reason}",
                                    "context": elem_text[:120],
                                })
                    pos = tag_close + 1
                else:
                    pos = next_char_idx
