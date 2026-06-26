import pytest
import os
import sys
import concurrent.futures
from unittest.mock import MagicMock
from ghostcheck.checks.data_exfiltration_detector import DataExfiltrationDetector, calculate_entropy, has_high_entropy_token

# Helper to write files and scan them
def run_scan(detector, tmp_path, filename, content):
    f = tmp_path / filename
    f.write_text(content, encoding="utf-8")
    return detector.scan([str(f)], None)


def test_alias_taint_tracking(tmp_path):
    # AC1: Alias Taint Tracking
    code = """
import os
import openai

env = os.environ
secret = env.get("API_KEY")
openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": secret}]
)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_alias.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_concat_folding(tmp_path):
    # AC1: Constant Folding on String Concatenation
    code = """
import os
import openai

key_parts = "SEC" + "RET" + "_KEY"
secret_key = os.getenv(key_parts)
openai.chat.completions.create(
    model="gpt-4",
    prompt="Here is my secret: " + secret_key
)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_concat.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)



def test_custom_wrapper(tmp_path):
    # AC1: Custom Wrapper Signature Harvesting
    code = """
import os
import openai

def query_llm(user_prompt):
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_prompt}]
    )

query_llm(os.environ.get("AWS_SECRET_ACCESS_KEY"))
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_wrapper.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_mcp_dynamic_register(tmp_path):
    # AC2: MCP Tool File Exfiltration with dynamic tool registration
    code = """
import mcp

def read_credentials():
    with open("~/.aws/credentials", "r") as f:
        data = f.read()
    return data

mcp.tool()(read_credentials)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_mcp_dynamic.py", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_pathlib_read(tmp_path):
    # AC2: MCP Tool using pathlib.Path read
    code = """
from mcp import FastMCP
from pathlib import Path

mcp = FastMCP("SecureServer")

@mcp.tool()
def get_env_file():
    p = Path(".env")
    return p.read_text()
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_pathlib.py", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_symlink_bypass(tmp_path):
    # AC2/AC3: Symlink creation involving sensitive path or public folder
    code = """
import os

os.symlink(".env", "public/sym_env.txt")
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_symlink.py", code)
    assert any("Symlink Creation Guard" in f["name"] for f in findings)


def test_traversal_path_write(tmp_path):
    # AC3: Public folder write via traversal path
    code = """
import os

secret = os.getenv("DB_PASSWORD")
with open("static/../public/leak.txt", "w") as f:
    f.write(secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_traversal.py", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_python_ast_syntax_error_fallback(tmp_path):
    # Fallback: Python syntax error should fallback to text scan
    code = """
# This is a syntax error
def class while 1:

os.environ.get("MY_SECRET")
openai.chat.completions.create(prompt=os.environ.get("MY_SECRET"))
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_syntax_error.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_esprima_missing_fallback(tmp_path, monkeypatch):
    # Fallback: esprima is missing, fall back to text scan
    # Mock esprima as None
    import ghostcheck.checks.data_exfiltration_detector as ded
    monkeypatch.setattr(ded, "esprima", None)

    code = """
const secret = process.env.SECRET_KEY;
completions.create({
    prompt: secret
});
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_esprima_missing.js", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_typescript_syntax_error_fallback(tmp_path):
    # Fallback: TS syntax causes esprima exception, fallback to text scan
    code = """
interface Config {
    apiKey: string;
}

const conf: Config = { apiKey: process.env.API_KEY };
completions.create({
    prompt: conf.apiKey
});
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_ts_syntax.ts", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_entropy_mathematical_limits(tmp_path):
    # Entropy limits: L <= 22 cannot exceed 4.5
    # A string of length 22 with unique characters
    short_str = "abcdefghijklmnopqrstuv"
    # A string of length 24 with unique characters
    long_str = "abcdefghijklmnopqrstuvwx"

    assert len(short_str) == 22
    assert len(long_str) == 24

    assert not has_high_entropy_token(short_str)
    assert has_high_entropy_token(long_str)

    # Test that short string in prompt is ignored, but long string triggers it
    detector = DataExfiltrationDetector()
    
    code_short = f'openai.chat.completions.create(prompt="{short_str}")'
    findings_short = run_scan(detector, tmp_path, "test_short.py", code_short)
    assert not any("LLM Prompt Leakage" in f["name"] for f in findings_short)

    code_long = f'openai.chat.completions.create(prompt="{long_str}")'
    findings_long = run_scan(detector, tmp_path, "test_long.py", code_long)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_long)


def test_entropy_non_ascii_natural_language(tmp_path):
    # Non-ASCII Chinese text should not trigger high entropy leaks
    chinese_text = "這是一個非常正常的中文測試段落，用來驗證會不會因為漢字字數多而誤判為高熵金鑰。"
    detector = DataExfiltrationDetector()
    
    code = f'openai.chat.completions.create(prompt="{chinese_text}")'
    findings = run_scan(detector, tmp_path, "test_chinese.py", code)
    assert not any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_windows_path_normalization(tmp_path):
    # Windows paths with backslashes normalisation
    code = """
import os
secret = os.getenv("API_KEY")
with open("C:\\\\project\\\\public\\\\secrets.txt", "w") as f:
    f.write(secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_windows.py", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_thread_safety_stress(tmp_path):
    # Stress test: scan 50 files concurrently
    detector = DataExfiltrationDetector()
    files = []
    
    # Create 25 safe files and 25 unsafe files
    for i in range(25):
        safe_f = tmp_path / f"safe_{i}.py"
        safe_f.write_text("print('hello')", encoding="utf-8")
        files.append(str(safe_f))
        
        unsafe_f = tmp_path / f"unsafe_{i}.py"
        unsafe_f.write_text("import os; completions.create(prompt=os.environ.get('KEY'))", encoding="utf-8")
        files.append(str(unsafe_f))

    # Run scan across multiple threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(detector.scan, [f], None) for f in files]
        all_findings = []
        for fut in concurrent.futures.as_completed(futures):
            all_findings.extend(fut.result())

    # We should have exactly 25 findings (1 for each unsafe file)
    assert len(all_findings) == 25
    for f in all_findings:
        assert "unsafe_" in f["file"]


def test_mock_pollution_isolation(tmp_path, monkeypatch):
    # Check that esprima mock does not leak out of its test
    import ghostcheck.checks.data_exfiltration_detector as ded
    assert ded.esprima is not None  # originally imported successfully
    
    # Mock it in a test
    monkeypatch.setattr(ded, "esprima", None)
    assert ded.esprima is None
    
    # Wait, after monkeypatch context exits, it must be restored
    # We will let this test run, and the next test will verify that it is restored.


def test_js_ast_exfiltration(tmp_path):
    # Valid JS AST exfiltration test
    code = """
    const secret = process.env.API_KEY;
    completions.create({
        prompt: secret
    });
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_ast.js", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_js_ast_mcp_leak(tmp_path):
    # Valid JS AST MCP leak test
    code = """
    const mcp = require('mcp');
    function get_key() {
        const data = fs.readFileSync('.env', 'utf-8');
        return data;
    }
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_mcp.js", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_js_ast_public_write(tmp_path):
    # Valid JS AST public directory write test
    code = """
    const secret = process.env.DB_PASSWORD;
    fs.writeFileSync('public/config.json', secret);
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_write.js", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_mcp_complex_expression(tmp_path):
    # Python MCP tool returning complex expression containing sensitive read
    code = """
import mcp

@mcp.tool()
async def get_credentials():
    data = open(".env").read()
    return "prefix: " + data
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_mcp_complex.py", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_async_wrapper_harvester(tmp_path):
    # Cover visit_AsyncFunctionDef in harvester and visitor
    code = """
import os

async def custom_prompt_call(prompt_val):
    return await completions.create(prompt=prompt_val)

async def test_run():
    await custom_prompt_call(os.environ.get("SECRET"))
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_async_wrapper.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_pathlib_public_write(tmp_path):
    # Cover pathlib write to public directory
    code = """
from pathlib import Path
import os
secret = os.getenv("API_KEY")
Path("public/keys.txt").write_text(secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_pathlib_write.py", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_shutil_copy(tmp_path):
    # Cover shutil copy of sensitive files to public folder
    code = """
import shutil
shutil.copy(".env", "public/.env")
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_shutil.py", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_keyword_mode_write(tmp_path):
    # Cover open mode keyword arguments
    code = """
import os
secret = os.getenv("API_KEY")
with open("public/leak.txt", mode="w") as f:
    f.write(secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_kw_mode.py", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_mcp_complex_expression_direct(tmp_path):
    # Python MCP tool returning complex expression containing sensitive read directly (covers MCPTaintChecker visit_Call)
    code = """
import mcp

@mcp.tool()
async def get_credentials():
    return "prefix: " + open(".env").read()
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_mcp_complex_direct.py", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_tuple_unpacking(tmp_path):
    # Cover target unpacking (tuple/list) in Python assignment
    code = """
import os
secret, normal = os.getenv("API_KEY"), "hello"
openai.chat.completions.create(prompt=secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_tuple.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_env_direct_reference(tmp_path):
    # Cover direct os.environ / os.getenv / sensitive name references in TaintChecker
    # Case 1: from os import environ
    code_1 = """
from os import environ
openai.chat.completions.create(prompt=environ["API_KEY"])
"""
    # Case 2: os.environ attribute directly
    code_2 = """
import os
openai.chat.completions.create(prompt=os.environ["API_KEY"])
"""
    # Case 3: sensitive variable directly (free variable)
    code_3 = """
openai.chat.completions.create(prompt=api_key)
"""
    detector = DataExfiltrationDetector()
    
    findings_1 = run_scan(detector, tmp_path, "test_direct_1.py", code_1)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_1)

    findings_2 = run_scan(detector, tmp_path, "test_direct_2.py", code_2)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_2)

    findings_3 = run_scan(detector, tmp_path, "test_direct_3.py", code_3)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_3)


def test_assign_public_write(tmp_path):
    # Cover open public write handle assignment
    code = """
import os
secret = os.getenv("API_KEY")
f = open("public/leak.txt", "w")
f.write(secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_assign_write.py", code)
    assert any("Public Output Leakage" in f["name"] for f in findings)


def test_assign_high_entropy(tmp_path):
    # Cover high entropy assignment in visit_Assign
    code = """
my_secret = "abcdefghijklmnopqrstuvwx" # len 24
openai.chat.completions.create(prompt=my_secret)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_assign_entropy.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)

def test_harmless_paths_ignored(tmp_path):
    # Verify that .env.example, .env.template, credentials.dist, and id_rsa.pub are ignored
    code = """
    import mcp
    from pathlib import Path

    @mcp.tool()
    def get_public_key():
        # Reading public key or config example should NOT trigger warnings
        p1 = Path("id_rsa.pub")
        p2 = Path(".env.example")
        p3 = Path(".env.template")
        p4 = Path("credentials.dist")
        return p1.read_text() + p2.read_text() + p3.read_text() + p4.read_text()
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_harmless.py", code)
    assert not any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_long_entropy_token(tmp_path):
    # Verify that a long key (>128 chars, e.g. 150 chars) is detected in text/entropy scan
    import random
    random.seed(42)
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    long_key = "".join(random.choice(chars) for _ in range(150))
    
    code = f"""
    openai.chat.completions.create(prompt="{long_key}")
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_long_key.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_text_scan_nested_parentheses_leak(tmp_path):
    # Verify that nested parenthesized calls in text scan do not cause early termination
    code = """
    # Syntax error to force text scan fallback
    class : InvalidSyntax
    
    openai.chat.completions.create(
        model=get_model_name("default"),
        messages=[{"role": "user", "content": os.environ.get("SECRET_KEY")}]
    )
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_nested.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_mcp_file_name_heuristic(tmp_path):
    # Verify that files named with 'mcp' trigger tool return leakage even without explicit import
    code = """
    def read_key():
        with open(".env", "r") as f:
            return f.read()
    """
    detector = DataExfiltrationDetector()
    # Name the file with 'mcp' in the filename
    findings = run_scan(detector, tmp_path, "my_mcp_tools.py", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_mcp_parameter_arbitrary_file_leak(tmp_path):
    # Case 1: Unvalidated dynamic parameter read
    code_unvalidated = """
import mcp

@mcp.tool()
def read_log(user_path: str):
    with open(user_path, "r") as f:
        return f.read()
"""
    # Case 2: Validated dynamic parameter read (should be ignored)
    code_validated = """
import mcp
from pathlib import Path

@mcp.tool()
def read_safe_log(user_path: str):
    p = Path(user_path).resolve()
    if not p.is_relative_to("/var/log"):
        raise ValueError("Invalid path")
    return open(p).read()
"""
    detector = DataExfiltrationDetector()
    findings_unval = run_scan(detector, tmp_path, "test_mcp_unval.py", code_unvalidated)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_unval)

    findings_val = run_scan(detector, tmp_path, "test_mcp_val.py", code_validated)
    assert not any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_val)


def test_metadata_ssrf_exfiltration(tmp_path):
    # Decimal IP exfiltration
    code_decimal = 'openai.chat.completions.create(prompt="http://2852039166/latest/meta-data/")'
    # Hex IP exfiltration
    code_hex = 'openai.chat.completions.create(prompt="http://0xa9fea9fe/latest/")'
    # Dotted Hex IP exfiltration
    code_dotted_hex = 'openai.chat.completions.create(prompt="http://0xA9.0xFE.0xA9.0xFE/")'
    # Dotted Octal IP exfiltration
    code_octal = 'openai.chat.completions.create(prompt="http://0251.0376.0251.0376/")'
    # IPv6 transition format
    code_ipv6 = 'openai.chat.completions.create(prompt="http://[::ffff:a9fe:a9fe]/")'
    # Azure WireServer IP
    code_azure = 'openai.chat.completions.create(prompt="http://168.63.129.16/metadata")'
    # Alibaba Cloud IP
    code_alibaba = 'openai.chat.completions.create(prompt="http://100.100.100.200/")'
    # Oracle Cloud IP
    code_oracle = 'openai.chat.completions.create(prompt="http://192.0.0.192/")'

    detector = DataExfiltrationDetector()

    for i, code in enumerate([code_decimal, code_hex, code_dotted_hex, code_octal, code_ipv6, code_azure, code_alibaba, code_oracle]):
        findings = run_scan(detector, tmp_path, f"test_ssrf_{i}.py", code)
        assert any("Metadata API SSRF Leakage" in f["name"] for f in findings), f"Failed for code: {code}"


def test_subscript_taint_propagation(tmp_path):
    # Key-level taint propagation
    code = """
import os
import openai

config = {
    "public_model": "gpt-4",
    "secret_key": os.environ.get("API_KEY")
}

# Accessing a safe key should NOT alert (no false positive)
openai.chat.completions.create(
    model=config["public_model"],
    prompt="hello"
)

# Accessing a tainted key MUST alert
openai.chat.completions.create(
    model="gpt-4",
    prompt=config["secret_key"]
)
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_subscript.py", code)
    leakage_findings = [f for f in findings if "LLM Prompt Leakage" in f["name"]]
    assert len(leakage_findings) == 1
    assert leakage_findings[0]["line"] == 17


def test_extra_metadata_ssrf_and_normalization(tmp_path):
    """
    Test additional metadata SSRF patterns and IP normalization logic.
    測試額外的雲端 Metadata SSRF 模式與 IP 正規化邏輯。
    """
    # 1. Test "metadata.google.internal" and "instance-data"
    # 測試 "metadata.google.internal" 與 "instance-data"
    code_meta_host = 'openai.chat.completions.create(prompt="http://metadata.google.internal/computeMetadata")'
    code_inst_data = 'openai.chat.completions.create(prompt="http://instance-data/latest/meta-data/")'

    # 2. Test IPv6 transition format like [::ffff:169.254.169.254]
    # 測試 IPv6 轉換格式，如 [::ffff:169.254.169.254]
    code_ipv6_transition = 'openai.chat.completions.create(prompt="http://[::ffff:169.254.169.254]/")'

    # 3. Test host with port: 169.254.169.254:80
    # 測試帶有連接埠的實例 IP：169.254.169.254:80
    code_host_port = 'openai.chat.completions.create(prompt="http://169.254.169.254:80/")'

    # 4. Test single octal host: 025177524776 (2852039166 in octal)
    # 測試單個八進制主機：025177524776 (即十進制 2852039166)
    code_octal_host = 'openai.chat.completions.create(prompt="http://025177524776/")'

    detector = DataExfiltrationDetector()

    for idx, code in enumerate([code_meta_host, code_inst_data, code_ipv6_transition, code_host_port, code_octal_host]):
        findings = run_scan(detector, tmp_path, f"test_extra_ssrf_{idx}.py", code)
        assert any("Metadata API SSRF Leakage" in f["name"] for f in findings), f"Failed for code: {code}"


def test_validation_scanner_path_compare(tmp_path):
    """
    Test Python ValidationScanner path comparison (e.g. ".." in path or ".." == path).
    測試 Python ValidationScanner 路徑比較邏輯（例如 ".." in path 或 ".." == path）。
    """
    code_unvalidated = """
import mcp

@mcp.tool()
def read_log(user_path: str):
    # No ".." check, should alert
    return open(user_path).read()
"""

    code_validated_1 = """
import mcp

@mcp.tool()
def read_log(user_path: str):
    if ".." in user_path:
        raise ValueError("Invalid path")
    return open(user_path).read()
"""

    code_validated_2 = """
import mcp

@mcp.tool()
def read_log(user_path: str):
    if user_path == "..":
        raise ValueError("Invalid path")
    return open(user_path).read()
"""

    detector = DataExfiltrationDetector()

    findings_unval = run_scan(detector, tmp_path, "test_val_unval.py", code_unvalidated)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_unval)

    findings_val1 = run_scan(detector, tmp_path, "test_val_val1.py", code_validated_1)
    assert not any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_val1)

    findings_val2 = run_scan(detector, tmp_path, "test_val_val2.py", code_validated_2)
    assert not any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_val2)


def test_unsupported_ast_nodes_resolve_name(tmp_path):
    """
    Test that _resolve_name and _resolve_expression gracefully handle unsupported AST nodes.
    測試 _resolve_name 與 _resolve_expression 能優雅處理不支援的 AST 節點。
    """
    from ghostcheck.checks.data_exfiltration_detector import PythonDataExfiltrationVisitor, JsDataExfiltrationVisitor
    
    # Python visitor test with unsupported nodes
    visitor = PythonDataExfiltrationVisitor("dummy.py", set(), {})
    # Pass None or non-AST node to trigger fallbacks
    assert visitor._resolve_name(None) == ""
    assert visitor._resolve_expression(None) is None
    
    # JS visitor test with unsupported nodes
    js_visitor = JsDataExfiltrationVisitor("dummy.js")
    assert js_visitor._resolve_expression(None) == ""


def test_subscript_and_attribute_assignment_taint(tmp_path):
    """
    Test key-level subscript assignments (e.g. config["secret_key"] = ...) and attribute assignments (cfg.secret_key = ...).
    測試鍵級下標賦值（如 config["secret_key"] = ...）與屬性賦值（如 cfg.secret_key = ...）的污點傳遞。
    """
    code_subscript = """
import os
import openai

config = {}
config["secret_key"] = os.environ.get("API_KEY")
openai.chat.completions.create(
    model="gpt-4",
    prompt=config["secret_key"]
)
"""

    code_attribute = """
import os
import openai

class Config:
    pass

cfg = Config()
cfg.secret_key = os.environ.get("API_KEY")
openai.chat.completions.create(
    model="gpt-4",
    prompt=cfg.secret_key
)
"""

    detector = DataExfiltrationDetector()

    findings_sub = run_scan(detector, tmp_path, "test_assign_sub.py", code_subscript)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_sub)

    findings_attr = run_scan(detector, tmp_path, "test_assign_attr.py", code_attribute)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_attr)


def test_mcp_unvalidated_params_direct_read(tmp_path):
    """
    Test direct file read patterns inside MCP tools such as path.read() or open(path).read().
    測試 MCP 工具中的直接檔案讀取模式，如 path.read() 或 open(path).read()。
    """
    code_path_read = """
import mcp

@mcp.tool()
def read_log(user_path: str):
    # Calling read() directly on parameter
    return user_path.read()
"""

    code_open_read = """
import mcp

@mcp.tool()
def read_log(user_path: str):
    # Calling open().read() directly
    return open(user_path).read()
"""

    detector = DataExfiltrationDetector()

    findings_path = run_scan(detector, tmp_path, "test_direct_path_read.py", code_path_read)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_path)

    findings_open = run_scan(detector, tmp_path, "test_direct_open_read.py", code_open_read)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_open)


def test_mcp_returns_metadata_ssrf(tmp_path):
    """
    Test MCP tool returning cloud metadata endpoint directly.
    測試 MCP 工具直接返回雲端 Metadata 端點的漏洞。
    """
    code = """
import mcp

@mcp.tool()
def get_cloud_info():
    return "169.254.169.254"
"""
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_mcp_ssrf.py", code)
    assert any("Metadata API SSRF Leakage" in f["name"] for f in findings)


def test_js_ast_identifier_constant_resolve_and_concatenation(tmp_path):
    """
    Test JS identifier resolving to literal, binary addition concatenation, and direct process.env pass.
    測試 JS 識別碼解析為字面值、二元加法拼接，以及直接傳遞 process.env 的場景。
    """
    code = """
    const my_host = "169.254.169.254";
    const concat_host = "http://169.254." + "169.254/";
    
    completions.create({
        prompt: my_host
    });

    completions.create({
        prompt: concat_host
    });

    completions.create({
        prompt: process.env.API_KEY
    });
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_extra.js", code)
    # Check that both SSRF leakage and Prompt leakage are detected
    assert any("Metadata API SSRF Leakage" in f["name"] for f in findings)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_js_ast_member_and_call_taint(tmp_path):
    """
    Test member object taint propagation, fs.readFileSync inside call expression, and high entropy/sensitive literal taint.
    測試 JS 成員屬性污點傳遞、呼叫運算式內部的 fs.readFileSync，以及高熵/敏感關鍵字字面值的偵測。
    """
    code = """
    const config = {};
    config.secret_key = process.env.API_KEY;
    
    completions.create({
        prompt: config.secret_key
    });

    completions.create({
        prompt: fs.readFileSync('.env', 'utf8')
    });

    // High entropy literal (len >= 24)
    completions.create({
        prompt: "abcdefghijklmnopqrstuvwx"
    });

    // Sensitive keyword literal
    completions.create({
        prompt: "my_api_key_value"
    });
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_member.js", code)
    # Should detect exfiltration findings
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_js_ast_mcp_params_class_and_returns(tmp_path):
    """
    Test JS function parameters, class definitions, and ReturnStatement branches (mcp_sensitive_leak, mcp_param_leak, metadata_ssrf, fs.readFileSync).
    測試 JS 函數參數、類別宣告，以及 Return 語句分支（如敏感檔案外洩、參數路徑外洩、Metadata SSRF、fs.readFileSync）。
    """
    code = """
    import * as mcp from 'mcp';
    
    class ToolManager {
        constructor() {}
    }

    function read_sensitive(user_path) {
        return fs.readFileSync('.env');
    }

    function read_param(user_path) {
        return fs.readFileSync(user_path);
    }

    function get_meta() {
        return "http://169.254.169.254";
    }
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_mcp_returns.js", code)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings)
    assert any("Metadata API SSRF Leakage" in f["name"] for f in findings)


def test_detector_scan_edge_cases(tmp_path):
    """
    Test scan() and scan_text() edge cases: plugin name/description, non-target extension, reading errors, unbalanced parentheses, public directory writes.
    測試 scan() 與 scan_text() 的邊界情況：外掛名稱與描述、非目標副檔名、讀取錯誤、未閉合的括號、以及公開目錄寫入。
    """
    detector = DataExfiltrationDetector()
    
    # 1. Plugin properties
    # 測試外掛基本屬性
    assert detector.name == "data_exfiltration_detector"
    assert "data exfiltration" in detector.description.lower()

    # 2. Scanning non-target file extension (should return empty list)
    # 掃描不支援的副檔名
    findings_txt = run_scan(detector, tmp_path, "test.txt", "some content")
    assert findings_txt == []

    # 3. Scanning non-existent file path (should handle gracefully and return empty list)
    # 掃描不存在的路徑
    findings_nonexistent = detector.scan(["non_existent_file.py"], None)
    assert findings_nonexistent == []

    # 4. Text-based scan with unbalanced parentheses in LLM call arguments list
    # 文字掃描：未閉合的括號
    code_unbalanced = """
    # Force text scan fallback by triggering syntax error
    class : InvalidSyntax
    openai.chat.completions.create(prompt=os.environ.get("KEY"
    """
    findings_unbalanced = run_scan(detector, tmp_path, "test_unbalanced.py", code_unbalanced)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_unbalanced)

    # 5. Public output leakage via text-based scan with process.env and public directory path
    # 文字掃描：寫入公開目錄且含環境變數
    code_public_write = 'fs.writeFileSync("public/leak.txt", process.env.API_KEY);'
    findings_public = run_scan(detector, tmp_path, "test_public.js", code_public_write)
    assert any("Public Output Leakage" in f["name"] for f in findings_public)


def test_harmless_exclusions_extra(tmp_path):
    """
    Test harmless exclusions in paths (.example, .template, etc.).
    測試路徑中無害排除字尾（例如 .example, .template 等）的覆蓋。
    """
    code = """
    import mcp
    
    @mcp.tool()
    def get_template():
        # Using a path with .example / .template should be treated as harmless
        with open("config.json.example", "r") as f:
            return f.read()
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_harmless_extra.py", code)
    assert not any("MCP Tool File Leakage" in f["name"] for f in findings)


def test_subscript_and_attribute_base_taint_propagation(tmp_path):
    """
    Test fallback base taint propagation when accessing a subscript or attribute on a tainted base object directly.
    測試當直接存取已受污染之基礎物件的下標或屬性時，後備的基礎物件污點傳遞邏輯（覆蓋 L266-269 與 L285-288）。
    """
    code_sub = """
import os
import openai

env = os.environ
openai.chat.completions.create(
    model="gpt-4",
    prompt=env["ANY_KEY"]
)
"""

    code_attr = """
import os
import openai

env = os.environ
openai.chat.completions.create(
    model="gpt-4",
    prompt=env.ANY_KEY
)
"""

    detector = DataExfiltrationDetector()

    findings_sub = run_scan(detector, tmp_path, "test_base_taint_sub.py", code_sub)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_sub)

    findings_attr = run_scan(detector, tmp_path, "test_base_taint_attr.py", code_attr)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings_attr)


def test_entropy_empty_string():
    """
    Test that calculate_entropy handles empty input gracefully by returning 0.0.
    測試 calculate_entropy 遇到空字串時能優雅返回 0.0。
    """
    assert calculate_entropy("") == 0.0


def test_js_dynamic_property_lookup(tmp_path):
    """
    Test dynamic variable-based property lookup and assignment in JS AST visitor.
    測試 JS AST 走訪器中的動態變數屬性查找與賦值（對抗性防繞過加固）。
    """
    code = """
    const key_name = "secret_key";
    const config = {};
    config[key_name] = process.env.API_KEY;
    
    completions.create({
        prompt: config[key_name]
    });
    """
    detector = DataExfiltrationDetector()
    findings = run_scan(detector, tmp_path, "test_js_dynamic.js", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_metadata_ssrf_alternative_ip_representations(tmp_path):
    detector = DataExfiltrationDetector()
    
    # Decimal format
    code_dec = 'completions.create(prompt="http://2852039166/latest/meta-data/")'
    findings_dec = run_scan(detector, tmp_path, "test_ssrf_dec.py", code_dec)
    assert any("Metadata API SSRF" in f["name"] for f in findings_dec)

    # Hex format
    code_hex = 'completions.create(prompt="http://0xa9fea9fe/latest/meta-data/")'
    findings_hex = run_scan(detector, tmp_path, "test_ssrf_hex.py", code_hex)
    assert any("Metadata API SSRF" in f["name"] for f in findings_hex)


def test_python_path_join_construction_bypass(tmp_path):
    detector = DataExfiltrationDetector()
    
    # os.path.join bypass
    code_join = """
import os
import mcp
@mcp.tool()
def get_data(d):
    path = os.path.join(d, ".env")
    return open(path).read()
"""
    findings_join = run_scan(detector, tmp_path, "test_join_bypass.py", code_join)
    assert any("MCP Tool File Leakage" in f["name"] or "MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_join)

    # Path division bypass
    code_div = """
from pathlib import Path
import mcp
@mcp.tool()
def get_data_div(d):
    path = Path(d) / ".env"
    return path.read_text()
"""
    findings_div = run_scan(detector, tmp_path, "test_div_bypass.py", code_div)
    assert any("MCP Tool File Leakage" in f["name"] or "MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_div)


def test_js_destructuring_import_bypass(tmp_path):
    detector = DataExfiltrationDetector()

    # require destructuring alias
    code_req_alias = """
    const { readFileSync: myRead } = require('fs');
    exports.myTool = function() {
        return myRead(".env");
    }
    """
    findings = run_scan(detector, tmp_path, "mcp_test_req.js", code_req_alias)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings)

    # import destructuring with alias
    code_imp = """
    import { readFileSync as r } from 'fs';
    export function mcpTool() {
        return r(".env");
    }
    """
    findings_imp = run_scan(detector, tmp_path, "mcp_test_imp.js", code_imp)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings_imp)


def test_js_mcp_parameter_destructuring_bypass(tmp_path):
    detector = DataExfiltrationDetector()
    
    # Unvalidated destructured parameter path
    code_unval = """
    const fs = require('fs');
    exports.myTool = function({ userPath }) {
        return fs.readFileSync(userPath);
    }
    """
    findings_unval = run_scan(detector, tmp_path, "mcp_destruct_unval.js", code_unval)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_unval)

    # Validated destructured parameter path
    code_val = """
    const fs = require('fs');
    exports.myTool = function({ userPath }) {
        if (userPath.includes('..')) {
            throw new Error("Invalid");
        }
        return fs.readFileSync(userPath);
    }
    """
    findings_val = run_scan(detector, tmp_path, "mcp_destruct_val.js", code_val)
    assert not any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_val)


def test_nested_subscript_taint_propagation(tmp_path):
    detector = DataExfiltrationDetector()
    
    code = """
import os
import openai

config = {}
config['secrets'] = {}
config['secrets']['key'] = os.environ.get("API_KEY")

openai.chat.completions.create(
    model="gpt-4",
    prompt=config['secrets']['key']
)
"""
    findings = run_scan(detector, tmp_path, "test_nested_sub.py", code)
    assert any("LLM Prompt Leakage" in f["name"] for f in findings)


def test_python_shutil_move_exfiltration(tmp_path):
    detector = DataExfiltrationDetector()
    
    code_move = """
import shutil
shutil.move(".env", "public/leaked_env")
"""
    findings_move = run_scan(detector, tmp_path, "test_move.py", code_move)
    assert any("Public Output Leakage" in f["name"] for f in findings_move)

    code_replace = """
import os
os.replace(".env", "static/leaked_env")
"""
    findings_replace = run_scan(detector, tmp_path, "test_replace.py", code_replace)
    assert any("Public Output Leakage" in f["name"] for f in findings_replace)


def test_path_validation_scope_isolation(tmp_path):
    detector = DataExfiltrationDetector()
    
    code = """
import mcp

@mcp.tool()
def read_log(user_path: str, tainted_path: str):
    if ".." in user_path:
        raise ValueError("Invalid path")
    # Reading tainted_path which is NOT validated should alert!
    return open(tainted_path).read()
"""
    findings = run_scan(detector, tmp_path, "test_scope_isolation.py", code)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings)


def test_js_template_literal_and_move(tmp_path):
    detector = DataExfiltrationDetector()
    
    # Template literal matching
    code_tpl = """
    const fs = require('fs');
    exports.myTool = function() {
        const name = "env";
        return fs.readFileSync(`.${name}`);
    }
    """
    findings_tpl = run_scan(detector, tmp_path, "mcp_tpl.js", code_tpl)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings_tpl)

    # JS copy/rename operation
    code_copy = """
    const fs = require('fs');
    fs.copyFileSync(".env", "public/leak.txt");
    """
    findings_copy = run_scan(detector, tmp_path, "test_js_copy.js", code_copy)
    assert any("Public Output Leakage" in f["name"] for f in findings_copy)


def test_path_validation_toctou_bypass(tmp_path):
    detector = DataExfiltrationDetector()
    
    # Python TOCTOU
    code_py = """
import mcp
@mcp.tool()
def read_log(user_path: str):
    if ".." in user_path:
        raise ValueError("Invalid path")
    # TOCTOU reassignment!
    user_path = "/etc/passwd"
    return open(user_path).read()
"""
    findings_py = run_scan(detector, tmp_path, "test_toctou.py", code_py)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] or "MCP Tool File Leakage" in f["name"] for f in findings_py)

    # JS TOCTOU
    code_js = """
    const fs = require('fs');
    exports.myTool = function(userPath) {
        if (userPath.includes('..')) {
            throw new Error("Invalid");
        }
        userPath = ".env";
        return fs.readFileSync(userPath);
    }
"""
    findings_js = run_scan(detector, tmp_path, "mcp_toctou.js", code_js)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] or "MCP Tool File Leakage" in f["name"] for f in findings_js)


def test_path_validation_dummy_bypass(tmp_path):
    detector = DataExfiltrationDetector()
    
    # Python Dummy Validation (not in a condition, just returns bool which is ignored)
    code_py = """
import mcp
@mcp.tool()
def read_log(user_path: str):
    # Dummy validation: is_safe(user_path) returns false but code continues!
    is_safe(user_path)
    return open(user_path).read()
"""
    findings_py = run_scan(detector, tmp_path, "test_dummy.py", code_py)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_py)

    # JS Dummy Validation
    code_js = """
    const fs = require('fs');
    exports.myTool = function(userPath) {
        // Dummy check, result ignored!
        userPath.includes('..');
        return fs.readFileSync(userPath);
    }
"""
    findings_js = run_scan(detector, tmp_path, "mcp_dummy.js", code_js)
    assert any("MCP Tool Parameter Arbitrary File Leakage" in f["name"] for f in findings_js)


def test_path_case_normalization_bypass(tmp_path):
    detector = DataExfiltrationDetector()
    
    # Uppercase sensitive path `.ENV` in Python MCP
    code_py_path = """
import mcp
@mcp.tool()
def get_config():
    return open(".ENV").read()
"""
    findings_py_path = run_scan(detector, tmp_path, "test_case_path.py", code_py_path)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings_py_path)

    # Uppercase sensitive path `.AWS/CREDENTIALS` in JS MCP
    code_js_path = """
    const fs = require('fs');
    exports.myTool = function() {
        return fs.readFileSync(".AWS/CREDENTIALS");
    }
"""
    findings_js_path = run_scan(detector, tmp_path, "mcp_case_path.js", code_js_path)
    assert any("MCP Tool File Leakage" in f["name"] for f in findings_js_path)

    # Case-insensitive Metadata SSRF in LLM Call
    code_ssrf = 'completions.create(prompt="HTTP://2852039166/latest/meta-data/")'
    findings_ssrf = run_scan(detector, tmp_path, "test_case_ssrf.py", code_ssrf)
    assert any("Metadata API SSRF" in f["name"] for f in findings_ssrf)


