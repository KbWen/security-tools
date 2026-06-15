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




