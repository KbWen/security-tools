import pytest
from ghostcheck.checks.ast_go_scanner import GoASTScanner
from ghostcheck.checks.ast_java_scanner import JavaASTScanner
from ghostcheck.checks.ast_dart_scanner import DartASTScanner

@pytest.fixture
def dummy_patterns():
    return [
        {"name": "Google API Key", "pattern": "AIza[0-9A-Za-z-_]{35}", "severity": "CRITICAL"}
    ]

def test_go_ast_scanner(dummy_patterns):
    scanner = GoASTScanner(dummy_patterns)
    content = '''
package main
func main() {
    apiKey := "AIzaSyDummyKey12345678901234567890123456789"
    var token = "AIzaSyDummyKey12345678901234567890123456789"
    safeKey := "just-a-plain-string"
}
'''
    findings = scanner.scan_file("main.go", content)
    assert len(findings) == 2
    assert findings[0]["name"] == "Go Hardcoded Google API Key"
    assert findings[1]["name"] == "Go Hardcoded Google API Key"
    assert "apiKey" in findings[0]["message"]
    assert "token" in findings[1]["message"]

def test_java_ast_scanner(dummy_patterns):
    scanner = JavaASTScanner(dummy_patterns)
    content = '''
public class Config {
    String key1 = "AIzaSyDummyKey12345678901234567890123456789";
    @Value("some-hardcoded-value")
    private String customKey;
    @Value("${spring.config}")
    private String safeKey;
}
    '''
    findings = scanner.scan_file("Config.java", content)
    assert len(findings) == 2
    
    assert findings[0]["name"] == "Java Hardcoded Google API Key"
    assert findings[1]["name"] == "Spring @Value Hardcoded Secret"

def test_dart_ast_scanner(dummy_patterns):
    scanner = DartASTScanner(dummy_patterns)
    content = '''
void main() {
    const apiKey = "AIzaSyDummyKey12345678901234567890123456789";
    print(apiKey);
}
    '''
    findings = scanner.scan_file("main.dart", content)
    assert len(findings) == 2
    assert findings[0]["name"] == "Dart Hardcoded Google API Key"
    assert findings[1]["name"] == "Dart Leaky Print"
    assert "apiKey" in findings[1]["message"]

def test_ast_scanners_case_insensitive_extensions(dummy_patterns):
    go_scanner = GoASTScanner(dummy_patterns)
    java_scanner = JavaASTScanner(dummy_patterns)
    dart_scanner = DartASTScanner(dummy_patterns)

    # Uppercase .GO, .JAVA, .DART, and Kotlin Script .kts
    go_findings = go_scanner.scan_file("App.GO", 'key := "AIzaSyDummyKey12345678901234567890123456789"')
    assert len(go_findings) == 1

    java_findings = java_scanner.scan_file("Main.JAVA", 'String key = "AIzaSyDummyKey12345678901234567890123456789";')
    assert len(java_findings) == 1

    kt_findings = java_scanner.scan_file("build.gradle.kts", 'val secret = "AIzaSyDummyKey12345678901234567890123456789"')
    assert len(kt_findings) == 1

    dart_findings = dart_scanner.scan_file("Main.DART", 'const key = "AIzaSyDummyKey12345678901234567890123456789";')
    assert len(dart_findings) == 1

