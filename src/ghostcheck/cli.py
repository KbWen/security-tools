import sys
import argparse
import os
from .scanner import Scanner
from .reporters.console import ConsoleReporter
from .reporters.json_reporter import JsonReporter
from .demo import DemoRunner

def main():
    parser = argparse.ArgumentParser(
        description="GhostCheck: AI-Era Security Scanner",
        epilog="Addressing the unique risks of AI-assisted development."
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run full scan on target path")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target path to scan (default: .)")
    
    # check-deps command
    deps_parser = subparsers.add_parser("check-deps", help="Check dependencies for hallucinations")
    deps_parser.add_argument("target", help="File to check (requirements.txt or package.json)")
    
    # check-secrets command
    secrets_parser = subparsers.add_parser("check-secrets", help="Scan for leaked secrets")
    secrets_parser.add_argument("path", help="Path to scan")
    
    # check-rules command
    rules_parser = subparsers.add_parser("check-rules", help="Lint agent rules")
    rules_parser.add_argument("path", help="Path to scan for rule files")
    
    # demo command
    subparsers.add_parser("demo", help="Run a demo scan with sample vulnerabilities")
    
    # Global flags
    parser.add_argument("--format", choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="INFO", help="Minimum severity threshold")
    parser.add_argument("--no-ignore", action="store_true", help="Disable .ghostcheckignore support")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version="GhostCheck 0.1.0")
    
    args = parser.parse_args()
    
    if args.command == "demo":
        runner = DemoRunner()
        sys.exit(runner.run(reporter_type=args.format))
        
    if not args.command:
        parser.print_help()
        sys.exit(0)
        
    # Standard scanning commands
    target_path = getattr(args, "path", getattr(args, "target", "."))
    if not os.path.exists(target_path):
        print(f"Error: Path '{target_path}' does not exist.")
        sys.exit(2)
        
    scanner = Scanner(target_path, ignore_enabled=not args.no_ignore)
    
    try:
        findings = []
        if args.command == "scan":
            findings = scanner.scan()
        elif args.command == "check-deps":
            # For specific file checks, we filter manual
            all_findings = scanner.scan()
            findings = [f for f in all_findings if f.get('package')]
        elif args.command == "check-secrets":
            all_findings = scanner.scan()
            findings = [f for f in all_findings if f.get('pattern_name')]
        elif args.command == "check-rules":
            all_findings = scanner.scan()
            findings = [f for f in all_findings if f.get('rule_name')]
            
        # Filter by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        threshold = severity_order.get(args.severity, 4)
        findings = [f for f in findings if severity_order.get(f.get('severity', 'INFO'), 4) <= threshold]
        
        # Report
        if args.format == "json":
            reporter = JsonReporter()
        else:
            reporter = ConsoleReporter(use_color=not args.no_color)
            
        reporter.report(findings)
        
        # Exit codes (AC-8)
        if findings:
            sys.exit(1)
        sys.exit(0)
        
    except Exception as e:
        print(f"Fatal Error: {str(e)}")
        sys.exit(2)

if __name__ == "__main__":
    main()
