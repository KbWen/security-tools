import sys
import argparse
import os
import json
from .scanner import Scanner
from .reporters.console import ConsoleReporter
from .reporters.json_reporter import JsonReporter
from .reporters.sarif_reporter import SarifReporter
from .reporters.html_reporter import HTMLReporter

from .config import GhostCheckConfig
from .init import GhostCheckInitializer
from .checks.git_diff_scanner import GitDiffScanner

def main():
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="GhostCheck: AI-Era Security Scanner",
        epilog="Addressing the unique risks of AI-assisted development."
    )
    
    # parent parser for common scan arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--format", choices=["console", "json", "sarif", "html"], default="console", help="Output format")
    parent_parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Minimum severity threshold (overrides config)")
    parent_parser.add_argument("--no-ignore", action="store_true", help="Disable .ghostcheckignore support")
    parent_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parent_parser.add_argument("--offline", action="store_true", help="Run in offline mode")
    parent_parser.add_argument("--baseline", help="Path to baseline file to suppress known findings")
    parent_parser.add_argument("--load-local-plugins", action="store_true", help="Enable loading plugins from local workspace .ghostcheck/plugins")

    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", parents=[parent_parser], help="Run scan on target path")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target path to scan (default: .)")
    scan_parser.add_argument("--staged", action="store_true", help="Only scan files staged in Git")
    scan_parser.add_argument("--diff", help="Only scan files changed since specific Git ref (e.g. HEAD~1)")
    
    # init command
    init_parser = subparsers.add_parser("init", help="Initialize GhostCheck in the current project")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing configuration")
    init_parser.add_argument("--ci", choices=["github", "gitlab"], help="Generate CI pipeline configuration")
    
    # baseline command
    baseline_parser = subparsers.add_parser("baseline", help="Manage security check baselines")
    baseline_sub = baseline_parser.add_subparsers(dest="baseline_cmd")
    create_bl = baseline_sub.add_parser("create", help="Create a baseline from current findings")
    create_bl.add_argument("output", nargs="?", default=".ghostcheck-baseline.json", help="Output file path")
    
    # check-deps command
    subparsers.add_parser("check-deps", parents=[parent_parser], help="Check dependencies for hallucinations")
    
    # check-secrets command
    subparsers.add_parser("check-secrets", parents=[parent_parser], help="Scan for leaked secrets")
    
    # Version flag
    parser.add_argument("--version", action="version", version="GhostCheck 0.8.0")
    
    args = parser.parse_args()
    
    if args.command == "init":
        initializer = GhostCheckInitializer(".")
        success, msg = initializer.initialize(force=args.force)
        print(f"{'✅' if success else '⚠️'} {msg}")
        if success and args.ci:
            success_ci, msg_ci = initializer.generate_ci_pipeline(args.ci)
            print(f"{'✅' if success_ci else '⚠️'} {msg_ci}")
        sys.exit(0 if success else 1)

    # Load configuration
    config = GhostCheckConfig(".")
    config.update_from_args(args)
    
    if args.command == "demo":
        runner = DemoRunner()
        sys.exit(runner.run(reporter_type=args.format))
        
    if not args.command:
        parser.print_help()
        sys.exit(0)
        
    # Determine target and file list
    target_path = getattr(args, "path", ".")
    limit_files = None
    
    if args.command == "scan":
        git_scanner = GitDiffScanner(target_path)
        if args.staged:
            if not git_scanner.is_git_repo():
                print("Error: Not a git repository.")
                sys.exit(2)
            limit_files = git_scanner.get_staged_files()
            if not limit_files:
                print("No staged files to scan.")
                sys.exit(0)
        elif args.diff:
            if not git_scanner.is_git_repo():
                print("Error: Not a git repository.")
                sys.exit(2)
            limit_files = git_scanner.get_diff_files(args.diff)
            if not limit_files:
                print("No files changed since ref.")
                sys.exit(0)

    # Initialize scanner
    scanner = Scanner(
        target_path, 
        ignore_enabled=not args.no_ignore, 
        offline=config.get("offline", False),
        config=config,
        baseline_path=args.baseline
    )
    
    try:
        findings = []
        if args.command == "scan":
            findings = scanner.scan(limit_files=limit_files)
        elif args.command == "check-deps":
            findings = scanner.scan_dependencies(limit_files=limit_files)
        elif args.command == "check-secrets":
            findings = scanner.scan_secrets(limit_files=limit_files)
            
        # Baseline creation
        if args.command == "baseline" and args.baseline_cmd == "create":
            scan_findings = scanner.scan()
            with open(args.output, "w") as f:
                json.dump({"findings": scan_findings}, f, indent=4)
            print(f"✅ Baseline created with {len(scan_findings)} findings at {args.output}")
            sys.exit(0)

        # Filter by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        threshold_name = args.severity or config.get("severity_threshold", "INFO")
        threshold = severity_order.get(threshold_name, 4)
        findings = [f for f in findings if severity_order.get(f.get('severity', 'INFO'), 4) <= threshold]
        
        # Calculate score
        grade, score_val = scanner.scoring_engine.calculate_score(findings)
        
        # Report
        if args.format == "json":
            reporter = JsonReporter()
            reporter.report(findings)
        elif args.format == "sarif":
            reporter = SarifReporter()
            reporter.report(findings)
        elif args.format == "html":
            reporter = HTMLReporter()
            path = reporter.report(findings, grade, score_val)
            print(f"✅ HTML Report generated at: {path}")
            print(f"📊 Security Grade: {grade} ({score_val}/100)")
        else:
            reporter = ConsoleReporter(use_color=not args.no_color)
            reporter.report(findings)
            print(f"\n📊 {ConsoleReporter()._color('Project Security Grade:', 'INFO')} {grade} ({score_val}/100)")
            
        if findings:
            sys.exit(1)
        sys.exit(0)
        
    except Exception as e:
        print(f"Fatal Error: {str(e)}")
        sys.exit(2)

if __name__ == "__main__":
    main()
