import sys
import io
import argparse
import os
import json


# Lazy imports inside functions for performance

from .config import GhostCheckConfig
from .init import GhostCheckInitializer
from .checks.git_diff_scanner import GitDiffScanner
from . import __version__

def get_icon(icon_type, use_unicode=True):
    icons = {
        "ok": ("✅", "[OK]"),
        "warn": ("⚠️", "[WARN]"),
        "stats": ("📊", "[STATS]"),
        "info": ("ℹ️", "[INFO]"),
    }
    char, fallback = icons.get(icon_type, ("?", "?"))
    return char if use_unicode else fallback

def main():
    # Fix: Reconfigure stdout to UTF-8 with replacement to avoid cp950/encoding crashes
    # on non-UTF-8 terminals (e.g., Windows cmd). Falls back gracefully.
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    elif hasattr(sys.stdout, 'buffer'):
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="GhostCheck: AI-Era Security Scanner",
        epilog="Addressing the unique risks of AI-assisted development."
    )
    
    # parent parser for common scan arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--format", choices=["console", "json", "sarif", "html", "owasp-llm"], default="console", help="Output format")
    parent_parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Minimum severity threshold (overrides config)")
    parent_parser.add_argument("--preset", help="Use a framework-specific scan preset (e.g., next.js, flutter)")
    parent_parser.add_argument("--no-ignore", action="store_true", help="Disable .ghostcheckignore support")
    parent_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parent_parser.add_argument("--ascii-only", action="store_true", help="Disable Unicode/Emoji output")
    parent_parser.add_argument("--offline", action="store_true", help="Run in offline mode")
    parent_parser.add_argument("--baseline", help="Path to baseline file to suppress known findings")
    parent_parser.add_argument("--output", help="Path to output file for results")
    parent_parser.add_argument("--soft-fail", action="store_true", help="Do not exit with non-zero code even if findings are present")
    parent_parser.add_argument("--load-local-plugins", action="store_true", help="Enable loading plugins from local workspace .ghostcheck/plugins")
    parent_parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parent_parser.add_argument("--insecure", action="store_true", help="Skip SSL certificate verification")
    parent_parser.add_argument("--timeout", type=int, default=10, help="Network timeout in seconds (default: 10)")

    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", parents=[parent_parser], help="Run scan on target path")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target path to scan (default: .)")
    scan_parser.add_argument("--staged", action="store_true", help="Only scan files staged in Git")
    scan_parser.add_argument("--diff", help="Only scan files changed since specific Git ref (e.g. HEAD~1)")
    
    # init command
    init_parser = subparsers.add_parser("init", parents=[parent_parser], help="Initialize GhostCheck in the current project")
    init_parser.add_argument("path", nargs="?", default=".", help="Target path to initialize (default: .)")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing configuration")
    init_parser.add_argument("--ci", choices=["github", "gitlab"], help="Generate CI pipeline configuration")
    
    # baseline command
    baseline_parser = subparsers.add_parser("baseline", parents=[parent_parser], help="Manage security check baselines")
    baseline_sub = baseline_parser.add_subparsers(dest="baseline_cmd")
    create_bl = baseline_sub.add_parser("create", help="Create a baseline from current findings")
    create_bl.add_argument("output", nargs="?", default=".ghostcheck-baseline.json", help="Output file path")
    
    # check-deps command
    subparsers.add_parser("check-deps", parents=[parent_parser], help="Check dependencies for hallucinations")
    
    # check-secrets command
    subparsers.add_parser("check-secrets", parents=[parent_parser], help="Scan for leaked secrets")
    
    # list-checks command
    subparsers.add_parser("list-checks", parents=[parent_parser], help="List all available security checks")
    
    # list-plugins command
    subparsers.add_parser("list-plugins", parents=[parent_parser], help="List all loaded plugins")
    
    # Version flag
    parser.add_argument("--version", action="version", version=f"GhostCheck {__version__}")
    
    args = parser.parse_args()
    
    # Determine encoding/unicode support
    stdout_encoding = (sys.stdout.encoding or 'ascii').lower()
    use_unicode = not args.ascii_only and stdout_encoding == 'utf-8'

    if args.command == "init":
        initializer = GhostCheckInitializer(args.path)
        success, msg = initializer.initialize(force=args.force)
        print(f"{get_icon('ok', use_unicode) if success else get_icon('warn', use_unicode)} {msg}")
        if success and args.ci:
            success_ci, msg_ci = initializer.generate_ci_pipeline(args.ci)
            print(f"{get_icon('ok', use_unicode) if success_ci else get_icon('warn', use_unicode)} {msg_ci}")
        sys.exit(0 if success else 1)

    # Load configuration
    config = GhostCheckConfig(".")
    config.update_from_args(args)
    
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

    if args.debug:
        os.environ["GHOSTCHECK_DEBUG"] = "1"

    if args.command == "list-checks":
        print(f"{get_icon('info', use_unicode)} Available Checks (v{__version__}):")
        checks = [
            ("hallucination", "Scan for hallucinated packages in requirements.txt/package.json"),
            ("secrets",       "Scan for hardcoded secrets using regex, AST & entropy analysis"),
            ("env",           "Scan .env files for exposed secrets"),
            ("rules",         "Lint AI agent rules (.cursorrules, AGENTS.md, CLAUDE.md)"),
            ("docker",        "Audit Dockerfiles & docker-compose for security risks"),
            ("iac",           "Audit Terraform/CloudFormation/K8s templates"),
            ("ci_cd",         "Scan CI pipeline configs (GitHub Actions/GitLab CI)"),
            ("mcp",           "Audit Model Context Protocol configuration"),
            ("supply_chain",  "Check AI supply chain & agentic dependencies"),
            ("mobile",        "Audit mobile configs (AndroidManifest.xml, Info.plist)"),
            ("api",           "Lint API endpoints for CORS, auth, and rate-limit issues"),
            ("vuln",          "Query OSV for known vulnerabilities in dependencies"),
            ("logic",         "Detect business logic bypass patterns (subscription, admin, debug)"),
        ]
        for name, desc in checks:
            print(f"  - {name:<15}: {desc}")
        sys.exit(0)

    from .scanner import Scanner
    from .plugin_manager import PluginManager
    
    # Initialize plugin manager
    pm = PluginManager()
    pm.load_builtins()

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
            with open(args.output, "w", encoding='utf-8') as f:
                json.dump({"findings": scan_findings}, f, indent=4, ensure_ascii=False)
            print(f"{get_icon('ok', use_unicode)} Baseline created with {len(scan_findings)} findings at {args.output}")
            sys.exit(0)

        # Filter by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        threshold_name = args.severity or config.get("severity_threshold", "INFO")
        threshold = severity_order.get(threshold_name, 4)
        findings = [f for f in findings if severity_order.get(f.get('severity', 'INFO'), 4) <= threshold]
        
        # Calculate score
        grade, score_val = scanner.scoring_engine.calculate_score(findings)
        
        # Report
        output_file = None

        if args.command == "list-plugins":
            # For now, list loaded scanners and reporters
            print(f"{get_icon('info', use_unicode)} Loaded Scanners ({len(pm.get_all_scanners())}):")
            for name in pm.get_all_scanners():
                print(f"  - {name}")
            print(f"{get_icon('info', use_unicode)} Loaded Reporters ({len(pm.get_all_reporters())}):")
            for name in pm.get_all_reporters():
                print(f"  - {name}")
            sys.exit(0)

        reporter_cls = pm.get_reporter(args.format)
        if not reporter_cls:
            # Fallback to console if not found
            reporter_cls = pm.get_reporter('console')
            if not reporter_cls:
                print(f"Fatal Error: No reporter found for format '{args.format}' and fallback 'console' is missing.")
                sys.exit(2)
        
        # Instantiate reporter (pass common kwargs, some might ignore them)
        try:
            reporter = reporter_cls(use_color=not args.no_color and not args.output, use_unicode=use_unicode)
        except TypeError:
            # If reporter doesn't take those kwargs
            reporter = reporter_cls()

        if args.output:
            try:
                output_file = open(args.output, 'w', encoding='utf-8')
            except IOError as e:
                print(f"Error: Could not open output file {args.output}: {str(e)}")
                sys.exit(2)
        
        try:
            reporter.report(findings, stream=output_file, grade=grade, score_val=score_val, output_path=args.output)
            
            # If console and we have cache hits
            if args.format == "console" and hasattr(scanner, 'cache_hits') and scanner.cache_hits > 0:
                print(f"  ({scanner.cache_hits} files loaded from cache)")
            
            # Summary footer for console
            if args.format == "console":
                # Assuming ConsoleReporter has _color, otherwise just print
                color_func = getattr(reporter, '_color', lambda text, sev: text)
                print(f"\n{get_icon('stats', use_unicode)} {color_func('Project Security Grade:', 'INFO')} {grade} ({score_val}/100)")
                print(f"{get_icon('info', use_unicode)} Total findings: {len(findings)}")

            if findings and not args.soft_fail:
                sys.exit(1)
            sys.exit(0)
        finally:
            if output_file:
                output_file.close()

    except Exception as e:
        print(f"Fatal Error: {str(e)}")
        # If debugging, print traceback
        if os.environ.get("GHOSTCHECK_DEBUG") == "1":
            import traceback
            traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
