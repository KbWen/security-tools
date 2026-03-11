import os
import shutil
import tempfile
from .scanner import Scanner

class DemoRunner:
    def __init__(self):
        # In a real package, files are in data/demo_fixtures/
        # Here we'll locate them relative to this file
        self.base_dir = os.path.dirname(__file__)
        self.fixtures_dir = os.path.join(self.base_dir, 'data', 'demo_fixtures')

    def run(self, reporter_type='console'):
        print("\n🚀 Starting GhostCheck Demo Scan...\n")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy fixtures to temp dir
            for f in os.listdir(self.fixtures_dir):
                shutil.copy(os.path.join(self.fixtures_dir, f), tmpdir)
            
            # Run scanner
            scanner = Scanner(tmpdir)
            findings = scanner.scan()
            
            # Use scanner's reporting logic via a shim or direct call
            # For demo, we just print the findings using the console reporter logic
            from .reporters.console import ConsoleReporter
            reporter = ConsoleReporter()
            reporter.report(findings)
            
            print(f"\n✅ Demo complete. Scanned {len(os.listdir(self.fixtures_dir))} files in temporary directory: {tmpdir}")
            print("Note: All temporary files have been cleaned up.\n")
            
        return 0
