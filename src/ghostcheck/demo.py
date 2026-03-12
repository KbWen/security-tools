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
            # Create expected directories
            agent_dir = os.path.join(tmpdir, '.agent')
            os.makedirs(agent_dir)
            
            # Map fixtures to their expected names and locations
            fixture_map = {
                'chat_log_demo.md': ('chat_log.md', tmpdir),
                'requirements_demo.txt': ('requirements.txt', tmpdir),
                'rules_demo.md': ('rules.md', agent_dir)
            }
            
            for src_name, (dst_name, dst_dir) in fixture_map.items():
                shutil.copy(
                    os.path.join(self.fixtures_dir, src_name),
                    os.path.join(dst_dir, dst_name)
                )
            
            # Run scanner
            scanner = Scanner(tmpdir)
            findings = scanner.scan()
            
            # Use scanner's reporting logic
            from .reporters.console import ConsoleReporter
            reporter = ConsoleReporter()
            reporter.report(findings)
            
            print(f"\n✅ Demo complete. Scanned temporary environment: {tmpdir}")
            print("Note: All temporary files have been cleaned up.\n")
            
        return 0
