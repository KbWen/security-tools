from ghostcheck.demo import DemoRunner

def test_demo_command_smoke():
    runner = DemoRunner()
    # Mocking or redirecting stdout to avoid terminal noise if needed, 
    # but for a basic smoke test, we just want to ensure it doesn't crash.
    # DemoRunner.run() returns the exit code.
    exit_code = runner.run(reporter_type="json")
    assert exit_code == 0 # Demo command should return 0 if it runs successfully
