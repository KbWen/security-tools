import os
import shutil
import subprocess
import json
import pathlib
import sys

# Ensure src is in python path
src_dir = os.path.abspath("src")

if sys.platform == "win32":
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def run_cmd(args, cwd):
    if args[0] == "ghostcheck":
        args = [sys.executable, "-m", "ghostcheck.cli"] + args[1:]
    env = os.environ.copy()
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    env["GHOSTCHECK_DEBUG"] = "1"
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace', env=env)
    return result

def setup_fresh_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)

def test_scenario_7_git_subfolder_isolation(base_dir):
    """
    Scenario: User is in a subfolder of a Git repo. 
    Staged files exist in other folders.
    Expected: 'scan --staged' in subfolder should only scan staged files in THAT subfolder.
    """
    print("\n--- [Scenario 7: Git Subfolder Isolation] ---")
    repo_dir = base_dir / "repo_root"
    setup_fresh_dir(repo_dir)
    
    # Init git repo
    subprocess.run(["git", "init"], cwd=repo_dir, capture_output=True)
    
    # Create file at root and stage it
    (repo_dir / "root_file.py").write_text("SECRET_K = 'root'")
    subprocess.run(["git", "add", "root_file.py"], cwd=repo_dir)
    
    # Create subfolder and file
    sub_dir = repo_dir / "sub"
    os.makedirs(sub_dir)
    (sub_dir / "sub_file.py").write_text("SECRET_K = 'sub'")
    # DO NOT STAGE sub_file.py
    
    # Run scan --staged in subfolder
    res = run_cmd(["ghostcheck", "scan", "--staged"], sub_dir)
    
    if "No staged files" in res.stdout:
        print("[OK] Correctly ignored staged files outside the current subfolder.")
    else:
        print(f"[!] Friction: It scanned root_file.py even though we are in /sub.\nSTDOUT: {res.stdout.strip()}")

def main():
    base_dir = pathlib.Path("c:/Users/wen/.gemini/antigravity/scratch/security-tools/friction_test_workspace")
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
        
    print("=== GhostCheck v1.0.0 Friction & Stress Tests ===\n")
    test_scenario_7_git_subfolder_isolation(base_dir)

if __name__ == "__main__":
    main()
