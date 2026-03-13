import os
import pytest
from ghostcheck.scanner import Scanner

def test_path_traversal_protection(tmp_path):
    # Create a dummy file outside the root
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("secret_key=SHHHH")
    
    # Create a project directory
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    
    scanner = Scanner(str(project_dir))
    
    # Attempt to read the outside file via a traversal-like path
    # Even if we pass it directly to a scanner method if it were exposed, 
    # but here we test the internal _read_file_safe
    traversal_path = os.path.join(str(project_dir), "..", "outside.txt")
    
    assert scanner._read_file_safe(traversal_path) is None

def test_file_size_limit(tmp_path):
    # Create a large file
    large_file = tmp_path / "large.txt"
    with open(large_file, "wb") as f:
        f.write(b"0" * (Scanner.MAX_FILE_SIZE + 1024))
    
    scanner = Scanner(str(tmp_path))
    assert scanner._read_file_safe(str(large_file)) is None
