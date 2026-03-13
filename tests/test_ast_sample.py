# Test file for AST secret scanning
# This should be caught by AST scanner but missed by simple regex

aws_key = "AKIA" + "QD6L7XYPVNEXAMPL"

print(f"Using key: {aws_key}")
