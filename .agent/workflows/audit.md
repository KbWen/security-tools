---
name: audit
description: Map existing repository state during migration or onboarding.
tasks:
  - audit
---

# /audit

> Purpose: Map an existing legacy repository to establish baseline context before transitioning to AgentCortex workflows.

## Environment Constraints

- **NO GATE**: This workflow bypasses all Gate Engine checks.
- **NO CODE MODIFICATION**: This workflow is read-only for codebase files.
- **REPORT ONLY**: The goal is to generate an analysis, not a plan or an implementation.

## Workflow Execution Steps

1. **Discover Files**: Perform a broad scan of the directory structure (respecting `.gitignore`).
2. **Infer Architecture**: Analyze the imports, configuration files (e.g., `package.json`, `requirements.txt`), and main entry points.
3. **Assess Documentation**: Check for existing READMEs, inline comments, or legacy specs.
4. **Assess Test Coverage**: Locate test directories and gauge the approximate level of testing.

## Expected Output Format

After scanning the repository, output the following structured report:

1. **`existing_files`**: High-level summary of the file structure.
2. **`system_map`**: Core modules and their dependencies.
3. **`entry_points`**: How the application starts or is built.
4. **`test_coverage`**: Status of existing tests.
5. **`missing_docs`**: Critical documentation gaps that should be addressed first.
6. **`recommended_next`**: The suggested next step (typically `/spec` or `/plan` to begin formalizing an area of the codebase).
