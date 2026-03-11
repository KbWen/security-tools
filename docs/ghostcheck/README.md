# GhostCheck

## AI-Era Security Scanner for Developers

GhostCheck is a zero-dependency CLI security scanner designed to detect risks specific to AI-assisted development workflows.

## Key Features

- **Hallucination Detection**: Flags packages that don't exist on PyPI/npm or are suspiciously new.
- **Secret Scanning**: Finds leaked API keys/tokens in AI chat logs and code with file-type-aware severity.
- **Agent Rules Linter**: Audits `.agent`, `.cursor`, and other agent rules for dangerous permissions or commands.
- **Zero Dependencies**: Pure Python implementation with no runtime dependencies.

## Installation

```bash
pip install -e .
```

## Usage

### Perform a Full Scan

```bash
ghostcheck scan .
```

### Check Dependencies

```bash
ghostcheck check-deps requirements.txt
ghostcheck check-deps package.json
```

### Scan for Secrets

```bash
ghostcheck check-secrets ./docs
```

### Audit Agent Rules

```bash
ghostcheck check-rules .agent/
```

### Interactive Demo

```bash
ghostcheck demo
```

## Options

- `--format [console|json]`: Specify output format.
- `--severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]`: Filter by minimum severity.
- `--no-ignore`: Ignore `.ghostcheckignore` rules.
- `--no-color`: Disable terminal colors.

## License

MIT
