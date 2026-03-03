# Contributing to MCP Security Scan

Thanks for your interest in contributing! This project scans MCP servers and AI agents for security vulnerabilities, and contributions that improve detection coverage or reduce false positives are especially valuable.

## How to Contribute

### Reporting Issues

- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md)
- **Bugs**: Open an issue with steps to reproduce, expected vs. actual behavior, and your environment
- **False positives/negatives**: Include the code snippet that was incorrectly flagged (or missed) and the scan output

### Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes in `scan.py` or `action.yml`
3. Test locally: `python scan.py` from the repo root
4. Ensure the self-test workflow passes: the action runs against itself on every PR
5. Open a PR with a clear description of what changed and why

### Adding New Vulnerability Detections

Each scanner class in `scan.py` has a pattern list. To add a new detection:

1. Add the pattern to the appropriate scanner (MCP Tool Poisoning, DataFlow Taint, Prompt Injection, or Architecture)
2. Assign a severity level (critical, high, medium, low)
3. Write a clear `message` that explains the risk
4. Test against a real-world example to avoid false positives

### Code Style

- Python 3.11+, no external dependencies (stdlib only)
- Keep `scan.py` self-contained — the action must run without pip install for the scanner itself
- SARIF output must validate against the SARIF 2.1.0 schema

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
