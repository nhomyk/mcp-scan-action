# mcp-scan-action

**Scan your MCP tools, AI agents, and LLM pipelines for security vulnerabilities.**

Detects tool poisoning, SSRF, prompt injection, cross-agent DataFlow taint, and ambient authority in any repo that uses MCP, LangChain, LangGraph, CrewAI, AutoGen, or direct Anthropic/OpenAI SDK calls — before you ship.

Results appear in your **GitHub Security tab** via SARIF. No API key required.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-mcp--scan--action-blue?logo=github)](https://github.com/marketplace/actions/mcp-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Quickstart

```yaml
- uses: nhomyk/mcp-scan-action@v1
```

That's it. Add it to any job that checks out your code.

---

## Full Example

```yaml
name: Security

on: [push, pull_request]

jobs:
  mcp-scan:
    name: MCP Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required to upload SARIF
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: nhomyk/mcp-scan-action@v1
        id: scan
        with:
          fail-on-critical: 'true'   # block the build on critical findings

      - name: Show risk level
        run: echo "Risk level ${{ steps.scan.outputs.risk-level }}"
```

Findings appear under **Security → Code scanning alerts** in your repository.

---

## What It Detects

### MCP Tool Poisoning (11 attack types)
| Attack Type | Description |
|-------------|-------------|
| `TOOL_POISONING` | Tool descriptions or schemas that manipulate LLM behavior |
| `EXFILTRATION_PATTERN` | Data being routed to unexpected external endpoints |
| `PROMPT_INJECTION_VECTOR` | User-controlled data concatenated unsafely into prompts |
| `AMBIENT_AUTHORITY` | Tools with implicit permissions beyond declared scope |
| `UNRESTRICTED_FILE_ACCESS` | Filesystem access without path sanitization |
| `SSRF_RISK` | Server-side request forgery via tool-controlled URLs |
| `COMMAND_INJECTION` | Shell commands constructed from LLM/user input |
| `MISSING_AUTH` | Authenticated actions reachable without credential checks |
| `UNCONSTRAINED_SCOPE` | Agents with no permission boundaries |
| `CROSS_ORIGIN_ESCALATION` | Cross-agent trust boundary violations |
| `SHADOW_TOOL` | Hidden tool registrations not visible to the user |

### DataFlow Taint (9 finding types)
`SECRET_SOURCE` · `PII_SOURCE` · `CROSS_BOUNDARY` · `SINK_LOGGING` · `SINK_NETWORK` · `SINK_STORAGE` · `TAINT_PROPAGATION` · `MISSING_SANITIZE` · `PRIVILEGE_ESCALATION`

### Prompt Injection (4 patterns)
Direct concatenation · Template injection · Unsafe LLM output · Role override

### Architecture (MCP/Agent integration points)
`MCP_TOOL` and `AGENT_FRAMEWORK` integration areas from static code analysis.

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `repo-path` | `.` | Path to the repository to scan |
| `fail-on-critical` | `false` | Exit code 1 if any critical findings found |
| `sarif-output` | `mcp-scan-results.sarif` | SARIF output filename |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning (requires `security-events: write`) |
| `category` | `mcp-security` | SARIF category (useful when running multiple scans) |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings across all scan types |
| `risk-level` | `low` \| `medium` \| `high` \| `critical` |
| `critical-count` | Number of critical findings |
| `sarif-file` | Path to the SARIF output file |

---

## Use the findings in downstream steps

```yaml
- uses: nhomyk/mcp-scan-action@v1
  id: mcp

- name: Gate on risk
  if: steps.mcp.outputs.risk-level == 'critical'
  run: |
    echo "Critical findings detected — blocking deployment"
    exit 1

- name: Upload scan artifact
  uses: actions/upload-artifact@v4
  with:
    name: mcp-scan-sarif
    path: ${{ steps.mcp.outputs.sarif-file }}
```

---

## Scan on pull requests only

```yaml
on:
  pull_request:
    branches: [main]

jobs:
  mcp-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: nhomyk/mcp-scan-action@v1
        with:
          fail-on-critical: 'true'
          category: 'mcp-pr-scan'
```

---

## No API key required

All scanning is static analysis. The action never calls an LLM, never sends your code to an external service, and produces results deterministically.

---

## Powered by AgenticQA

This action wraps the [AgenticQA](https://github.com/nhomyk/AgenticQA) security scanners — a multi-agent CI/CD platform for AI-native teams that adds continuous security, compliance (EU AI Act, HIPAA, SOC 2), and self-healing test automation to your pipeline.

---

## License

MIT © [nhomyk](https://github.com/nhomyk)
