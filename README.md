# mcp-scan-action

<div align="center">

### The first GitHub Action that scans MCP servers, AI agents, and LLM pipelines for security vulnerabilities — and sends results directly to your GitHub Security tab.

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-mcp--scan--action-blue?logo=github&logoColor=white&style=for-the-badge)](https://github.com/marketplace/actions/mcp-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![SARIF](https://img.shields.io/badge/Output-SARIF%202.1.0-orange?style=for-the-badge)](https://sarifweb.azurewebsites.net/)
[![No API Key](https://img.shields.io/badge/API%20Key-Not%20Required-brightgreen?style=for-the-badge)](#no-api-key-required)

**24 vulnerability checks. 4 scan engines. Zero runtime cost. One line of YAML.**

</div>

---

## Why This Exists

MCP is moving fast. Thousands of servers are being built to give AI agents access to browsers, filesystems, APIs, and internal services. **Almost none of them are being scanned for security vulnerabilities before they ship.**

We scanned 5 popular open-source MCP servers. **All 5 had findings:**

| Repo Type | Risk Score | Top Finding | Severity |
|-----------|-----------|-------------|----------|
| Browser automation MCP | **1.000 (Critical)** | Arbitrary JS execution via `playwright_evaluate` | CVSS 9.8 |
| Productivity API connector | 0.390 | Auth token logged to stdout | High |
| Browser vendor DevTools MCP | 0.080 | Full environment cloned to child process | High |
| Vector DB Claude plugin | 0.150 | Unpinned `npx -y` supply chain risk | Medium |
| Search MCP server | 0.200 | SSRF via unvalidated URL parameter | High |

> A browser automation MCP with 33 registered tools exposes a `playwright_evaluate` tool that accepts raw JavaScript from the LLM — no validation, no sandboxing. That's **remote code execution (CVSS 9.8)** controlled by any prompt-injected agent. This action would have caught it before the first commit landed on `main`.

This action brings automated, continuous MCP security scanning to every team building on the Model Context Protocol — with zero configuration and no API key.

---

## Quickstart — One Line

```yaml
- uses: nhomyk/mcp-scan-action@v1
```

Add it to any job that checks out your code. That's it.

---

## Full Workflow

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  mcp-security:
    name: MCP Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # upload findings to GitHub Security tab
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: nhomyk/mcp-scan-action@v1
        id: scan
        with:
          fail-on-critical: 'true'   # block merges on critical findings

      - name: Show risk level
        run: echo "Risk → ${{ steps.scan.outputs.risk-level }}"
```

Findings appear immediately under **Security → Code scanning alerts.**

---

## What It Detects — 24 Vulnerability Classes

### MCP Tool Poisoning (11 attack types)

| Attack Type | What It Finds | Real-World Example |
|-------------|---------------|-------------------|
| `TOOL_POISONING` | Tool descriptions/schemas that manipulate LLM behavior | Hidden instructions in tool metadata |
| `EXFILTRATION_PATTERN` | Data routed to unexpected external endpoints | Credentials forwarded to attacker-controlled URL |
| `PROMPT_INJECTION_VECTOR` | User-controlled data concatenated unsafely into prompts | `f"Summarize: {user_input}"` without sanitization |
| `AMBIENT_AUTHORITY` | Tools with implicit permissions beyond declared scope | `Object.entries(process.env)` cloned to child process |
| `UNRESTRICTED_FILE_ACCESS` | Filesystem access without path sanitization | Path traversal via `../../../etc/passwd` |
| `SSRF_RISK` | Server-side request forgery via tool-controlled URLs | `args.url` passed to `fetch()` without domain allowlist |
| `COMMAND_INJECTION` | Shell commands constructed from LLM/user input | `exec("ls " + args.directory)` |
| `MISSING_AUTH` | Authenticated actions reachable without credential checks | Tool handler missing token validation |
| `UNCONSTRAINED_SCOPE` | Agents with no permission boundaries | Agent with read+write+execute on arbitrary paths |
| `CROSS_ORIGIN_ESCALATION` | Cross-agent trust boundary violations | Agent A forwarding unvalidated output to Agent B |
| `SHADOW_TOOL` | Hidden tool registrations not visible to user | Tools registered without appearing in tool list |

### Cross-Agent DataFlow Taint (9 finding types)

Tracks secrets and PII from **source to sink** across agent boundaries:

```
SECRET_SOURCE (line 87): authToken = randomBytes(32).toString('hex')
        │
        ▼ [UNSANITIZED]
SINK_LOGGING (line 89): console.log(`Generated auth token: ${authToken}`)
                                     ↑
                          DataFlow risk: 1.000  ← caught by this action
```

`SECRET_SOURCE` · `PII_SOURCE` · `CROSS_BOUNDARY` · `SINK_LOGGING` · `SINK_NETWORK` · `SINK_STORAGE` · `TAINT_PROPAGATION` · `MISSING_SANITIZE` · `PRIVILEGE_ESCALATION`

### Prompt Injection (4 patterns)

| Pattern | Example |
|---------|---------|
| Direct concatenation | `prompt = "Answer: " + user_message` |
| Template injection | `f"You are helpful. {system_prompt}"` with user-controlled `system_prompt` |
| Unsafe LLM output | LLM response passed to `eval()` or `exec()` without validation |
| Role override | User input that can override system role context |

### Architecture Analysis (MCP/Agent integration points)

Static mapping of all `MCP_TOOL`, `AGENT_FRAMEWORK`, `SHELL_EXEC`, and `EXTERNAL_HTTP` integration areas — gives you a complete picture of your agent's attack surface before manual review.

---

## Output — GitHub Security Tab

Findings upload as **SARIF 2.1.0** directly to your repository's **Security → Code scanning** page. No third-party dashboard, no account required, no data leaves GitHub.

```
┌─────────────────────────────────────────────────────────────────┐
│  Security  /  Code scanning alerts                               │
│                                                                  │
│  ● SSRF_RISK          High     src/tools/requests.ts:99         │
│  ● AMBIENT_AUTHORITY  High     scripts/eval_gemini.ts:115       │
│  ● SINK_LOGGING       High     scripts/start-server.ts:89       │
│  ● SHADOW_TOOL        Medium   src/registry.ts:44               │
│                                                                  │
│  4 open alerts  ·  Powered by AgenticQA MCP Scanner             │
└─────────────────────────────────────────────────────────────────┘
```

Each alert includes: file path, line number, severity, CWE class, and remediation guidance.

---

## Step Summary

After every run, a formatted summary appears in your workflow's **Summary** tab:

```
🔴 MCP Security Scan — CRITICAL

Total findings: 7 | Critical: 2

| Scanner                | Findings | Critical | Types Detected                          |
|------------------------|----------|----------|-----------------------------------------|
| MCP Tool Scan          | 3        | 1        | SSRF_RISK, COMMAND_INJECTION, SHADOW_TOOL |
| DataFlow Taint         | 2        | 1        | SECRET_SOURCE, SINK_LOGGING             |
| Prompt Injection       | 1        | 0        |                                         |
| Architecture (MCP/Agent)| 1       | 0        | AGENT_FRAMEWORK                         |
```

---

## Use Outputs in Downstream Steps

```yaml
- uses: nhomyk/mcp-scan-action@v1
  id: mcp

# Gate deployment on risk level
- name: Block on critical
  if: steps.mcp.outputs.risk-level == 'critical'
  run: |
    echo "❌ ${{ steps.mcp.outputs.critical-count }} critical finding(s) — deploy blocked"
    exit 1

# Save SARIF as workflow artifact
- name: Upload scan artifact
  uses: actions/upload-artifact@v4
  with:
    name: mcp-scan-sarif
    path: ${{ steps.mcp.outputs.sarif-file }}

# Post finding count to Slack/webhook
- name: Notify
  run: |
    curl -X POST $SLACK_WEBHOOK \
      -d "{\"text\": \"MCP scan: ${{ steps.mcp.outputs.findings-count }} findings, risk=${{ steps.mcp.outputs.risk-level }}\"}"
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `repo-path` | `.` | Path to the repository root to scan |
| `fail-on-critical` | `false` | Exit code 1 if any critical findings exist |
| `sarif-output` | `mcp-scan-results.sarif` | SARIF output filename |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning (`security-events: write` required) |
| `category` | `mcp-security` | SARIF category — useful when running multiple scan jobs |

## Outputs

| Output | Values | Description |
|--------|--------|-------------|
| `findings-count` | integer | Total findings across all 4 scan engines |
| `risk-level` | `low` · `medium` · `high` · `critical` | Overall risk classification |
| `critical-count` | integer | Number of critical-severity findings |
| `sarif-file` | path | Location of the generated SARIF file |

---

## PR-Only Scan

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

## Cost Savings

| Without this action | With this action |
|---------------------|-----------------|
| Manual security review: ~40 hrs × $200/hr = **$8,000 per review cycle** | $0 — runs on every push |
| Average cost of a data breach: **$4.88M** (IBM 2024) | Catch credential leaks before they reach production |
| Security consultant for MCP audit: **$15,000–$50,000** | Automated, continuous, deterministic |
| Finding a bug in production: **6× more expensive** than finding it in CI | Shift-left: block the merge, not the incident |

> Static analysis catches an entire class of bugs — SSRF, command injection, credential logging — that are trivial to prevent and catastrophic to miss. Automating the check costs zero.

---

## No API Key Required

All scanning is **pure static analysis.** The action:

- Never calls an LLM
- Never sends your code to an external service
- Produces results deterministically — same code, same findings, every run
- Works entirely within your GitHub Actions runner

---

## Languages and Frameworks Supported

Detects MCP and agent patterns in:

| Language | Frameworks / Patterns |
|----------|-----------------------|
| **TypeScript / JavaScript** | `@modelcontextprotocol/sdk`, LangChain.js, AutoGen JS, direct `fetch()` calls |
| **Python** | `langchain`, `langgraph`, `crewai`, `autogen`, `anthropic`, `openai` SDK |
| **JSON** | `mcp*.json` config files — tool registrations, `npx -y` supply chain risk |
| **Any** | Architecture analysis runs on all supported languages |

---

## How It Works

```
Your repo
    │
    ├── MCPSecurityScanner     → 11 attack types via pattern matching + tool schema analysis
    │                            Learned patterns accumulate from real findings
    │
    ├── CrossAgentDataFlowTracer → 9 taint finding types
    │                              Tracks SECRET/PII from source → sink across agent calls
    │
    ├── PromptInjectionScanner → 4 injection patterns
    │                            Direct concat · Template · Unsafe output · Role override
    │
    └── ArchitectureScanner    → Maps all MCP_TOOL + AGENT_FRAMEWORK integration points
                                 Full attack surface visibility before manual review
                                        │
                                        ▼
                               SARIFExporter (2.1.0)
                                        │
                                        ▼
                        GitHub Security → Code scanning alerts
```

---

## Powered by AgenticQA

This action wraps the security scanners from **[AgenticQA](https://github.com/nhomyk/AgenticQA)** — an open-source autonomous CI/CD platform for AI-native teams.

AgenticQA adds to your pipeline:
- **Continuous MCP security scanning** (this action)
- **EU AI Act compliance** — Annex III classification + Articles 9, 13, 14, 22
- **HIPAA PHI detection** — 5 PHI taint categories across your codebase
- **Self-healing CI** — SRE agent auto-fixes lint errors and test failures
- **Adversarial hardening** — Red Team agent with 20 bypass techniques + constitutional gate
- **SOC 2 / GDPR** — 7 compliance scanners, SARIF-exportable evidence

[Explore AgenticQA →](https://github.com/nhomyk/AgenticQA)

---

## License

MIT © [nhomyk](https://github.com/nhomyk)
