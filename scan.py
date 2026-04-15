#!/usr/bin/env python3
"""
AgenticQA MCP Security Scanner
Scans for MCP tool poisoning, SSRF, DataFlow taint, and prompt injection.
https://github.com/nhomyk/mcp-scan-action
"""
import json
import os
import sys
from pathlib import Path

MINIMAL_SARIF = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "AgenticQA MCP Scanner",
                "version": "1.0.0",
                "informationUri": "https://github.com/nhomyk/mcp-scan-action",
                "rules": []
            }
        },
        "results": []
    }]
}

def _safe_path(env_var: str, default: str, must_exist: bool = False) -> str:
    """Resolve env var to a real path, preventing path traversal (CWE-22)."""
    raw = os.environ.get(env_var, default)
    resolved = os.path.realpath(raw)
    if must_exist and not os.path.exists(resolved):
        print(f"Warning: {env_var}={raw} does not exist, using default", file=sys.stderr)
        resolved = os.path.realpath(default)
    return resolved

repo_path = _safe_path('SCAN_REPO_PATH', '.', must_exist=True)
sarif_output = _safe_path('SARIF_OUTPUT', 'mcp-scan-results.sarif')
fail_on_critical = os.environ.get('FAIL_ON_CRITICAL', 'false').lower() == 'true'

total_findings = 0
critical_count = 0
# risk_level is assigned after scans run (line ~182); no default needed.
scan_results = []

mcp_output = None
dataflow_output = None
arch_mcp_findings = []

# ── Helper ─────────────────────────────────────────────────────────────────────
def _src_path(base: str) -> str:
    """Return base/src if it exists, otherwise base."""
    candidate = Path(base) / 'src'
    return str(candidate) if candidate.exists() else base


def _to_dict(obj):
    """Convert scan result object to dict."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    return vars(obj)


# ── 1. MCP Security Scan ───────────────────────────────────────────────────────
print("🔍 Running MCP Security Scan...")
try:
    from agenticqa.security.mcp_scanner import MCPSecurityScanner
    result = MCPSecurityScanner().scan(_src_path(repo_path))
    mcp_output = _to_dict(result)

    n = mcp_output.get('findings', 0)
    c = mcp_output.get('critical_count', 0)
    risk = mcp_output.get('risk_score', 0.0)
    total_findings += n
    critical_count += c
    attack_types = mcp_output.get('attack_types', [])

    print(f"   {n} finding(s) | {c} critical | risk_score={risk:.2f}")
    if attack_types:
        print(f"   Attack types: {', '.join(attack_types[:6])}")
    scan_results.append({'name': 'MCP Tool Scan', 'findings': n, 'critical': c, 'types': attack_types})

except ImportError as e:
    print(f"   MCPSecurityScanner not available: {e}", file=sys.stderr)
    scan_results.append({'name': 'MCP Tool Scan', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})
except Exception as e:
    print(f"   MCP scan error: {e}", file=sys.stderr)
    scan_results.append({'name': 'MCP Tool Scan', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})


# ── 2. DataFlow Taint Analysis ─────────────────────────────────────────────────
print("🔍 Running DataFlow Taint Analysis...")
try:
    from agenticqa.security.data_flow_tracer import CrossAgentDataFlowTracer
    result = CrossAgentDataFlowTracer().trace(_src_path(repo_path))
    dataflow_output = _to_dict(result)

    n = dataflow_output.get('findings', 0)
    c = dataflow_output.get('critical_count', 0)
    risk = dataflow_output.get('risk_score', 0.0)
    total_findings += n
    critical_count += c
    finding_types = dataflow_output.get('finding_types', [])

    print(f"   {n} finding(s) | {c} critical | risk_score={risk:.2f}")
    if finding_types:
        print(f"   Finding types: {', '.join(finding_types[:6])}")
    scan_results.append({'name': 'DataFlow Taint', 'findings': n, 'critical': c, 'types': finding_types})

except ImportError as e:
    print(f"   CrossAgentDataFlowTracer not available: {e}", file=sys.stderr)
    scan_results.append({'name': 'DataFlow Taint', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})
except Exception as e:
    print(f"   DataFlow scan error: {e}", file=sys.stderr)
    scan_results.append({'name': 'DataFlow Taint', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})


# ── 3. Prompt Injection Scan ───────────────────────────────────────────────────
print("🔍 Running Prompt Injection Scan...")
try:
    from agenticqa.security.prompt_injection_scanner import PromptInjectionScanner
    result = PromptInjectionScanner().scan(repo_path)
    pi_dict = _to_dict(result)

    details = pi_dict.get('finding_details', [])
    n = pi_dict.get('total_findings', 0) or pi_dict.get('findings', 0) or len(details)
    c = pi_dict.get('critical_count', 0) or sum(
        1 for d in details if d.get('severity') == 'critical'
    )
    total_findings += n
    critical_count += c

    print(f"   {n} finding(s) | {c} critical")
    scan_results.append({'name': 'Prompt Injection', 'findings': n, 'critical': c, 'types': []})

except ImportError as e:
    print(f"   PromptInjectionScanner not available: {e}", file=sys.stderr)
    scan_results.append({'name': 'Prompt Injection', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})
except Exception as e:
    print(f"   Prompt injection scan error: {e}", file=sys.stderr)
    scan_results.append({'name': 'Prompt Injection', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})


# ── 4. Architecture Scan — MCP_TOOL + AGENT_FRAMEWORK focus ───────────────────
print("🔍 Running Architecture Scan (MCP_TOOL + AGENT_FRAMEWORK)...")
try:
    from agenticqa.security.architecture_scanner import ArchitectureScanner
    arch_result = ArchitectureScanner().scan(repo_path)
    areas = getattr(arch_result, 'integration_areas', []) or []

    MCP_CATEGORIES = {'MCP_TOOL', 'AGENT_FRAMEWORK', 'SHELL_EXEC', 'EXTERNAL_HTTP'}
    for area in areas:
        if getattr(area, 'category', '') in MCP_CATEGORIES:
            arch_mcp_findings.append({
                'type': getattr(area, 'category', 'UNKNOWN'),
                'severity': getattr(area, 'severity', 'medium'),
                'file': getattr(area, 'source_file', ''),
                'line': getattr(area, 'line_number', 1),
                'desc': str(getattr(area, 'plain_english', '') or
                            getattr(area, 'evidence', ''))[:120],
            })

    n = len(arch_mcp_findings)
    c = sum(1 for f in arch_mcp_findings if f['severity'] == 'critical')
    total_findings += n
    critical_count += c

    print(f"   {n} MCP/agent area(s) flagged | {c} critical")
    scan_results.append({'name': 'Architecture (MCP/Agent)', 'findings': n, 'critical': c, 'types': []})

except ImportError as e:
    print(f"   ArchitectureScanner not available: {e}", file=sys.stderr)
    scan_results.append({'name': 'Architecture (MCP/Agent)', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})
except Exception as e:
    print(f"   Architecture scan error: {e}", file=sys.stderr)
    scan_results.append({'name': 'Architecture (MCP/Agent)', 'findings': 0, 'critical': 0, 'types': [], 'error': str(e)})


# ── Determine overall risk level ───────────────────────────────────────────────
if critical_count > 0:
    risk_level = 'critical'
elif total_findings > 20:
    risk_level = 'high'
elif total_findings > 5:
    risk_level = 'medium'
else:
    risk_level = 'low'

print(f"\n📊 Total: {total_findings} finding(s) | {critical_count} critical | Risk: {risk_level.upper()}")


# ── 5. Export to SARIF ─────────────────────────────────────────────────────────
print(f"📄 Writing SARIF → {sarif_output}")
sarif_count = 0
try:
    from agenticqa.export.sarif import SARIFExporter
    exporter = SARIFExporter(repo_root=repo_path)

    if mcp_output:
        sarif_count += exporter.add_mcp_result(mcp_output)
    if dataflow_output:
        sarif_count += exporter.add_dataflow_result(dataflow_output)

    sev_map = {'critical': 'error', 'high': 'warning', 'medium': 'warning', 'low': 'note'}
    for f in arch_mcp_findings:
        exporter._add(
            f'ARCH_{f["type"]}',
            f['desc'] or f'{f["type"]} integration point',
            f['file'], f['line'],
            severity=sev_map.get(f['severity'], 'note'),
            rule_desc=f'Architecture: {f["type"]}',
        )
        sarif_count += 1

    exporter.write(sarif_output)
    print(f"   {sarif_count} finding(s) in SARIF")

except Exception as e:
    print(f"   SARIF export error ({e}) — writing fallback", file=sys.stderr)
    with open(sarif_output, 'w') as fh:
        json.dump(MINIMAL_SARIF, fh)


# ── 6. Write GitHub Actions step summary ──────────────────────────────────────
summary_file = os.path.realpath(os.environ.get('GITHUB_STEP_SUMMARY', ''))
if os.environ.get('GITHUB_STEP_SUMMARY', ''):
    risk_icon = {'low': '🟢', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}.get(risk_level, '⚪')
    lines = [
        f'## {risk_icon} MCP Security Scan — {risk_level.upper()}',
        '',
        f'**Total findings:** {total_findings} &nbsp;|&nbsp; **Critical:** {critical_count}',
        '',
    ]

    if critical_count > 0:
        lines += [f'> ⚠️ **{critical_count} critical finding(s) detected** — review before shipping', '']

    lines += [
        '| Scanner | Findings | Critical | Types Detected |',
        '|---------|----------|----------|----------------|',
    ]
    for r in scan_results:
        err = r.get('error', '')
        types_str = ', '.join(r.get('types', [])[:4]) or ('⚠️ unavailable' if err else '—')
        lines.append(f'| {r["name"]} | {r["findings"]} | {r["critical"]} | {types_str} |')

    footer = (
        '*Powered by AgenticQA MCP Scanner · '
        '[mcp-scan-action](https://github.com/nhomyk/mcp-scan-action)*'
    )
    lines += ['', footer]

    with open(summary_file, 'a') as fh:
        fh.write('\n'.join(lines) + '\n')


# ── 7. Write GitHub output variables ──────────────────────────────────────────
github_output = os.path.realpath(os.environ.get('GITHUB_OUTPUT', ''))
if os.environ.get('GITHUB_OUTPUT', ''):
    with open(github_output, 'a') as fh:
        fh.write(f'findings_count={total_findings}\n')
        fh.write(f'risk_level={risk_level}\n')
        fh.write(f'critical_count={critical_count}\n')


# ── 8. Exit code ───────────────────────────────────────────────────────────────
if fail_on_critical and critical_count > 0:
    print(f'\n❌ Failing: {critical_count} critical finding(s) and fail-on-critical=true')
    sys.exit(1)

print('\n✅ MCP scan complete')
