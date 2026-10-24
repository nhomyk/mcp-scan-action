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


def _get(obj, key, default=None):
    """Read a field from a dict or an object (dataclass, property) alike."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def summarize(result, *, type_key, desc_key, file_key, line_key):
    """Turn a scanner result into one dict with an INTEGER finding count.

    The engines return dataclasses whose ``findings`` field is a LIST of finding
    objects (the count is a ``total_findings`` property). The previous code
    treated ``findings`` as a number, so ``total_findings += <list>`` raised a
    TypeError that the broad ``except`` swallowed: every MCP, DataFlow and
    Prompt Injection finding was discarded and the scan reported 0. This reads
    both shapes and always returns ``findings`` as an int, plus per-finding
    ``finding_details`` in the shape the SARIF exporter ingests.
    """
    raw = _get(result, 'findings', []) or []
    error = _get(result, 'scan_error')
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        # Already-summarized dict shape: {"findings": <int>, "finding_details": [...]}
        details = list(_get(result, 'finding_details', []) or [])
        count = int(raw)
    else:
        items = list(raw)
        details = [{
            'type': str(_get(f, type_key, '') or 'UNKNOWN'),
            'desc': str(_get(f, desc_key, '') or ''),
            'file': str(_get(f, file_key, '') or ''),
            'line': int(_get(f, line_key, 0) or 1),
            'severity': str(_get(f, 'severity', 'medium') or 'medium').lower(),
        } for f in items]
        count = len(items)
    critical = sum(1 for d in details if d.get('severity') == 'critical')
    types = sorted({d['type'] for d in details if d.get('type')})
    return {
        'findings': count,
        'critical_count': critical,
        'risk_score': float(_get(result, 'risk_score', 0.0) or 0.0),
        'finding_details': details,
        'attack_types': types,
        'finding_types': types,
        'scan_error': str(error) if error else None,
    }


def _record(name: str, out: dict) -> None:
    global total_findings, critical_count
    total_findings += out['findings']
    critical_count += out['critical_count']
    print(f"   {out['findings']} finding(s) | {out['critical_count']} critical | risk_score={out['risk_score']:.2f}")
    if out['attack_types']:
        print(f"   Types: {', '.join(out['attack_types'][:6])}")
    entry = {'name': name, 'findings': out['findings'], 'critical': out['critical_count'], 'types': out['attack_types']}
    if out['scan_error']:
        entry['error'] = out['scan_error']
        scanner_errors.append(f"{name}: {out['scan_error']}")
        print(f"   {name} reported a scan error: {out['scan_error']}", file=sys.stderr)
    scan_results.append(entry)


def _failed(name: str, exc: Exception) -> None:
    """A scanner that could not run is an error, never a silent zero."""
    msg = f"{type(exc).__name__}: {exc}"
    print(f"   {name} failed: {msg}", file=sys.stderr)
    scanner_errors.append(f"{name}: {msg}")
    scan_results.append({'name': name, 'findings': 0, 'critical': 0, 'types': [], 'error': msg})


scanner_errors = []
pi_output = None
per_scanner = {}


# ── 1. MCP Security Scan ───────────────────────────────────────────────────────
print("🔍 Running MCP Security Scan...")
try:
    from agenticqa.security.mcp_scanner import MCPSecurityScanner
    mcp_output = summarize(MCPSecurityScanner().scan(_src_path(repo_path)),
                           type_key='attack_type', desc_key='description',
                           file_key='source_file', line_key='line_number')
    _record('MCP Tool Scan', mcp_output)
    per_scanner['mcp'] = mcp_output['findings']
except Exception as e:  # noqa: BLE001 - reported as an error and fails the run
    mcp_output = None
    _failed('MCP Tool Scan', e)


# ── 2. DataFlow Taint Analysis ─────────────────────────────────────────────────
print("🔍 Running DataFlow Taint Analysis...")
try:
    from agenticqa.security.data_flow_tracer import CrossAgentDataFlowTracer
    dataflow_output = summarize(CrossAgentDataFlowTracer().trace(_src_path(repo_path)),
                                type_key='finding_type', desc_key='description',
                                file_key='source_file', line_key='line_number')
    _record('DataFlow Taint', dataflow_output)
    per_scanner['dataflow'] = dataflow_output['findings']
except Exception as e:  # noqa: BLE001
    dataflow_output = None
    _failed('DataFlow Taint', e)


# ── 3. Prompt Injection Scan ───────────────────────────────────────────────────
print("🔍 Running Prompt Injection Scan...")
try:
    from agenticqa.security.prompt_injection_scanner import PromptInjectionScanner
    pi_output = summarize(PromptInjectionScanner().scan(repo_path),
                          type_key='rule_id', desc_key='message',
                          file_key='file', line_key='line')
    _record('Prompt Injection', pi_output)
    per_scanner['prompt_injection'] = pi_output['findings']
except Exception as e:  # noqa: BLE001
    pi_output = None
    _failed('Prompt Injection', e)


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
    per_scanner['architecture'] = n

    print(f"   {n} MCP/agent area(s) flagged | {c} critical")
    scan_results.append({'name': 'Architecture (MCP/Agent)', 'findings': n, 'critical': c, 'types': []})

except Exception as e:  # noqa: BLE001
    _failed('Architecture (MCP/Agent)', e)


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
    for d in (pi_output or {}).get('finding_details', []):
        exporter._add(
            f'PI_{d["type"]}',
            d['desc'] or d['type'],
            d['file'] or 'src', d['line'],
            severity=sev_map.get(d['severity'], 'note'),
            rule_desc=f'Prompt Injection: {d["type"]}',
        )
        sarif_count += 1
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
    scanner_errors.append(f"SARIF export: {type(e).__name__}: {e}")
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
        fh.write(f'mcp_count={per_scanner.get("mcp", 0)}\n')
        fh.write(f'dataflow_count={per_scanner.get("dataflow", 0)}\n')
        fh.write(f'prompt_injection_count={per_scanner.get("prompt_injection", 0)}\n')
        fh.write(f'architecture_count={per_scanner.get("architecture", 0)}\n')
        fh.write(f'scanner_errors={len(scanner_errors)}\n')


# ── 8. Exit code ───────────────────────────────────────────────────────────────
if scanner_errors:
    # Fail closed: a scanner that crashed has not shown the code is clean, and
    # reporting its silence as "0 findings" is how this action hid every MCP,
    # DataFlow and Prompt Injection finding behind a swallowed TypeError.
    for err in scanner_errors:
        print(f'::error title=mcp-scan-action scanner error::{err}')
    print(f'\n❌ Failing: {len(scanner_errors)} scanner(s) did not complete')
    sys.exit(2)

if fail_on_critical and critical_count > 0:
    print(f'\n❌ Failing: {critical_count} critical finding(s) and fail-on-critical=true')
    sys.exit(1)

print('\n✅ MCP scan complete')
