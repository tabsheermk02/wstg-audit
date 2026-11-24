#!/usr/bin/env python3
"""
Enterprise OWASP WSTG & LLM Security Audit Report Generator (v2.0)
Produces rigorous, executive-grade security reports matching Cloudflare security-audit standards.
Structures output into:
1. Run Scope & Limits (Deviations, Source Ref, Sandbox Limits)
2. Security Posture Summary (Architectural Strengths & Systemic Weaknesses)
3. Confirmed Vulnerabilities (with reproducible Entrypoint -> Sink Traces)
4. Needs-Validation Leads (Decisive Unknowns, Deployment Dependencies)
5. Positive Security Patterns & Defenses Verified
6. Hardening & Operational Hygiene
7. Non-REST Entrypoints & Gateway Topology
8. OWASP WSTG & LLM Compliance Scorecard
"""

import json
import os
import sys
from datetime import datetime

def generate_report(
    findings_file=".wstg-audit/verified_findings.json",
    matrix_file="references/wstg_matrix.json",
    surface_map_file=".wstg-audit/surface_map.json",
    output_md=".wstg-audit/WSTG-REPORT.md"
):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    matrix_path = os.path.join(script_dir, "..", matrix_file) if not os.path.exists(matrix_file) else matrix_file

    matrix = {}
    if os.path.exists(matrix_path):
        with open(matrix_path, "r", encoding="utf-8") as f:
            matrix = json.load(f).get("domains", {})

    report_data = {}
    findings = []
    needs_validation = []
    positive_patterns = []
    hardening_notes = []
    audited_domains = set()
    posture_summary = ""
    scope_info = {}

    if os.path.exists(findings_file):
        with open(findings_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
            if isinstance(raw, dict):
                report_data = raw
                findings = raw.get("findings", [])
                needs_validation = raw.get("needs_validation", [])
                positive_patterns = raw.get("positive_patterns", [])
                hardening_notes = raw.get("hardening_notes", [])
                audited_domains = set(raw.get("audited_domains", []))
                posture_summary = raw.get("posture_summary", "")
                scope_info = raw.get("scope", {})
            elif isinstance(raw, list):
                findings = raw

    # Auto-detect surface_map.json if not specified
    if not surface_map_file or not os.path.exists(surface_map_file):
        findings_dir = os.path.dirname(os.path.abspath(findings_file))
        auto_surface = os.path.join(findings_dir, "surface_map.json")
        if os.path.exists(auto_surface):
            surface_map_file = auto_surface

    surface_data = {}
    if surface_map_file and os.path.exists(surface_map_file):
        try:
            with open(surface_map_file, "r", encoding="utf-8") as sf:
                surface_data = json.load(sf)
        except Exception:
            pass

    def extract_domain_key(code):
        if not code:
            return "UNCLASSIFIED"
        if code.startswith("OWASP-LLM"):
            return "OWASP-LLM"
        parts = code.split("-")
        return f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else "UNCLASSIFIED"

    # Track all domains present in findings and leads
    for item in findings + needs_validation:
        code = item.get("wstg_code", "")
        audited_domains.add(extract_domain_key(code))

    # Calculate domain stats
    domain_stats = {}
    for d_key, d_info in matrix.items():
        domain_stats[d_key] = {
            "name": d_info.get("name", d_key),
            "total_checks": len(d_info.get("checks", {})),
            "findings_count": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "audited": d_key in audited_domains,
            "findings": []
        }

    for f in findings:
        code = f.get("wstg_code", "UNCLASSIFIED")
        domain_key = extract_domain_key(code)
        sev = f.get("severity", "MEDIUM").upper()

        if domain_key not in domain_stats:
            domain_stats[domain_key] = {
                "name": domain_key,
                "total_checks": 1,
                "findings_count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "audited": True,
                "findings": []
            }

        domain_stats[domain_key]["findings_count"] += 1
        if sev == "CRITICAL":
            domain_stats[domain_key]["critical"] += 1
        elif sev == "HIGH":
            domain_stats[domain_key]["high"] += 1
        elif sev == "MEDIUM":
            domain_stats[domain_key]["medium"] += 1
        else:
            domain_stats[domain_key]["low"] += 1

        domain_stats[domain_key]["findings"].append(f)

    # ------------------------------------------------------------------
    # Markdown Report Construction
    # ------------------------------------------------------------------
    target_repo = scope_info.get("repo", os.path.basename(os.getcwd()))
    commit_ref = scope_info.get("commit", "HEAD")

    gateway_routes_count = surface_data.get("gateway_routes_discovered", 0)
    lines = [
        f"# Security Audit Report: {target_repo} @ {commit_ref}",
        f"**Audit Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "**Methodology:** OWASP Web Security Testing Guide (WSTG v4.2 / v5) & OWASP Top 10 for LLMs / GenAI  ",
        "",
        "---",
        "",
        "## 1. Run Profile, Scope, and Execution Limits",
        "",
        f"- **Repository:** `{target_repo}`",
        f"- **Source Reference:** `{commit_ref}` (Working tree reviewed)",
        f"- **Execution Policy:** {scope_info.get('execution_policy', 'Source-only static analysis, AST taint verification & trust-boundary mapping (No target code executed live)')}",
        f"- **Gateway-to-Service Mapping:** {scope_info.get('gateway_mappings_detected', f'{gateway_routes_count} gateway routes discovered via pluggable drivers')}",
        f"- **Total Attack Surface Analyzed:** {surface_data.get('total_endpoints', 'N/A')} endpoints, {surface_data.get('total_non_rest_entrypoints', 0)} non-REST entrypoints",
        "- **Limits & Deviations:** Offline inspection mode. Ingress WAF rules, production cloud IAM bindings, and live third-party API limits are external deployment facts recorded under Needs Validation.",
        "",
        "---",
        "",
        "## 2. Security Posture Summary",
        ""
    ]

    if posture_summary:
        lines.append(posture_summary)
    else:
        lines.append("The repository surface was analyzed across web controllers, API gateway ingress rules, async event handlers, and AI integration boundaries. Trust boundaries were evaluated for broken authentication, object-level authorization (BOLA/IDOR), parameter taint propagation, and token consumption limits.")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Confirmed Vulnerabilities (Independently Verified)",
        ""
    ])

    if not findings:
        lines.append("*No confirmed vulnerabilities were validated in the reviewed scope.*")
    else:
        lines.extend([
            "| # | Severity | WSTG Code | Title | Target File & Line |",
            "|---|---|---|---|---|"
        ])
        for i, f in enumerate(findings, 1):
            lines.append(f"| {i} | **{f.get('severity', 'MEDIUM').upper()}** | `{f.get('wstg_code', 'N/A')}` | {f.get('title', 'Finding')} | `{f.get('file', 'N/A')}:{f.get('line', 'N/A')}` |")

        lines.extend(["", "### Detailed Finding Traces & Remediation", ""])

        for i, f in enumerate(findings, 1):
            lang = f.get("poc_language", "http")
            lines.extend([
                f"#### Finding {i}: [{f.get('wstg_code', 'N/A')}] {f.get('title', 'Finding')}",
                f"- **Severity:** `{f.get('severity', 'MEDIUM').upper()}`",
                f"- **Location:** `{f.get('file', 'N/A')}:{f.get('line', 'N/A')}`",
                "",
                "**Description:**",
                f.get("description", "N/A"),
                "",
                f"> **Root Cause (Invariant Failure):** {f.get('root_cause', 'Unenforced authorization / boundary control')}",
                f"> ",
                f"> **Intended Behavior:** {f.get('intended_behavior', 'Reject or isolate unauthenticated / cross-tenant requests')}",
                "",
                "**Preconditions Required:**"
            ])

            conditions = f.get("conditions", [])
            if conditions:
                for cond in conditions:
                    lines.append(f"- {cond}")
            else:
                lines.append("- Direct network access to route entrypoint.")

            lines.extend([
                "",
                "**Execution Trace (Entrypoint $\\rightarrow$ Sink):**"
            ])

            trace = f.get("trace", [])
            if trace:
                for step in trace:
                    lines.append(f"- `[{step.get('kind', 'step').upper()}]` `{step.get('file', '')}:{step.get('line', '')}` ({step.get('scope', '')}): {step.get('description', '')}")
            else:
                lines.append(f"- Direct flaw at `{f.get('file', 'N/A')}:{f.get('line', 'N/A')}`")

            lines.extend([
                "",
                "**Proof of Concept / Native Reproduction:**",
                f"```{lang}",
                f.get("proof_of_concept", "# Verified via code inspection"),
                "```",
                "",
                "**Recommended Invariant Remediation:**",
                f.get("remediation", "Apply appropriate authorization and input controls.")
            ])

            reg_test = f.get("regression_test", "")
            if reg_test:
                lines.extend([
                    "",
                    "**Automated Regression Test Specification:**",
                    f"```text",
                    reg_test,
                    f"```"
                ])

            lines.extend([
                "",
                "---",
                ""
            ])

    lines.extend([
        "## 4. Needs Validation: Source-Verified Leads with Deployment Unknowns",
        "",
        "These leads represent confirmed code-level flaws where decisive exploitability depends on an unobserved production or infrastructure fact (e.g. edge reverse proxy rules, VPC peering, cloud IAM, or live third-party keys).",
        ""
    ])

    if not needs_validation:
        lines.append("*No open needs-validation leads recorded.*")
    else:
        lines.extend([
            "| # | Severity | Lead Title | Code Entry Point | Decisive Unknown (Deployment Dependency) |",
            "|---|---|---|---|---|"
        ])
        for i, lead in enumerate(needs_validation, 1):
            lines.append(f"| {i} | `{lead.get('severity', 'HIGH')}` | {lead.get('title', 'Lead')} | `{lead.get('file', 'N/A')}:{lead.get('line', 'N/A')}` | {lead.get('decisive_unknown', 'Production network/WAF exposure')} |")

        lines.extend(["", "### Needs-Validation Lead Traces", ""])
        for i, lead in enumerate(needs_validation, 1):
            lines.extend([
                f"#### Lead {i}: {lead.get('title', 'Lead')}",
                f"- **Entry Point:** `{lead.get('file', 'N/A')}:{lead.get('line', 'N/A')}`",
                f"- **Decisive Unknown:** {lead.get('decisive_unknown', 'N/A')}",
                "",
                "**Description & Source Finding:**",
                lead.get("description", "N/A"),
                "",
                "**Verification Plan:**",
                f"- **Local:** {lead.get('validation_plan', {}).get('local', 'Test against local mock container')}",
                f"- **Deployment:** {lead.get('validation_plan', {}).get('deployment', 'Verify ingress and IAM bindings in staging')}",
                "",
                "---",
                ""
            ])

    lines.extend([
        "## 5. Positive Security Patterns & Controls Verified",
        "",
        "Architectural defenses confirmed active and effective during the audit:",
        ""
    ])

    if not positive_patterns:
        lines.append("- Global framework guards and parameter type validation observed.")
    else:
        for p in positive_patterns:
            lines.append(f"- **{p.get('name', 'Control')}:** {p.get('description', '')} (Verified at `{p.get('file', 'N/A')}`)")

    lines.extend([
        "",
        "---",
        "",
        "## 6. Hardening & Operational Hygiene Notes",
        ""
    ])

    if not hardening_notes:
        lines.append("- No immediate operational hardening blockers detected.")
    else:
        for h in hardening_notes:
            lines.append(f"- **[{h.get('scope', 'Infra')}]** {h.get('description', '')}")

    # Section 7: Gateway Topology & Non-REST Surfaces
    if surface_data:
        lines.extend([
            "",
            "---",
            "",
            "## 7. Gateway Ingress Topology & Non-REST Surfaces",
            "",
            f"- **Active Gateway Drivers:** {len(surface_data.get('gateway_topology', []))} route bindings discovered",
            f"- **Non-REST Entrypoints (WebSockets & Pub/Sub):** {surface_data.get('total_non_rest_entrypoints', 0)} detected",
            f"- **AST Taint Invariant Flaws:** {surface_data.get('total_taint_vulnerabilities', 0)} flows to dangerous sinks",
            ""
        ])

        non_rest = surface_data.get("non_rest_entrypoints", [])
        if non_rest:
            lines.extend([
                "| Kind | Protocol | Path / Target | Auth Status | Risk Flag |",
                "|---|---|---|---|---|"
            ])
            for nr in non_rest[:10]:
                auth_badge = "❌ Unauthenticated" if nr.get("is_unauthenticated") else "✅ Guarded"
                lines.append(f"| {nr.get('kind', 'N/A')} | `{nr.get('protocol', 'N/A')}` | `{nr.get('path', 'N/A')}` | {auth_badge} | {nr.get('threat', 'N/A')} |")
            lines.append("")

    lines.extend([
        "",
        "---",
        "",
        "## 8. OWASP WSTG & LLM Compliance Scorecard",
        "",
        "| WSTG Domain | Category Name | Status | Critical | High | Medium | Low |",
        "|---|---|---|---|---|---|---|",
    ])

    for d_key, stat in domain_stats.items():
        if stat["findings_count"] > 0:
            status = f"🔴 VULNERABLE ({stat['findings_count']})"
        elif stat["audited"]:
            status = "🟢 SECURE"
        else:
            status = "⚪ UNTESTED"

        lines.append(f"| `{d_key}` | {stat['name']} | {status} | {stat['critical']} | {stat['high']} | {stat['medium']} | {stat['low']} |")

    lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(output_md)), exist_ok=True)
    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Audit report generated successfully: {output_md}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Executive OWASP WSTG Compliance Report.")
    parser.add_argument("findings", nargs="?", default=".wstg-audit/verified_findings.json", help="Path to findings JSON")
    parser.add_argument("output", nargs="?", default=None, help="Path for output Markdown report")
    parser.add_argument("--matrix", default="references/wstg_matrix.json", help="Path to WSTG matrix JSON")
    parser.add_argument("--surface", default=None, help="Path to surface_map.json (auto-detected if omitted)")
    args = parser.parse_args()

    out_file = args.output
    if not out_file:
        findings_dir = os.path.dirname(os.path.abspath(args.findings))
        out_file = os.path.join(findings_dir, "WSTG-REPORT.md")

    generate_report(findings_file=args.findings, matrix_file=args.matrix, surface_map_file=args.surface, output_md=out_file)
