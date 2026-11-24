#!/usr/bin/env python3
"""
Automated Invariant Critic Engine (CRITIC_MODE / Red-Team vs Blue-Team Protocol)
Zero External Dependencies (Python Standard Library Only)

Mandate:
Disprove candidate security vulnerabilities by actively hunting for mitigating
controls across 5 defense vectors:
1. Upstream Gateway & Reverse Proxy Rewrites
2. Pipeline Middlewares & Request Interceptors
3. Framework DTO, Schema & Type Boundaries
4. Data Layer, ORM & Persistence Constraints
5. Intra-Procedural Invariants & Downstream Authorization

Usage:
    python scripts/run_critic.py <target_repo> [.wstg-audit/verified_findings.json] [--apply-verdicts]
"""

import argparse
import ast
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ======================================================================
# 1. FALSIFICATION DETECTORS ACROSS THE 5 DEFENSE VECTORS
# ======================================================================

class FalsificationResult:
    def __init__(self, vector_name: str):
        self.vector_name = vector_name
        self.mitigating_control_found = False
        self.evidence_file: Optional[str] = None
        self.evidence_line: Optional[int] = None
        self.details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector": self.vector_name,
            "status": "PASSED_DEFENSE" if self.mitigating_control_found else "FAILED_TO_REFUTE",
            "evidence_file": self.evidence_file,
            "evidence_line": self.evidence_line,
            "details": self.details
        }


def evaluate_vector_1_gateway(repo_dir: str, finding: Dict[str, Any]) -> FalsificationResult:
    """Vector 1: Upstream Gateway & Reverse Proxy Rewrites"""
    res = FalsificationResult("Vector 1: Upstream Gateway & Reverse Proxy Rewrites")
    file_rel = finding.get("file", "").replace("\\", "/")
    
    # 1. Search for gateway configuration files
    gateway_files = []
    for root, _, files in os.walk(repo_dir):
        if any(skip in root for skip in [".git", "node_modules", ".venv", "venv", ".agents", ".wstg-audit"]):
            continue
        for f in files:
            lower = f.lower()
            if lower in ("container.py", "nginx.conf", "envoy.yaml", "ingress.yaml", "traefik.yaml") or "gateway" in lower:
                gateway_files.append(os.path.join(root, f))

    if not gateway_files:
        res.details = "No centralized API Gateway or Ingress configuration detected in repository."
        return res

    # 2. Extract route path from finding or handler
    target_path = ""
    # Try finding in trace
    for step in finding.get("trace", []):
        if step.get("kind") == "entrypoint" and "scope" in step:
            target_path = step.get("scope", "")

    # Check if gateway files map this route with an explicit auth guard
    for gw_path in gateway_files:
        rel_gw = os.path.relpath(gw_path, repo_dir).replace("\\", "/")
        try:
            with open(gw_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()

            # Check if gateway route mapping applies global or path-specific auth middleware
            if "RouteMapping(" in content:
                for idx, line in enumerate(lines, 1):
                    if "RouteMapping(" in line:
                        # Check if route mapping has an auth guard or auth dependency
                        surrounding = "\n".join(lines[max(0, idx - 1):min(len(lines), idx + 8)])
                        if any(auth_tok in surrounding.lower() for auth_tok in ["auth=", "guard=", "require_auth", "dependencies=[depends"]):
                            res.mitigating_control_found = True
                            res.evidence_file = rel_gw
                            res.evidence_line = idx
                            res.details = f"Gateway route mapping enforces perimeter authentication in '{rel_gw}' at line {idx}."
                            return res
        except Exception:
            continue

    res.details = "Perimeter gateway maps service routes without enforcing perimeter-level auth guards."
    return res


def evaluate_vector_2_middlewares(repo_dir: str, finding: Dict[str, Any]) -> FalsificationResult:
    """Vector 2: Pipeline Middlewares & Request Interceptors"""
    res = FalsificationResult("Vector 2: Pipeline Middlewares & Request Interceptors")
    file_rel = finding.get("file", "").replace("\\", "/")
    service_dir = ""
    parts = file_rel.split("/")
    if "services" in parts:
        s_idx = parts.index("services")
        if len(parts) > s_idx + 1:
            service_dir = "/".join(parts[:s_idx + 2])

    target_app_dirs = [os.path.join(repo_dir, service_dir)] if service_dir else [repo_dir]

    for search_dir in target_app_dirs:
        for root, _, files in os.walk(search_dir):
            if any(skip in root for skip in [".git", "node_modules", ".venv", "venv", ".agents", ".wstg-audit"]):
                continue
            for f in files:
                if f in ("app.py", "main.py", "app.module.ts", "server.go", "Application.java"):
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, repo_dir).replace("\\", "/")
                    try:
                        with open(full_p, "r", encoding="utf-8", errors="ignore") as pf:
                            lines = pf.readlines()
                        for idx, line in enumerate(lines, 1):
                            # Global JWT / Auth guard
                            if any(g in line for g in ["add_middleware(AuthenticationMiddleware", "APP_GUARD", "UseGuards(JwtAuthGuard", "SecurityFilterChain"]):
                                res.mitigating_control_found = True
                                res.evidence_file = rel_p
                                res.evidence_line = idx
                                res.details = f"Global security middleware or interceptor registered in '{rel_p}' at line {idx}."
                                return res
                    except Exception:
                        continue

    res.details = "No global authentication middleware or request interceptor discovered that aborts unauthenticated callers early."
    return res


def evaluate_vector_3_dto_and_typing(repo_dir: str, finding: Dict[str, Any]) -> FalsificationResult:
    """Vector 3: Framework DTO, Schema & Type Boundaries"""
    res = FalsificationResult("Vector 3: Framework DTO, Schema & Type Boundaries")
    file_rel = finding.get("file", "")
    line_no = finding.get("line")
    full_path = os.path.join(repo_dir, file_rel)

    if not os.path.exists(full_path):
        res.details = f"Target file '{file_rel}' not found on disk."
        return res

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Check line surroundings for auth dependency
        start_scan = max(0, (line_no or 1) - 10)
        end_scan = min(len(lines), (line_no or 1) + 25)
        snippet = "".join(lines[start_scan:end_scan])

        # If the handler explicitly includes an auth guard
        auth_tokens = ["depends(get_current_user", "depends(require_roles", "require_user", "current_user", "@useguards", "@rolesallowed"]
        for idx in range(start_scan, end_scan):
            line_str = lines[idx].lower()
            if any(tok in line_str for tok in auth_tokens):
                res.mitigating_control_found = True
                res.evidence_file = file_rel
                res.evidence_line = idx + 1
                res.details = f"Handler definition at line {idx + 1} binds explicit authentication dependency: '{lines[idx].strip()}'."
                return res

    except Exception as e:
        res.details = f"Could not parse handler definition: {e}"
        return res

    res.details = "Handler function accepts caller parameters without route-level authentication dependencies."
    return res


def evaluate_vector_4_data_layer(repo_dir: str, finding: Dict[str, Any]) -> FalsificationResult:
    """Vector 4: Data Layer, ORM & Persistence Constraints"""
    res = FalsificationResult("Vector 4: Data Layer, ORM & Persistence Constraints")
    wstg_code = finding.get("wstg_code", "")

    # For injection vulnerabilities, check if the sink uses parameterized ORM
    sink_file = ""
    sink_line = 0
    for step in finding.get("trace", []):
        if step.get("kind") == "sink":
            sink_file = step.get("file", "")
            sink_line = step.get("line", 0)

    if not sink_file:
        sink_file = finding.get("file", "")
        sink_line = finding.get("line", 0)

    full_sink_path = os.path.join(repo_dir, sink_file)
    if os.path.exists(full_sink_path):
        try:
            with open(full_sink_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(0, sink_line - 10)
            end = min(len(lines), sink_line + 15)
            snippet = "".join(lines[start:end])

            # Check if SQL injection was claimed but ORM parameterization is active
            if "INPV-05" in wstg_code:
                if "execute(" in snippet and (", {" in snippet or ", (" in snippet or "params=" in snippet):
                    res.mitigating_control_found = True
                    res.evidence_file = sink_file
                    res.evidence_line = sink_line
                    res.details = "Database execution at sink utilizes safe parameterized query tuple/dictionary bindings."
                    return res
        except Exception:
            pass

    res.details = "Persistence sink execution path operates without automated parameterization or tenant isolation constraints."
    return res


def evaluate_vector_5_intraprocedural_invariants(repo_dir: str, finding: Dict[str, Any]) -> FalsificationResult:
    """Vector 5: Intra-Procedural Invariants & Downstream Authorization"""
    res = FalsificationResult("Vector 5: Intra-Procedural Invariants & Downstream Authorization")
    
    # Check all files in the trace for internal tenant or ownership verification
    trace = finding.get("trace", [])
    for step in trace:
        step_file = step.get("file", "")
        step_line = step.get("line", 0)
        full_p = os.path.join(repo_dir, step_file)
        if os.path.exists(full_p):
            try:
                with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                start = max(0, step_line - 15)
                end = min(len(lines), step_line + 25)
                snippet = "".join(lines[start:end]).lower()

                # Check for explicit ownership or tenant verification
                ownership_tokens = [
                    "tenant_id != current_user",
                    "user_id != current_user",
                    "raise unauthorizedexception",
                    "raise forbiddenexception",
                    "raise httpexception(status_code=403",
                    "raise httpexception(status_code=401"
                ]
                for tok in ownership_tokens:
                    if tok in snippet:
                        res.mitigating_control_found = True
                        res.evidence_file = step_file
                        res.evidence_line = step_line
                        res.details = f"Downstream service logic in '{step_file}' enforces authorization check: '{tok}'."
                        return res
            except Exception:
                continue

    res.details = "Downstream use case and domain layers execute without internal ownership check or tenant assertion."
    return res


# ======================================================================
# 2. INVARIANT CRITIC EVALUATOR
# ======================================================================

def evaluate_finding_with_critic(
    repo_dir: str,
    finding: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates a candidate finding across all 5 defense vectors.
    Returns the complete critic evaluation record.
    """
    v1 = evaluate_vector_1_gateway(repo_dir, finding)
    v2 = evaluate_vector_2_middlewares(repo_dir, finding)
    v3 = evaluate_vector_3_dto_and_typing(repo_dir, finding)
    v4 = evaluate_vector_4_data_layer(repo_dir, finding)
    v5 = evaluate_vector_5_intraprocedural_invariants(repo_dir, finding)

    evaluations = [v1, v2, v3, v4, v5]
    mitigations = [e for e in evaluations if e.mitigating_control_found]

    status = finding.get("status", "confirmed").lower().replace("_", "-")
    
    if len(mitigations) > 0:
        verdict = "REFUTED"
        disposition = "DOWNGRADE_TO_SUPPRESSED"
        summary = f"Refuted by {len(mitigations)} mitigating architectural defense(s) discovered in source."
    elif status == "needs-validation":
        verdict = "NEEDS_FACTS"
        disposition = "TAG_AS_NEEDS_VALIDATION"
        summary = "Code flaw verified, but decisive reachability depends on unobserved deployment configuration."
    else:
        verdict = "CONFIRMED"
        disposition = "PROMOTE_TO_CONFIRMED"
        summary = "Vulnerability survived all 5 adversarial falsification attempts. No mitigating controls found."

    return {
        "verdict": verdict,
        "adversarial_status": "SURVIVED_FALSIFICATION" if verdict == "CONFIRMED" else ("REFUTED_BY_DEFENSE" if verdict == "REFUTED" else "REQUIRES_DEPLOYMENT_FACTS"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "falsification_attempts_made": 5,
        "mitigations_discovered": len(mitigations),
        "falsification_summary": summary,
        "disposition_decision": disposition,
        "vector_evaluations": [e.to_dict() for e in evaluations]
    }


def run_critic_pipeline(
    repo_dir: str,
    findings_file: str,
    apply_verdicts: bool = False,
    output_critic_report: Optional[str] = None
) -> Dict[str, Any]:
    """
    Runs the Invariant Critic pipeline across all candidate findings.
    """
    if not os.path.exists(findings_file):
        raise FileNotFoundError(f"Findings file not found: '{findings_file}'")

    with open(findings_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", []) if isinstance(data, dict) else data

    critic_results = []
    confirmed_count = 0
    refuted_count = 0
    needs_facts_count = 0

    print("=================================================================")
    print("   Automated Invariant Critic (CRITIC_MODE / Blue-Team Protocol) ")
    print("=================================================================")
    print(f"Target Repository:  {repo_dir}")
    print(f"Input Findings:     {findings_file}")
    print(f"Candidate Count:    {len(findings)}")
    print("-----------------------------------------------------------------")

    for idx, finding in enumerate(findings, 1):
        wstg_code = finding.get("wstg_code", "UNKNOWN")
        title = finding.get("title", "Untitled")
        print(f"[{idx}/{len(findings)}] Evaluating #{idx} [{wstg_code}] {title[:48]}...")

        evaluation = evaluate_finding_with_critic(repo_dir, finding)
        verdict = evaluation["verdict"]

        if verdict == "CONFIRMED":
            confirmed_count += 1
            print(f"      └── ⚔️  SURVIVED: All 5 falsification vectors failed to locate defense.")
        elif verdict == "REFUTED":
            refuted_count += 1
            print(f"      └── 🛡️  REFUTED: Mitigating defense detected! ({evaluation['falsification_summary']})")
        else:
            needs_facts_count += 1
            print(f"      └── ⚪ NEEDS_FACTS: {evaluation['falsification_summary']}")

        # Attach critic report to finding record
        finding["critic_falsification"] = evaluation
        critic_results.append({
            "wstg_code": wstg_code,
            "title": title,
            "evaluation": evaluation
        })

    print("-----------------------------------------------------------------")
    print(f"Critic Verdicts Rendered: {confirmed_count} Confirmed | {refuted_count} Refuted | {needs_facts_count} Needs Facts")
    print("=================================================================")

    if apply_verdicts:
        # Save back to findings file
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Updated '{findings_file}' with critic falsification audit trail.")

    if output_critic_report:
        os.makedirs(os.path.dirname(os.path.abspath(output_critic_report)), exist_ok=True)
        with open(output_critic_report, "w", encoding="utf-8") as f:
            json.dump({
                "audit_timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_candidates": len(findings),
                    "confirmed_survivors": confirmed_count,
                    "refuted_defended": refuted_count,
                    "needs_facts": needs_facts_count
                },
                "evaluations": critic_results
            }, f, indent=2)
        print(f"Saved complete critic report to: '{output_critic_report}'")

    return {
        "confirmed": confirmed_count,
        "refuted": refuted_count,
        "needs_facts": needs_facts_count,
        "evaluations": critic_results
    }


def main():
    parser = argparse.ArgumentParser(description="Automated Invariant Critic Engine (CRITIC_MODE).")
    parser.add_argument("repo_dir", help="Path to target repository root")
    parser.add_argument("findings", nargs="?", default=".wstg-audit/verified_findings.json", help="Path to findings JSON")
    parser.add_argument("--apply-verdicts", action="store_true", help="Update findings JSON with critic metadata")
    parser.add_argument("--out-critic", default=None, help="Path to write standalone critic evaluation JSON")

    args = parser.parse_args()
    resolved_findings = args.findings
    if not os.path.isabs(resolved_findings) and not os.path.exists(resolved_findings):
        # Try relative to repo_dir
        candidate = os.path.join(args.repo_dir, resolved_findings)
        if os.path.exists(candidate):
            resolved_findings = candidate

    run_critic_pipeline(
        repo_dir=os.path.abspath(args.repo_dir),
        findings_file=os.path.abspath(resolved_findings),
        apply_verdicts=args.apply_verdicts,
        output_critic_report=args.out_critic
    )


if __name__ == "__main__":
    main()
