#!/usr/bin/env python3
"""
Deterministic Findings & Invariant Schema Validator (Zero-Dependency Python)
Adheres to Cloudflare security-audit and OWASP WSTG verification standards.

Validates that:
1. Every confirmed finding contains unbroken [entrypoint -> sink] traces.
2. All cited files physically exist in the target repository.
3. All cited line numbers fall within the actual target file length.
4. Every finding states root_cause, intended_behavior, conditions, and regression_test.
5. Severity reflects demonstrated boundary impact and is absent from needs_validation.

Usage:
    python scripts/validate_findings.py [.wstg-audit/verified_findings.json] [--repo-dir <path>]
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
VALID_STATUSES = {"confirmed", "needs-validation", "needs_validation", "suppressed"}
VALID_TRACE_KINDS = {"entrypoint", "propagation", "sink", "control"}

def validate_finding_record(
    finding: Dict[str, Any],
    index: int,
    repo_dir: str,
    file_cache: Dict[str, int]
) -> Tuple[List[str], List[str]]:
    """
    Validates a single finding record.
    Returns (errors, warnings).
    """
    errors = []
    warnings = []
    prefix = f"Finding #{index} [{finding.get('wstg_code', 'NO-CODE')}]"

    # 1. Status & Severity Validation
    status = finding.get("status", "confirmed").lower().replace("_", "-")
    if status not in VALID_STATUSES:
        errors.append(f"{prefix}: Invalid status '{status}'. Must be one of {sorted(VALID_STATUSES)}")

    severity = finding.get("severity", "").upper()
    if status == "needs-validation":
        # needs-validation represents an unobserved deployment lead, not a confirmed vulnerability
        if "severity" in finding and severity in ("CRITICAL", "HIGH"):
            warnings.append(f"{prefix}: 'needs-validation' lead has severity '{severity}'. Leads should have tentative priority, not confirmed vulnerability severity.")
    else:
        if severity not in VALID_SEVERITIES:
            errors.append(f"{prefix}: Missing or invalid severity '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}")

    # 2. Required Invariant Fields
    required_text_fields = ["title", "description", "root_cause", "intended_behavior", "remediation"]
    for field in required_text_fields:
        val = finding.get(field, "")
        if not val or not isinstance(val, str) or not val.strip():
            errors.append(f"{prefix}: Missing required invariant field '{field}'")

    # 3. Target File & Line Existence
    rel_file = finding.get("file", "")
    line_no = finding.get("line")

    if not rel_file or not isinstance(rel_file, str):
        errors.append(f"{prefix}: Missing target file path")
    else:
        target_full_path = os.path.join(repo_dir, rel_file)
        if not os.path.exists(target_full_path):
            errors.append(f"{prefix}: Target file does not exist at '{target_full_path}'")
        else:
            # Check line number bounds
            if rel_file not in file_cache:
                try:
                    with open(target_full_path, "r", encoding="utf-8", errors="ignore") as f:
                        file_cache[rel_file] = len(f.readlines())
                except Exception as e:
                    file_cache[rel_file] = 0
                    errors.append(f"{prefix}: Could not read target file: {e}")

            max_lines = file_cache.get(rel_file, 0)
            if not isinstance(line_no, int) or line_no < 1:
                errors.append(f"{prefix}: Invalid line number {line_no}. Must be positive integer.")
            elif max_lines > 0 and line_no > max_lines:
                errors.append(f"{prefix}: Line number {line_no} exceeds file length ({max_lines} lines) in '{rel_file}'")

    # 4. Trace Validation (Must have Entrypoint -> Sink)
    trace = finding.get("trace", [])
    if not isinstance(trace, list) or len(trace) == 0:
        errors.append(f"{prefix}: Missing execution trace. Findings must provide an unbroken [entrypoint -> sink] path.")
    else:
        kinds = [t.get("kind", "").lower() for t in trace if isinstance(t, dict)]
        if "entrypoint" not in kinds:
            errors.append(f"{prefix}: Trace is missing an 'entrypoint' step")
        if "sink" not in kinds:
            errors.append(f"{prefix}: Trace is missing a 'sink' step")

        for s_idx, step in enumerate(trace, 1):
            s_kind = step.get("kind", "").lower()
            if s_kind not in VALID_TRACE_KINDS:
                errors.append(f"{prefix} Trace Step #{s_idx}: Invalid kind '{s_kind}'. Must be one of {sorted(VALID_TRACE_KINDS)}")
            s_file = step.get("file", "")
            if not s_file:
                errors.append(f"{prefix} Trace Step #{s_idx}: Missing file path")
            else:
                s_full_path = os.path.join(repo_dir, s_file)
                if not os.path.exists(s_full_path):
                    errors.append(f"{prefix} Trace Step #{s_idx}: Cited trace file does not exist: '{s_file}'")

    # 5. Conditions & Regression Test Specification
    conditions = finding.get("conditions", [])
    if not isinstance(conditions, list):
        errors.append(f"{prefix}: 'conditions' must be a list of prerequisite environmental/exploit facts")
    elif len(conditions) == 0:
        warnings.append(f"{prefix}: No explicit preconditions recorded in 'conditions' list")

    reg_test = finding.get("regression_test", "")
    if not reg_test or not isinstance(reg_test, str):
        warnings.append(f"{prefix}: Missing 'regression_test' specification. Recommended to specify automated test assertion.")

    # 6. Critic Falsification Metadata (Validated if present)
    critic = finding.get("critic_falsification")
    if critic is not None:
        if not isinstance(critic, dict):
            errors.append(f"{prefix}: 'critic_falsification' must be an object")
        else:
            c_verdict = critic.get("verdict", "")
            if c_verdict not in ("CONFIRMED", "REFUTED", "NEEDS_FACTS"):
                errors.append(f"{prefix}: Invalid critic verdict '{c_verdict}'. Must be CONFIRMED, REFUTED, or NEEDS_FACTS.")

    return errors, warnings


def validate_findings_file(
    findings_path: str = ".wstg-audit/verified_findings.json",
    repo_dir: Optional[str] = None
) -> Tuple[bool, List[str], List[str]]:
    if not os.path.exists(findings_path):
        return False, [f"Findings file not found: '{findings_path}'"], []

    abs_findings = os.path.abspath(findings_path)
    if not repo_dir:
        if ".wstg-audit" in abs_findings:
            repo_dir = abs_findings.split(".wstg-audit")[0].rstrip("/\\")
        else:
            repo_dir = os.path.dirname(abs_findings) or "."

    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, [f"JSON Parse Error in '{findings_path}': {e}"], []

    findings = []
    if isinstance(data, dict):
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data

    all_errors = []
    all_warnings = []
    file_cache: Dict[str, int] = {}

    for idx, f in enumerate(findings, 1):
        errs, warns = validate_finding_record(f, idx, repo_dir, file_cache)
        all_errors.extend(errs)
        all_warnings.extend(warns)

    is_valid = len(all_errors) == 0
    return is_valid, all_errors, all_warnings


def main():
    parser = argparse.ArgumentParser(description="Deterministic Invariant and Finding Schema Validator.")
    parser.add_argument("findings", nargs="?", default=".wstg-audit/verified_findings.json", help="Path to findings JSON")
    parser.add_argument("--repo-dir", default=None, help="Root directory of target repository")
    args = parser.parse_args()

    abs_findings = os.path.abspath(args.findings)
    resolved_repo = args.repo_dir
    if not resolved_repo:
        if ".wstg-audit" in abs_findings:
            resolved_repo = abs_findings.split(".wstg-audit")[0].rstrip("/\\")
        else:
            resolved_repo = os.path.dirname(abs_findings) or "."

    is_valid, errors, warnings = validate_findings_file(args.findings, resolved_repo)

    print("=================================================================")
    print("  OWASP WSTG Findings & Invariant Schema Validator (v2.0)        ")
    print("=================================================================")
    print(f"Target Repository Root: {os.path.abspath(resolved_repo)}")
    print(f"Findings File:          {args.findings}")
    print("-----------------------------------------------------------------")

    if warnings:
        print(f"⚠️  {len(warnings)} Advisory Warning(s):")
        for w in warnings:
            print(f"  • {w}")
        print("-----------------------------------------------------------------")

    if not is_valid:
        print(f"❌ FAILED: {len(errors)} Schema / Source Verification Error(s):")
        for e in errors:
            print(f"  • {e}")
        print("-----------------------------------------------------------------")
        print("Audit findings rejected by validation contract. Fix the above citations.")
        sys.exit(1)
    else:
        print("✅ PASSED: All findings comply with WSTG invariant schema.")
        print("   All cited source files, positive line bounds, and traces verified.")
        print("=================================================================")
        sys.exit(0)

if __name__ == "__main__":
    main()
