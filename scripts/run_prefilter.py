#!/usr/bin/env python3
"""
Fast Deterministic Pre-Filter for WSTG Audit (Optional Static Accelerator)
Executes local Semgrep rules (OWASP Top 10 + Secrets) when available,
mapping them directly to precise WSTG domains to seed hunting units.
If Semgrep is not installed, this step is skipped without error.
"""

import json
import os
import shutil
import subprocess
import sys

def find_semgrep_cmd():
    if shutil.which("semgrep"):
        return ["semgrep"]

    appdata = os.environ.get("APPDATA", "")
    if appdata:
        py_scripts = os.path.join(appdata, "Python", "Python314", "Scripts", "semgrep.exe")
        if os.path.exists(py_scripts):
            return [py_scripts]
        for py_ver in ["Python313", "Python312", "Python311", "Python310"]:
            p = os.path.join(appdata, "Python", py_ver, "Scripts", "semgrep.exe")
            if os.path.exists(p):
                return [p]

    if shutil.which("docker"):
        return ["docker", "run", "--rm", "-v", f"{os.getcwd()}:/src", "-w", "/src", "semgrep/semgrep", "semgrep"]

    return None

def map_check_id_to_wstg(check_id: str) -> tuple[str, str]:
    cid = check_id.lower()
    if "sql" in cid:
        return "WSTG-INPV-05", "SQL Injection"
    elif "xss" in cid or "cross-site" in cid:
        return "WSTG-INPV-01", "Cross-Site Scripting (XSS)"
    elif "path-traversal" in cid or "file-read" in cid or "directory" in cid:
        return "WSTG-INPV-12", "Path Traversal"
    elif "subprocess" in cid or "command" in cid or "exec" in cid:
        return "WSTG-INPV-11", "Command Injection"
    elif "secret" in cid or "credential" in cid or "password" in cid or "key" in cid:
        return "WSTG-CONF-09", "Hardcoded Credentials & Sensitive Data Exposure"
    elif "jwt" in cid or "token" in cid or "bearer" in cid:
        return "WSTG-ATHN-04", "Authentication Token Validation"
    elif "cors" in cid:
        return "WSTG-CONF-07", "Cross-Origin Resource Sharing (CORS) Misconfiguration"
    elif "csrf" in cid:
        return "WSTG-SESS-05", "Cross-Site Request Forgery (CSRF)"
    elif "pickle" in cid or "yaml" in cid or "deserialize" in cid:
        return "WSTG-INPV-15", "Insecure Deserialization"
    elif "idor" in cid or "bola" in cid or "authz" in cid:
        return "WSTG-ATHZ-02", "Broken Object Level Authorization (BOLA/IDOR)"
    elif "ssrf" in cid or "request-forgery" in cid:
        return "WSTG-INPV-19", "Server-Side Request Forgery (SSRF)"
    elif "eval" in cid:
        return "WSTG-INPV-11", "Code Injection / Eval"
    else:
        return "WSTG-INFO-01", "General Misconfiguration / Code Quality"

def run_prefilter(target_path=".", output_file=".wstg-audit/prefilter_candidates.json", existing_json=None):
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    candidate_json = existing_json or ("semgrep-owasp.json" if os.path.exists("semgrep-owasp.json") else None)

    raw_output = os.path.join(".wstg-audit", "temp_semgrep_raw.json")
    if candidate_json and os.path.exists(candidate_json):
        print(f"Ingesting pre-existing scan results from: {candidate_json}")
        raw_output = candidate_json
    else:
        semgrep_cmd = find_semgrep_cmd()
        if not semgrep_cmd:
            print("Note: Semgrep CLI / Docker not available locally. Deterministic prefilter skipped (AST engine active).")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump({"total_candidates": 0, "results": []}, f)
            return

        cmd = semgrep_cmd + [
            "scan",
            "--config", "p/owasp-top-ten",
            "--metrics=off",
            "--disable-version-check",
            "--exclude", "**/.venv",
            "--exclude", "**/tests",
            "--exclude", "**/__pycache__",
            "--json",
            "-o", raw_output,
            target_path
        ]

        print(f"Running Semgrep pre-filter on {target_path}...")
        try:
            subprocess.run(cmd, check=False, timeout=120)
        except Exception as e:
            print(f"Semgrep execution skipped or timed out: {e}")
            return

    if not os.path.exists(raw_output):
        return

    try:
        with open(raw_output, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}

    results = data.get("results", [])
    candidates = []

    for r in results:
        check_id = r.get("check_id", "")
        path = r.get("path", "").replace("\\", "/")
        line = r.get("start", {}).get("line", 0)
        message = r.get("extra", {}).get("message", "")
        severity = r.get("extra", {}).get("severity", "WARNING")

        wstg_code, category_name = map_check_id_to_wstg(check_id)

        candidates.append({
            "check_id": check_id,
            "wstg_code": wstg_code,
            "category_name": category_name,
            "file": path,
            "line": line,
            "severity": severity,
            "message": message
        })

    output_data = {
        "total_candidates": len(candidates),
        "results": candidates
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Pre-filter triage complete: {len(candidates)} candidates saved to {output_file}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    out = sys.argv[2] if len(sys.argv) > 2 else ".wstg-audit/prefilter_candidates.json"
    run_prefilter(target, out)
