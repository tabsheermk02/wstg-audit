#!/usr/bin/env python3
"""
Automated Remediation Patch Generator for OWASP WSTG Audit Findings
Generates standard Git unified diff (.patch) files from confirmed security findings.

Usage:
    python scripts/generate_patches.py [.wstg-audit/verified_findings.json] [--output-dir .wstg-audit/patches] [--dry-run]
"""

import argparse
import difflib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def generate_hunk_for_finding(finding: Dict[str, Any], root_dir: str = ".") -> Optional[Tuple[str, str]]:
    """
    Synthesizes a unified diff for a single finding based on its source file, line,
    and remediation instructions. Returns (patch_content, relative_path) or None.
    """
    rel_path = finding.get("file", "").replace("\\", "/")
    if not rel_path or rel_path == "N/A":
        return None

    full_path = os.path.join(root_dir, rel_path)
    if not os.path.exists(full_path):
        # Try finding the file relative to current workspace
        matching = list(Path(root_dir).glob(f"**/{os.path.basename(rel_path)}"))
        if matching:
            full_path = str(matching[0])
            rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")
        else:
            return None

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            original_lines = f.readlines()
    except Exception:
        return None

    line_no = finding.get("line", 1)
    if not isinstance(line_no, int) or line_no < 1 or line_no > len(original_lines):
        line_no = 1

    code = finding.get("wstg_code", "VULN")
    title = finding.get("title", "Security Defect")
    remediation = finding.get("remediation", "").strip()
    explicit_patch = finding.get("patch", "")

    modified_lines = list(original_lines)

    # 1. If explicit patch is provided, format directly
    if explicit_patch:
        return explicit_patch, rel_path

    # 2. Intelligent automated remediation synthesizer
    target_idx = line_no - 1
    target_line = original_lines[target_idx] if target_idx < len(original_lines) else ""
    indent = len(target_line) - len(target_line.lstrip())
    indent_str = target_line[:indent]

    applied = False

    # A. NestJS @Public() bypass fix
    if "@Public()" in target_line or "@Public(" in target_line:
        modified_lines[target_idx] = f"{indent_str}// [WSTG Fix {code}] Removed @Public() bypass\n{indent_str}@UseGuards(JwtAuthGuard)\n"
        applied = True

    # B. FastAPI Route missing authentication
    elif any(d in target_line for d in ["@router.post(", "@router.delete(", "@router.put(", "@router.patch(", "@app.post(", "@app.delete("]):
        if "dependencies=" not in target_line:
            # Insert auth dependency into decorator
            fixed_line = re.sub(
                r"""(@(?:router|app)\.(?:post|delete|put|patch)\s*\([^)]+)\)""",
                r"""\1, dependencies=[Depends(require_authenticated_user)])""",
                target_line
            )
            if fixed_line != target_line:
                modified_lines[target_idx] = f"{indent_str}# [WSTG Fix {code}] Enforce gateway authentication\n{fixed_line}"
                applied = True

    # C. Insecure Mersenne Twister random replacement
    elif "random.randint(" in target_line or "random.choice(" in target_line:
        fixed_line = target_line.replace("random.randint(", "secrets.randbelow(").replace("random.choice(", "secrets.choice(")
        modified_lines[target_idx] = f"{indent_str}# [WSTG Fix {code}] Cryptographically secure PRNG\n{fixed_line}"
        applied = True

    # D. LLM missing max_tokens or timeout
    elif any(call in target_line for call in [".create(", ".generate_content(", "generatetext("]):
        if "max_tokens" not in target_line:
            fixed_line = re.sub(r"""(\.create\s*\([^)]*)\)""", r"""\1, max_tokens=2048, timeout=30.0)""", target_line)
            if fixed_line != target_line:
                modified_lines[target_idx] = f"{indent_str}# [WSTG Fix {code}] Enforce max token limit and timeout\n{fixed_line}"
                applied = True

    # E. Generic remediation insertion comment
    if not applied:
        comment_marker = "#" if rel_path.endswith((".py", ".sh", ".yaml", ".yml")) else "//"
        fix_comment = (
            f"{indent_str}{comment_marker} ================================================================\n"
            f"{indent_str}{comment_marker} [WSTG REMEDIATION: {code}] {title}\n"
            f"{indent_str}{comment_marker} ACTION REQUIRED: {remediation}\n"
            f"{indent_str}{comment_marker} ================================================================\n"
        )
        modified_lines.insert(target_idx, fix_comment)

    # 3. Compute Git unified diff
    diff = difflib.unified_diff(
        original_lines,
        modified_lines,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        n=3
    )
    diff_text = "".join(diff)

    if not diff_text:
        return None

    patch_header = (
        f"From: wstg-audit <security@autonomous-audit.local>\n"
        f"Subject: [PATCH] Fix {code}: {title}\n\n"
        f"Automated remediation generated for {rel_path}:{line_no}\n"
        f"Remediation: {remediation}\n\n"
        f"---\n"
        f"diff --git a/{rel_path} b/{rel_path}\n"
    )
    return patch_header + diff_text, rel_path


def generate_patches(
    findings_file: str = ".wstg-audit/verified_findings.json",
    output_dir: str = ".wstg-audit/patches",
    repo_dir: Optional[str] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    if not os.path.exists(findings_file):
        print(f"Error: Findings file not found at '{findings_file}'")
        return {"total_patches": 0, "patches": []}

    # Auto-detect target repository root if not specified
    if not repo_dir:
        abs_findings = os.path.abspath(findings_file)
        if ".wstg-audit" in abs_findings:
            repo_dir = abs_findings.split(".wstg-audit")[0].rstrip("/\\")
        else:
            repo_dir = os.path.dirname(abs_findings) or "."

    try:
        with open(findings_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading findings file: {e}")
        return {"total_patches": 0, "patches": []}

    findings = []
    if isinstance(data, dict):
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data

    confirmed_findings = [f for f in findings if f.get("status") == "confirmed" or "status" not in f]

    os.makedirs(output_dir, exist_ok=True)
    generated_patches = []
    consolidated_diffs = []

    for idx, finding in enumerate(confirmed_findings, 1):
        code = finding.get("wstg_code", f"FINDING_{idx}").replace("-", "_")
        result = generate_hunk_for_finding(finding, root_dir=repo_dir)
        if not result:
            continue

        patch_text, rel_path = result
        patch_filename = f"{idx:02d}_{code}.patch"
        patch_file_path = os.path.join(output_dir, patch_filename)

        if not dry_run:
            with open(patch_file_path, "w", encoding="utf-8") as pf:
                pf.write(patch_text)

        generated_patches.append({
            "index": idx,
            "wstg_code": finding.get("wstg_code", "N/A"),
            "title": finding.get("title", "Finding"),
            "file": rel_path,
            "patch_path": patch_file_path.replace("\\", "/")
        })
        consolidated_diffs.append(patch_text)

    # Write consolidated patch
    consolidated_file = os.path.join(output_dir, "all_remediations.patch")
    if not dry_run and consolidated_diffs:
        with open(consolidated_file, "w", encoding="utf-8") as cf:
            cf.write("\n\n".join(consolidated_diffs))

    print(f"Remediation Patch Generation Complete:")
    print(f"  • Confirmed Findings Processed: {len(confirmed_findings)}")
    print(f"  • Individual Patches Created: {len(generated_patches)}")
    if generated_patches and not dry_run:
        print(f"  • Consolidated Patch: {consolidated_file}")
    elif dry_run:
        print("  • Dry-Run Mode Active (no files written)")
        for p in generated_patches:
            print(f"    - [{p['wstg_code']}] {p['title']} -> {p['file']}")

    return {
        "total_patches": len(generated_patches),
        "consolidated_patch": consolidated_file.replace("\\", "/"),
        "patches": generated_patches
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Git patches from verified WSTG audit findings.")
    parser.add_argument("findings", nargs="?", default=".wstg-audit/verified_findings.json", help="Path to verified findings JSON")
    parser.add_argument("--output-dir", default=".wstg-audit/patches", help="Directory to save generated patch files")
    parser.add_argument("--repo-dir", default=None, help="Root directory of the target codebase (auto-detected if omitted)")
    parser.add_argument("--dry-run", action="store_true", help="Print diff summary without writing patch files")
    args = parser.parse_args()

    generate_patches(findings_file=args.findings, output_dir=args.output_dir, repo_dir=args.repo_dir, dry_run=args.dry_run)
