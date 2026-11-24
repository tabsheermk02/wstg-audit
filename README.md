# OWASP WSTG Autonomous Security Audit Skill (Polyglot & Zero-Dependency)

A shareable, methodology-driven application security auditor adhering to the **OWASP Web Security Testing Guide (WSTG v4.2 / v5)** across **any programming language and stack**.

### Zero External Dependencies
- **No Semgrep required.**
- **No Trivy required.**
- **No Docker required.**
- **No Node.js, Go, or JDK required on host.**
- Uses a lightweight, standard-library polyglot surface engine (`ast`, `re`, `json`, `os`, `sys`) coupled with the Agent's native polyglot reasoning.

---

## Supported Stacks & Frameworks

| Language / Stack | Frameworks Supported | Auth Guards Checked |
|---|---|---|
| **Python** | FastAPI, Django, Flask | `Depends(...)`, Type annotations, `@login_required` |
| **TypeScript / JavaScript** | Express.js, NestJS, Next.js App Router (`route.ts`) | `@UseGuards()`, Auth middleware, Passport.js |
| **Go** | Gin, Chi, Fiber, standard `net/http` | Auth middleware handlers, JWT context checks |
| **Java / Kotlin** | Spring Boot (`@RestController`) | `@PreAuthorize`, `@Secured`, `@RolesAllowed` |
| **Cross-Stack** | Rust, C#, Ruby, PHP | Native Agentic Semantic Reasoning |

---

## What It Detects (The Architecture Flaws Linters Miss)

1. **Unauthenticated Dangerous Endpoints (`WSTG-ATHN-04`):**
   * Discovers `DELETE`, `POST`, `PUT` routes that lack authentication guards across all stacks.
2. **Unpartitioned Cache & Secret Lookups (`WSTG-SESS-04` / `WSTG-ATHZ-02`):**
   * Flags generic cache getters that can leak OTPs or provider session tokens.
3. **BOLA / IDOR on Resource Identifiers (`WSTG-ATHZ-02`):**
   * Identifies routes accepting caller-supplied object keys, session IDs, or files without user ownership checks.
4. **Internal Header Spoofing (`WSTG-ATHN-04`):**
   * Detects services that trust internal user headers directly without verifying gateway tokens.

---

## How to Share & Install

### 1. In Your Team's Git Repository (Zero Setup)
The skill is located at `.agents/skills/wstg-audit/`. Commit it to your repo:
```bash
git add .agents/skills/wstg-audit/
git commit -m "feat(security): add polyglot zero-dependency WSTG audit skill"
git push
```
Any teammate opening the repo in Antigravity or a compatible agent gets the skill automatically.

### 2. Standalone Git Repo (Cloudflare Model)
Push this folder to a standalone GitHub repository (`https://github.com/your-org/wstg-audit-skill`).
Install in any repository using:
```bash
npx skills add https://github.com/your-org/wstg-audit-skill --skill wstg-audit
```

---

## Running the Skill Manually

1. **Polyglot Surface & Trust-Chain Analysis:**
   ```bash
   python .agents/skills/wstg-audit/scripts/map_surface.py . surface_map.json
   ```

2. **Generate Compliance Scorecard:**
   ```bash
   python .agents/skills/wstg-audit/scripts/generate_report.py verified_findings.json
   ```
