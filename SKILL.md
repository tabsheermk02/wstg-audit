---
name: wstg-audit
description: Autonomous polyglot security auditor for OWASP WSTG v4.2/v5 and OWASP Top 10 for LLMs. Use when asked to audit authentication, authorization (BOLA/IDOR), API trust boundaries, Gateway-to-Service exposure, prompt injection, or full WSTG compliance.
---

# OWASP WSTG Autonomous Security Audit Skill

This skill equips the agent to conduct exhaustive, methodology-driven application security audits adhering to the **OWASP Web Security Testing Guide (WSTG v4.2 / v5)** and the **OWASP Top 10 for LLMs / GenAI (2025)** across multiple technology stacks.

It provides a native, zero-dependency polyglot surface mapping engine coupled with deep agentic code verification across **Gateway $\rightarrow$ Microservice trust boundaries**.

---

## Supported Stacks & Framework Parsers

| Stack | Parsers & Frameworks Supported | Security & Auth Context Analyzed |
|---|---|---|
| **Python** | FastAPI, Django REST Framework, Flask | AST-based route extraction, `APIRouter(prefix, dependencies)`, decorator `dependencies=[Depends(...)]`, `Annotated[..., Depends(...)]`, exclusion of non-auth DB sessions |
| **TypeScript / JS** | NestJS, Express.js, Next.js App Router (`route.ts`) | Automatic NestJS `APP_GUARD` global security discovery, `@Public()` opt-out detection, class & method `@UseGuards()`, Next.js route handlers |
| **Java / Kotlin** | Spring Boot | `@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping`, `@PreAuthorize`, `@Secured`, `@RolesAllowed` |
| **Go** | Gin, Chi, Fiber, standard `net/http` | Route verbs (`r.GET`, `r.POST`), middleware handlers (`jwt`, `auth`, `token`) |
| **AI / GenAI** | OpenAI (Chat & Responses), Anthropic, Gemini, LangChain, LiteLLM, Vercel AI SDK | `LLM01` (Prompt Injection), `LLM02` (Insecure Output), `LLM06` (Excessive Agency), `LLM08` (Unscoped RAG), `LLM10` (Unbounded Consumption / Max Tokens) |

---

## Autonomous Self-Evolution & Fallback Engine (`SKILL_EVOLUTION`)

A primary strength of the `wstg-audit` skill is its **self-evolving architectural fallback**. Real-world repositories frequently feature proprietary routing layers, unmapped micro-frameworks (e.g., Rust Axum/Actix, C# ASP.NET Core, PHP Laravel/Symfony, Ruby on Rails, Elixir Phoenix), or custom ingress proxies (e.g., Envoy, Kong, Traefik, Nginx, APISIX) not predefined in the static mapper.

When the agent encounters an unmapped technology or custom gateway layer, it must **never abort or produce an unverified pass**. Instead, the agent executes the **Autonomous Adaptation Protocol**:

1. **Surface Reconnaissance & Framework Discovery:**
   - Scan configuration files and dependency manifests (`Cargo.toml`, `*.csproj`, `composer.json`, `Gemfile`, `mix.exs`, `envoy.yaml`, `nginx.conf`, custom proxy configurations) to identify active web engines and ingress routers.
   - Inspect routing definitions, dispatch tables, and middleware chains to determine entrypoints, path prefixes, parameter syntax, and authentication middleware.

2. **Dynamic Surface Synthesis & Mapper Extension:**
   - Either extend `scripts/map_surface.py` by adding framework regex/AST parsing rules, or generate an ad-hoc adapter script to parse the routes, public vs. protected scopes, and parameter bindings.
   - Cross-reference ingress routing tables (e.g., API gateway dispatchers, reverse proxy configs) against downstream handlers to verify external reachability.

3. **Audit Memory & Evolution Logging:**
   - Record newly discovered framework parsers, ingress mapping patterns, and heuristic adjustments in `.wstg-audit/evolution_log.json`:
     ```json
     {
       "timestamp": "2026-11-24T15:20:00Z",
       "framework_discovered": "Rust Axum",
       "file_patterns": ["src/**/*.rs"],
       "auth_mechanisms_identified": ["Extension(AuthUser)", "from_request_parts"],
       "adaptation_applied": "Synthesized Axum route extractor into map_surface.py"
     }
     ```

4. **Resilient Agentic Fallback:**
   - If AST or regex parsing cannot fully resolve ambiguous routing (e.g. dynamic reflection or meta-programming), fall back to structured semantic code inspection.
   - Trace each mutating endpoint manually from Entrypoint to Sink to guarantee zero false negatives across critical trust boundaries.

---

## The 4-Phase Audit Workflow

```
[Phase 1: Polyglot Surface & Gateway Mapping]
                       │
                       ▼
[Phase 2: Optional Static Pre-Filter (Semgrep)]
                       │
                       ▼
[Phase 3: Deep Logic & Authorization Verification (Trace Analysis)]
                       │
                       ▼
[Phase 4: WSTG Compliance Scorecard & Report Generation]
```

All run outputs are written to the `.wstg-audit/` directory to prevent repository root clutter.

---

### Phase 1: Polyglot Surface & Gateway Mapping
Run the surface analyzer across the repository:
```bash
python .agents/skills/wstg-audit/scripts/map_surface.py . .wstg-audit/surface_map.json
```
The script performs:
1. **Gateway Route Discovery:** Extracts route mappings (e.g. from `container.py` or proxy configs) to determine which endpoints are exposed externally vs. internal-only microservice routes.
2. **Framework Auth Inheritance:** Discovers application-level guards (like NestJS `APP_GUARD` or global FastAPI dependencies) so that protected routes are not misclassified as unauthenticated.
3. **AI Surface Scan:** Checks LLM client calls for `max_tokens`, client timeouts, direct prompt string interpolations, and unscoped vector database similarity searches.
4. **Threat Classification:**
   * **CRITICAL:** Public, Gateway-Exposed unauthenticated mutating routes (`POST`, `PUT`, `DELETE`).
   * **HIGH:** Public unauthenticated parameter lookups, BOLA/IDOR candidates without user/tenant validation, and prompt injection vectors.
   * **MEDIUM:** Handlers inspecting raw internal headers (`x-bantrly-*`) without caller validation.
   * **LOW / INTERNAL:** Internal microservice routes unexposed through the gateway.

---

### Phase 2: Optional Static Pre-Filter (Semgrep Accelerator)
If Semgrep CLI or Docker is installed locally, run the fast pre-filter to triage static pattern matches:
```bash
python .agents/skills/wstg-audit/scripts/run_prefilter.py . .wstg-audit/prefilter_candidates.json
```
*Note: If Semgrep is not installed, skip this step. Phase 1 and Phase 3 provide full independent AST coverage with zero external dependencies.*

---

### Phase 3: Deep Logic & Authorization Verification

The agent audits candidate findings against the 5 critical WSTG domains:

1. **`WSTG-ATHZ-02` (BOLA / IDOR & Tenant Boundary):**
   - For every endpoint accepting an object ID (`{id}`, `{user_id}`, `{session_id}`):
     - Does the service query verify ownership (`auth.user_id == record.user_id`) or tenant context?
     - Can a user from Tenant A access resources in Tenant B?
2. **`WSTG-ATHN-04` (Gateway-to-Service Trust Breaches):**
   - Does a public gateway route forward directly to an unguarded downstream handler?
   - Does the downstream handler trust incoming `x-user-id` or `x-role` without gateway authentication?
3. **`WSTG-SESS-04` (Cache & Session Isolation):**
   - Are Redis session or cache keys strictly namespaced per tenant?
4. **`WSTG-INPV-05 / 11 / 12` (Injection Flaws):**
   - Are SQL queries, system commands, or file system paths constructed via dynamic string formatting?
5. **`OWASP-LLM01 / 10` (GenAI Vulnerabilities):**
   - Does the model call have bounded token generation (`max_tokens`)?
   - Are untrusted database values or user inputs concatenated into system prompt instructions?

#### Verification Contract & Finding Statuses (`.wstg-audit/verified_findings.json`)

Findings in `.wstg-audit/verified_findings.json` must follow a strict lifecycle status:

| Finding Status | Meaning | When to Use |
|---|---|---|
| `confirmed` | **Independently Proven Vulnerability** | An unbroken execution trace exists from Entrypoint to Sink. The flaw is exploitable based on visible code and configuration without depending on unverified external assumptions. Requires reproducible PoC and remediation. |
| `needs-validation` | **Source-Verified Lead with Deployment Unknown** | A dangerous code pattern or missing control is verified in source, but exploitability depends on an unobserved production fact (e.g. edge WAF rules, cloud IAM bucket ACLs, private VPC isolation). Requires local/deployment test plans. |
| `suppressed` | **Evaluated False Positive / Defense Holds** | Candidate flagged by static scanners or prefilters, but manual code analysis confirms architectural defenses (e.g. constant-time HMAC check, upstream gateway stripping, strict enum validation) neutralize the risk. |

Every verified finding must be written with the following strict JSON schema:
```json
{
  "audited_domains": ["WSTG-ATHZ", "WSTG-ATHN", "OWASP-LLM"],
  "findings": [
    {
      "wstg_code": "WSTG-ATHZ-02",
      "severity": "CRITICAL",
      "status": "confirmed",
      "title": "Unauthenticated Administrative User Creation via Public Decorator",
      "description": "Endpoint POST / is decorated with @Public(), bypassing the global AuthGuard and allowing anonymous callers to create admin users.",
      "file": "api/libs/admin/src/eworx_users/eworx_users.controller.ts",
      "line": 101,
      "trace": [
        { "kind": "entrypoint", "file": "api/libs/admin/src/eworx_users/eworx_users.controller.ts", "line": 101, "scope": "create", "description": "POST / decorated with @Public()" },
        { "kind": "sink", "file": "api/libs/admin/src/eworx_users/eworx_users.service.ts", "line": 34, "scope": "create", "description": "Persists admin user in MongoDB without auth check" }
      ],
      "poc_language": "http",
      "proof_of_concept": "POST / HTTP/1.1\\nHost: target\\nContent-Type: application/json\\n\\n{\"email\":\"attacker@evil.com\",\"role\":\"admin\"}",
      "remediation": "Remove @Public() and enforce @UseGuards(RolesGuard) requiring ADMIN role."
    }
  ]
}
```

---

### Phase 4: Compliance Scorecard & Remediation Report
Compile findings into the final compliance report:
```bash
python .agents/skills/wstg-audit/scripts/generate_report.py .wstg-audit/verified_findings.json .wstg-audit/WSTG-REPORT.md
```

#### Scorecard Status Meanings
The compliance matrix strictly rejects naive `PASS` assertions. Each domain receives one of three truthful statuses:

| Scorecard Status | Meaning & Criteria |
|---|---|
| `⚪ UNTESTED` | **Domain Out of Scope / Unreviewed:** The auditor did not inspect endpoints or logic under this domain during the run. Indicates zero testing occurred—prevents teams from mistaking uninspected areas for secure code. |
| `🟢 SECURE` | **Actively Audited & Defended:** The domain was explicitly evaluated (included in `audited_domains`), surface handlers were audited, and all relevant security controls were verified active and effective without flaws. |
| `🔴 VULNERABLE (X)` | **Active Vulnerabilities Confirmed:** One or more findings in this domain were validated with proven `[ENTRYPOINT] -> [SINK]` traces. Breakdown by severity (Critical, High, Medium, Low) is shown in the table. |
