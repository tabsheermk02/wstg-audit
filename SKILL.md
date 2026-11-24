---
name: wstg-audit
description: Autonomous polyglot security auditor for OWASP WSTG v4.2/v5 and OWASP Top 10 for LLMs. Use when asked to audit authentication, authorization (BOLA/IDOR), API trust boundaries, Gateway-to-Service exposure, AST taint tracking, prompt injection, or full WSTG compliance.
---

# OWASP WSTG Autonomous Security Audit Skill (v2.0)

This skill equips the agent to conduct exhaustive, methodology-driven application security audits adhering to the **OWASP Web Security Testing Guide (WSTG v4.2 / v5)** and the **OWASP Top 10 for LLMs / GenAI (2025)** across multiple technology stacks.

It provides a native, zero-dependency polyglot surface mapping engine, pluggable gateway ingress drivers, AST-level taint/data-flow analysis, and deep agentic code verification across **Gateway $\rightarrow$ Microservice trust boundaries**.

---

## Supported Stacks & Framework Parsers

| Stack | Parsers & Frameworks Supported | Security & Auth Context Analyzed |
|---|---|---|
| **Python** | FastAPI, Django REST Framework, Flask | AST route extraction, `APIRouter(prefix, dependencies)`, decorator `dependencies=[Depends(...)]`, `Annotated[..., Depends(...)]`, exclusion of non-auth DB sessions, **AST Taint Tracking down to dangerous sinks** |
| **TypeScript / JS** | NestJS, Express.js, Next.js App Router (`route.ts`) | Automatic NestJS `APP_GUARD` global security discovery, class-level `@Controller` prefixes & `@UseGuards()`, `@Public()` opt-out detection, method `@UseGuards()`, Express router middleware mounting |
| **Go** | Gin, Chi, Fiber, standard `net/http` | Grouped routes (`r.Group`), prefix inheritance, middleware inheritance (`group.Use(...)`), route verbs (`r.GET`, `r.POST`) |
| **Java / Kotlin** | Spring Boot | `@RestController`, class & method `@RequestMapping`, `@GetMapping`, `@PostMapping`, class & method `@PreAuthorize`, `@Secured`, `@RolesAllowed` |
| **Non-REST** | WebSockets, GCP Pub/Sub, RabbitMQ, Kafka, Celery | WebSocket handshake authentication (`@router.websocket`, `socket.io`, `ws.on('connection')`), async subscriber message payload validation |
| **AI / GenAI** | OpenAI (Chat & Responses), Anthropic, Gemini, LangChain, LiteLLM, Vercel AI SDK | `LLM01` (Prompt Injection), `LLM02` (Insecure Output), `LLM06` (Excessive Agency), `LLM08` (Unscoped RAG), `LLM10` (Unbounded Consumption / Max Tokens) |

---

## Pluggable Gateway & Ingress Discovery Drivers

The surface analyzer automatically discovers perimeter gateways to differentiate externally exposed routes from private microservice routes using modular drivers:

1. **`FastAPIRouteMappingDriver`:** Discovers `RouteMapping(public_prefix, service_name, target_prefix=...)` in gateway dispatchers (e.g. `container.py`).
2. **`NginxGatewayDriver`:** Parses `location <prefix> { proxy_pass http://<service>; }` reverse proxy rules in `.conf` files.
3. **`EnvoyGatewayDriver`:** Parses Envoy routing tables (`route_config`, `virtual_hosts`, `prefix: ...`, `cluster: ...`).
4. **`KubernetesIngressDriver`:** Parses Kubernetes `Ingress` and Gateway API `HTTPRoute` YAML manifests.
5. **`TraefikGatewayDriver`:** Parses Traefik dynamic routing rules (`PathPrefix(...)` and service declarations).
6. **`ExpressNestMountDriver`:** Parses NestJS `app.setGlobalPrefix('...')` and Express `app.use('/prefix', router)`.

---

## AST Function-Level Taint & Data-Flow Tracking

The Python surface engine includes an intra-procedural AST taint tracker that models untrusted parameters flowing down to dangerous sinks:

* **`WSTG-INPV-05` (SQL Injection):** Tracks parameters reaching `cursor.execute()`, `session.execute(text(...))`, or raw queries constructed via f-strings or string concatenation with SQL keywords.
* **`WSTG-INPV-12` (Command Injection):** Detects untrusted parameters flowing into `subprocess.run()`, `subprocess.Popen()`, `os.system()`, or `os.popen()` (with special escalation on `shell=True`).
* **`WSTG-INPV-12` (Path Traversal):** Identifies file path variables reaching `open()`, `aiofiles.open()`, `os.remove()`, or `FileResponse()` without safe path resolution (`.resolve()`).
* **`WSTG-INPV-11` (Code Injection):** Flags parameters reaching `eval()`, `exec()`, or `compile()`.
* **`WSTG-INPV-15` (Insecure Deserialization):** Flags untrusted data reaching `pickle.loads()`, `yaml.load()` (without `SafeLoader`), or `marshal.loads()`.
* **`WSTG-INPV-16` (SSRF):** Identifies parameters reaching outbound HTTP client requests (`requests.get`, `httpx.post`, `urllib.request.urlopen`).
* **`WSTG-ATHZ-02` (Arbitrary Storage Signed URL Exposure):** Tracks caller-supplied object keys reaching `generate_presigned_url` or `signed_url` without ownership verification.

---

## The 4-Phase Audit Workflow

```
[Phase 1: Polyglot Surface, Gateway & Taint Mapping]
                        │
                        ▼
[Phase 2: Optional Static Pre-Filter (Semgrep)]
                        │
                        ▼
[Phase 3: Deep Logic & Authorization Verification (Trace Analysis)]
                        │
                        ▼
[Phase 4: Compliance Scorecard & Remediation Patch Generation]
```

All run outputs are written to the `.wstg-audit/` directory to prevent repository root clutter.

---

### Phase 1: Polyglot Surface, Gateway & Taint Mapping
Run the surface analyzer across the repository:
```bash
python .agents/skills/wstg-audit/scripts/map_surface.py . .wstg-audit/surface_map.json
```
The script performs:
1. **Pluggable Gateway Discovery:** Distinguishes externally exposed routes from internal microservice routes.
2. **Framework Auth Inheritance:** Discovers NestJS `APP_GUARD`, class-level `@UseGuards()`, and Go router group middleware.
3. **AST Taint Tracking:** Surfaces dangerous sinks receiving tainted route inputs.
4. **Non-REST Entrypoint Scan:** Audits WebSockets and async Pub/Sub event consumers.
5. **AI Surface Scan:** Checks LLM client calls for `max_tokens`, client timeouts, direct prompt string interpolations, and unscoped vector database similarity searches.

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

#### Verification Contract (`.wstg-audit/verified_findings.json`)
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

### Phase 4: Compliance Scorecard & Remediation Patch Generation

#### 1. Compile the Compliance Report
```bash
python .agents/skills/wstg-audit/scripts/generate_report.py .wstg-audit/verified_findings.json .wstg-audit/WSTG-REPORT.md
```

#### 2. Generate Automated Git Unified Diff Patches
```bash
python .agents/skills/wstg-audit/scripts/generate_patches.py .wstg-audit/verified_findings.json --output-dir .wstg-audit/patches
```
This produces ready-to-apply `.patch` files for each confirmed vulnerability as well as a consolidated `all_remediations.patch`.

#### Scorecard Status Standards
| Scorecard Status | Meaning & Criteria |
|---|---|
| `⚪ UNTESTED` | **Domain Out of Scope / Unreviewed:** Indicates zero testing occurred—prevents mistaking uninspected areas for secure code. |
| `🟢 SECURE` | **Actively Audited & Defended:** The domain was explicitly evaluated, handlers were audited, and all relevant security controls were verified active without defects. |
| `🔴 VULNERABLE (X)` | **Active Vulnerabilities Confirmed:** One or more findings in this domain were validated with proven `[ENTRYPOINT] -> [SINK]` traces. |
