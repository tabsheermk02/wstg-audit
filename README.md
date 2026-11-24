# OWASP WSTG Autonomous Security Audit Skill (v2.0)

A shareable, methodology-driven application security auditor adhering to the **OWASP Web Security Testing Guide (WSTG v4.2 / v5)** and the **OWASP Top 10 for LLMs / GenAI (2025)** across **any programming language and stack**.

### Zero External Dependencies
- **No Semgrep required.**
- **No Trivy required.**
- **No Docker required.**
- **No Node.js, Go, or JDK required on host.**
- Standard-library polyglot surface engine (`ast`, `re`, `json`, `os`, `sys`, `pathlib`) coupled with the Agent's native polyglot reasoning.

---

## What's New in v2.0

1. **Pluggable Gateway Discovery Drivers:**
   - Modular drivers for **FastAPI RouteMapping**, **Nginx**, **Envoy**, **Kubernetes Ingress / HTTPRoute**, **Traefik**, and **Express / NestJS global mounts**.
   - Accurately distinguishes public, gateway-exposed mutating routes from internal microservice routes.
2. **Function-Level AST Taint & Data-Flow Tracking:**
   - Traces untrusted route parameters through assignments and formatting into dangerous sinks:
     - **SQL Injection (`WSTG-INPV-05`)** via `cursor.execute`, `text()`, raw f-string queries
     - **Command Injection (`WSTG-INPV-12`)** via `subprocess.run`, `os.system`
     - **Path Traversal (`WSTG-INPV-12`)** via `open()`, `FileResponse`
     - **Code Injection (`WSTG-INPV-11`)** via `eval()`, `exec()`
     - **Insecure Deserialization (`WSTG-INPV-15`)** via `pickle.loads()`, `yaml.load()`
     - **SSRF (`WSTG-INPV-16`)** via `requests.*`, `httpx.*`
     - **Arbitrary Presigned Storage URLs (`WSTG-ATHZ-02`)** via `generate_presigned_url`
3. **Syntax-Aware Multi-Language Parsers:**
   - **TypeScript / NestJS:** Class-level `@Controller` prefixes, class-level `@UseGuards()`, and `@Public()` bypass detection.
   - **Go:** `r.Group` route prefixes and inherited middleware (`group.Use(...)`).
   - **Java / Spring Boot:** Class `@RequestMapping` combined with method mappings and `@PreAuthorize`.
4. **Non-REST Entrypoint Scanner:**
   - Audits **WebSockets** (`@router.websocket`, `socket.io`, `ws.on('connection')`) for handshake token validation.
   - Audits **Pub/Sub & Message Queues** (GCP Pub/Sub, RabbitMQ, Kafka, Celery) for unvalidated payload ingestion.
5. **Deterministic Invariant & Citation Validator (`validate_findings.py`):**
   - Validates findings against physical source files, checks line boundaries, enforces unbroken traces (`entrypoint` $\rightarrow$ `sink`), and requires root cause, intended behavior, and regression test specifications.
6. **Deep Protocol & Tenancy Attack Guides:**
   - Integrated heuristics for JWT algorithm confusion, key injection (`kid`/`jku`), HTTP request desync, cache deception, BOLA across tenants, and unpartitioned cache stores.

---

## Supported Stacks & Frameworks

| Language / Stack | Frameworks Supported | Auth & Ingress Context Analyzed |
|---|---|---|
| **Python** | FastAPI, Django REST, Flask | AST route mapping, `APIRouter` prefix/dependencies, `Annotated[Depends]`, AST taint tracking to sinks |
| **TypeScript / JS** | Express.js, NestJS, Next.js App Router | Class & method `@UseGuards()`, `@Public()` bypass, Express middleware chaining |
| **Go** | Gin, Chi, Fiber, standard `net/http` | Route grouping (`r.Group`), middleware inheritance |
| **Java / Kotlin** | Spring Boot (`@RestController`) | Class/method `@RequestMapping`, `@PreAuthorize`, `@Secured`, `@RolesAllowed` |
| **Non-REST** | WebSockets, Pub/Sub, Kafka, Celery | WebSocket handshake authentication, async consumer message validation |
| **AI / GenAI** | OpenAI, Anthropic, Gemini, LangChain, LiteLLM | Prompt injection, max tokens limit, client timeout, unscoped vector RAG |

---

## Running the Skill Manually

### 1. Polyglot Surface, Gateway & Taint Analysis:
```bash
python scripts/map_surface.py <path-to-target-repo> .wstg-audit/surface_map.json
```

### 2. Validate Findings Invariants & Source Citations:
```bash
python scripts/validate_findings.py .wstg-audit/verified_findings.json
```

### 3. Generate Compliance Scorecard & Markdown Report:
```bash
python scripts/generate_report.py .wstg-audit/verified_findings.json .wstg-audit/WSTG-REPORT.md
```

---

## How to Share & Install

### 1. In Your Team's Git Repository (Zero Setup)
```bash
git add .agents/skills/wstg-audit/
git commit -m "feat(security): add polyglot zero-dependency WSTG audit skill v2.0"
git push
```

### 2. Standalone Git Repo
```bash
npx skills add https://github.com/your-org/wstg-audit-skill --skill wstg-audit
```
