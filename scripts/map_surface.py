#!/usr/bin/env python3
"""
Polyglot Trust-Chain, Gateway-Aware & AI Security Surface Analyzer
Adheres to OWASP WSTG v4.2/v5 and OWASP Top 10 for LLMs / GenAI (2025).

Supported Stacks:
- Python: FastAPI (AST with APIRouter & decorator dependencies, Annotated[Depends]), Django REST, Flask
- TypeScript / JS: NestJS (Global APP_GUARD discovery & @Public scoping), Express.js, Next.js App Router (route.ts)
- Go: Gin, Chi, Fiber, net/http
- Java / Kotlin: Spring Boot (@RestController, @RequestMapping, @PreAuthorize)
- AI / LLM (Polyglot): OpenAI (Chat & Responses), Anthropic, Gemini, LangChain, LiteLLM, Vercel AI SDK
"""

import ast
import json
import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "vendor", "target", "bin",
    "obj", "dist", "build", "__pycache__", ".next", ".nuxt", "tests", "test",
    "coverage", ".vscode", "docs", ".gemini"
}

# ----------------------------------------------------------------------
# 1. Gateway Route Mapping Discovery (Gateway-Awareness)
# ----------------------------------------------------------------------
def discover_gateway_mappings(root_dir):
    """
    Scans the repository for API Gateway route definitions (e.g. FastAPI Gateway container.py,
    Kong/Envoy route tables, Nginx configs) to distinguish externally exposed routes from
    internal microservice routes.
    """
    gateway_routes = {} # service_name -> list of target_prefixes
    public_prefixes = [] # list of public prefixes

    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            if f.endswith((".py", ".ts", ".js", ".json", ".conf", ".yaml", ".yml")):
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                        content = src.read()
                except Exception:
                    continue

                if "RouteMapping(" in content:
                    for line in content.splitlines():
                        if "RouteMapping(" in line:
                            # RouteMapping(public_prefix, service_name, ..., target_prefix=...)
                            m = re.search(r"""RouteMapping\(\s*["']([^"']+)["'],\s*["']([^"']+)["']""", line)
                            if m:
                                pub_prefix = m.group(1)
                                svc_name = m.group(2)
                                target_m = re.search(r"""target_prefix\s*=\s*["']([^"']+)["']""", line)
                                target_prefix = target_m.group(1) if target_m else pub_prefix

                                if svc_name not in gateway_routes:
                                    gateway_routes[svc_name] = []
                                gateway_routes[svc_name].append(target_prefix)
                                public_prefixes.append(pub_prefix)

    return gateway_routes, public_prefixes

# ----------------------------------------------------------------------
# 2. AI / LLM Vulnerability Scanners (OWASP LLM Top 10 - 2025)
# ----------------------------------------------------------------------
AI_IMPORT_PATTERNS = [
    "openai", "anthropic", "litellm", "langchain", "llamaindex",
    "google.generativeai", "google.genai", "@google/genai", "@anthropic-ai",
    "@ai-sdk", "ollama", "mistralai", "groq", "cohere", "huggingface"
]

LLM_CALL_PATTERNS = [
    ".chat.completions.create", ".completions.create", ".responses.create",
    ".messages.create", ".generate_content", ".generatecontent",
    "generatetext(", "streamtext(", "generateobject(",
    "completion(", "ainvoke(", "invoke(", "agent.run(", "chain.run("
]

def scan_file_for_ai_vulnerabilities(file_path, content, ext):
    ai_findings = []
    content_lower = content.lower()

    if not any(imp in content_lower for imp in AI_IMPORT_PATTERNS):
        return ai_findings

    lines = content.splitlines()

    # LLM01: Prompt Injection (Direct user variable formatting into prompts)
    for line_no, line in enumerate(lines, 1):
        line_clean = line.strip()
        if ext == ".py":
            if any(k in line for k in ["prompt =", "prompt=", "content =", "content=", "text =", "instruction ="]):
                if 'f"' in line or "f'" in line or ".format(" in line:
                    if any(v in line.lower() for v in ["user", "answer", "input", "transcript", "text", "query", "message", "body"]):
                        ai_findings.append({
                            "file": file_path.replace("\\", "/"),
                            "line": line_no,
                            "domain": "OWASP-LLM",
                            "code": "LLM01",
                            "severity": "HIGH",
                            "title": "Potential Direct Prompt Injection via Variable Interpolation",
                            "description": f"User-controlled variable interpolated directly into prompt template: {line_clean[:80]}",
                            "stack": "ai-llm-prompt"
                        })
        elif ext in (".ts", ".js", ".tsx", ".jsx"):
            if any(k in line for k in ["prompt", "content", "messages", "instruction", "input"]):
                if "`" in line and "${" in line:
                    if any(v in line.lower() for v in ["user", "answer", "input", "transcript", "text", "query", "req.", "message", "body."]):
                        ai_findings.append({
                            "file": file_path.replace("\\", "/"),
                            "line": line_no,
                            "domain": "OWASP-LLM",
                            "code": "LLM01",
                            "severity": "HIGH",
                            "title": "Potential Direct Prompt Injection via Template Literal",
                            "description": f"User-controlled variable interpolated into prompt: {line_clean[:80]}",
                            "stack": "ai-llm-prompt"
                        })

    # LLM10: Unbounded Consumption / Denial of Wallet
    has_llm_call = any(call in content_lower for call in LLM_CALL_PATTERNS)
    if has_llm_call:
        has_max_tokens = any(k in content for k in [
            "max_tokens", "max_output_tokens", "maxTokens", "max_completion_tokens"
        ])
        has_timeout = any(k in content_lower for k in ["timeout", "timeout_ms", "timeoutms", "timeoutseconds"])
        if not has_max_tokens:
            ai_findings.append({
                "file": file_path.replace("\\", "/"),
                "line": 1,
                "domain": "OWASP-LLM",
                "code": "LLM10",
                "severity": "MEDIUM",
                "title": "LLM Call Missing Explicit Max Tokens Limit (Denial of Wallet)",
                "description": "Model invocation detected without explicit max_tokens/max_output_tokens constraint, risking unbounded generation costs.",
                "stack": "ai-llm-resource"
            })
        if not has_timeout:
            ai_findings.append({
                "file": file_path.replace("\\", "/"),
                "line": 1,
                "domain": "OWASP-LLM",
                "code": "LLM10",
                "severity": "LOW",
                "title": "LLM Call Missing Client-Side Timeout",
                "description": "External model client call without an explicit timeout may hang worker threads indefinitely.",
                "stack": "ai-llm-resource"
            })

    # LLM02: Insecure Output Handling
    if has_llm_call:
        if ext == ".py":
            has_dangerous_sink = any(sink in content_lower for sink in ["subprocess", "os.system", "eval(", "exec("])
        else:
            has_dangerous_sink = any(sink in content_lower for sink in [
                "dangerouslysetinnerhtml", "child_process", "execsync", "eval(", "vm.runin"
            ])
        if has_dangerous_sink:
            ai_findings.append({
                "file": file_path.replace("\\", "/"),
                "line": 1,
                "domain": "OWASP-LLM",
                "code": "LLM02",
                "severity": "HIGH",
                "title": "Potential Insecure Output Handling (Execution / DOM Injection)",
                "description": "File integrates LLM completions and invokes dynamic evaluation or raw HTML/process sinks without intermediate sanitization.",
                "stack": "ai-llm-output"
            })

    # LLM08: Unscoped Vector / RAG Search
    if any(rag in content_lower for rag in ["similarity_search", "vectorstore", "pinecone", "chroma", "qdrant", "weaviate"]):
        if not any(f in content_lower for f in ["filter", "tenant", "metadata", "namespace"]):
            ai_findings.append({
                "file": file_path.replace("\\", "/"),
                "line": 1,
                "domain": "OWASP-LLM",
                "code": "LLM08",
                "severity": "HIGH",
                "title": "Vector Store / RAG Query Missing Tenant Metadata Filter",
                "description": "Vector database similarity search executed without tenant or user namespace filters, risking cross-tenant knowledge leaks.",
                "stack": "ai-rag-security"
            })

    return ai_findings

# ----------------------------------------------------------------------
# 3. Python / FastAPI AST Route & Auth Parser (Deep Router-Aware)
# ----------------------------------------------------------------------
AUTH_POSITIVE_TOKENS = {
    "auth", "user", "token", "guard", "role", "principal", "permission",
    "credential", "verify_", "require_", "login", "authenticated"
}
DB_EXCLUDE_TOKENS = {
    "db", "session", "database", "sessionlocal", "engine", "connection"
}

def is_auth_dependency(dep_name: str) -> bool:
    name_lower = dep_name.lower()
    # If it is exclusively a database session dependency, it is NOT auth
    if any(db in name_lower for db in DB_EXCLUDE_TOKENS) and not any(a in name_lower for a in ["user", "auth", "token", "guard"]):
        return False
    return any(tok in name_lower for tok in AUTH_POSITIVE_TOKENS)

def extract_dep_name(node):
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    elif isinstance(node, ast.Call):
        return extract_dep_name(node.func)
    return None

def analyze_python_file(file_path, gateway_routes=None):
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            tree = ast.parse(content, filename=file_path)
    except Exception:
        return routes

    # Pass 1: Map APIRouter instances and their router-level dependencies and prefixes
    router_configs = {} # var_name -> {"prefix": str, "dependencies": list}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            if isinstance(stmt.value, ast.Call) and getattr(stmt.value.func, "id", None) == "APIRouter":
                prefix = ""
                router_deps = []
                for kw in stmt.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefix = str(kw.value.value).rstrip("/")
                    elif kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Call) and getattr(elt.func, "id", None) == "Depends":
                                if elt.args:
                                    dname = extract_dep_name(elt.args[0])
                                    if dname and is_auth_dependency(dname):
                                        router_deps.append(dname)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        router_configs[target.id] = {"prefix": prefix, "dependencies": router_deps}

    # Identify service name from file path if inside a microservices architecture
    service_name = None
    parts = file_path.replace("\\", "/").split("/")
    if "services" in parts:
        s_idx = parts.index("services")
        if s_idx + 1 < len(parts):
            service_name = parts[s_idx + 1]

    # Pass 2: Map route handler functions
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for decorator in node.decorator_list:
            verb = None
            raw_path = "/"
            router_var = None
            decorator_deps = []

            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                attr_name = decorator.func.attr.lower()
                if attr_name in ("get", "post", "put", "delete", "patch"):
                    verb = attr_name.upper()
                    if isinstance(decorator.func.value, ast.Name):
                        router_var = decorator.func.value.id
                    if decorator.args and isinstance(decorator.args[0], ast.Constant):
                        raw_path = str(decorator.args[0].value)

                    # Check decorator-level dependencies=[Depends(...)]
                    for kw in decorator.keywords:
                        if kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Call) and getattr(elt.func, "id", None) == "Depends":
                                    if elt.args:
                                        dname = extract_dep_name(elt.args[0])
                                        if dname and is_auth_dependency(dname):
                                            decorator_deps.append(dname)

            if verb:
                # Combine router prefix + path
                router_prefix = router_configs.get(router_var, {}).get("prefix", "")
                full_path = f"{router_prefix}{raw_path if raw_path.startswith('/') else '/' + raw_path}"

                # Combine router deps + decorator deps + function param Depends
                auth_guards = list(router_configs.get(router_var, {}).get("dependencies", [])) + decorator_deps

                # Function parameter Depends (defaults + Annotated)
                for default in node.args.defaults:
                    if isinstance(default, ast.Call) and getattr(default.func, "id", None) == "Depends":
                        if default.args:
                            dname = extract_dep_name(default.args[0])
                            if dname and is_auth_dependency(dname):
                                auth_guards.append(dname)

                for arg in node.args.args + node.args.kwonlyargs:
                    if arg.annotation and isinstance(arg.annotation, ast.Subscript):
                        # Annotated[..., Depends(...)]
                        if isinstance(arg.annotation.slice, ast.Tuple):
                            for elt in arg.annotation.slice.elts:
                                if isinstance(elt, ast.Call) and getattr(elt.func, "id", None) == "Depends":
                                    if elt.args:
                                        dname = extract_dep_name(elt.args[0])
                                        if dname and is_auth_dependency(dname):
                                            auth_guards.append(dname)

                func_src = ast.get_source_segment(content, node) or ""
                has_user_check = len(auth_guards) > 0 or any(k in func_src for k in ["current_user", "user_id", "authenticated_user"])
                has_tenant_check = any(k in func_src for k in ["tenant_id", "organization_id", "org_id", "tenant_context"])

                # Precise header reliance check (checks handler code, not whole file)
                trusts_raw_headers = ("x-bantrly" in func_src.lower()) and not has_user_check

                # Gateway Exposure Evaluation
                is_gateway_exposed = True
                if gateway_routes and service_name:
                    exposed_prefixes = gateway_routes.get(service_name, [])
                    is_gateway_exposed = any(full_path.startswith(p) for p in exposed_prefixes)

                routes.append(classify_route(
                    file_path=file_path,
                    line=node.lineno,
                    function=node.name,
                    method=verb,
                    path=full_path,
                    auth_guards=auth_guards,
                    has_user_check=has_user_check,
                    has_tenant_check=has_tenant_check,
                    trusts_raw_headers=trusts_raw_headers,
                    is_gateway_exposed=is_gateway_exposed,
                    stack="python-fastapi"
                ))

    return routes

# ----------------------------------------------------------------------
# 4. TypeScript / JavaScript Parser (NestJS, Express, Next.js)
# ----------------------------------------------------------------------
RE_EXPRESS = re.compile(r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`](.*?)(?:function|\([a-zA-Z0-9_,\s]*\)\s*=>)""", re.DOTALL | re.IGNORECASE)
RE_NESTJS_METHOD = re.compile(r"""@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]?([^'"`\)]*)['"`]?\s*\)""", re.IGNORECASE)
RE_NESTJS_GUARD = re.compile(r"""@UseGuards\s*\((.*?)\)""", re.DOTALL)
RE_NEXTJS_HANDLER = re.compile(r"""export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(""", re.IGNORECASE)

def analyze_ts_js_file(file_path, has_global_auth=False):
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            content = "".join(lines)
    except Exception:
        return routes

    # Next.js App Router (route.ts / route.js)
    if "route.ts" in file_path.lower() or "route.js" in file_path.lower():
        for m in RE_NEXTJS_HANDLER.finditer(content):
            verb = m.group(1).upper()
            line_no = content[:m.start()].count("\n") + 1
            has_auth = any(t in content.lower() for t in ["auth(", "getserversession", "verifytoken", "currentuser"])
            routes.append(classify_route(
                file_path=file_path,
                line=line_no,
                function=f"NextApp_{verb}",
                method=verb,
                path=file_path.replace("\\", "/"),
                auth_guards=["NextAuth"] if has_auth else [],
                has_user_check=has_auth,
                has_tenant_check=False,
                trusts_raw_headers=False,
                is_gateway_exposed=True,
                stack="typescript-nextjs"
            ))

    # NestJS Controllers
    if "@Controller" in content:
        has_class_guard = False
        has_class_public = False
        class_idx = content.find("class ")
        if class_idx != -1:
            pre_class = content[:class_idx]
            has_class_guard = bool(RE_NESTJS_GUARD.search(pre_class))
            has_class_public = "@Public(" in pre_class or "@Public()" in pre_class

        for line_no, line in enumerate(lines, 1):
            line_str = line.strip()
            if line_str.startswith(("//", "/*", "*", "#")):
                continue
            m = RE_NESTJS_METHOD.search(line)
            if m:
                verb = m.group(1).upper()
                path = m.group(2).strip()
                surrounding = "".join(lines[max(0, line_no-8):line_no])
                has_method_guard = bool(RE_NESTJS_GUARD.search(surrounding))
                has_method_public = "@Public(" in surrounding or "@Public()" in surrounding

                is_public = has_class_public or has_method_public
                if has_global_auth:
                    has_guard = not is_public
                    auth_guards = ["APP_GUARD (Global)"] if has_guard else []
                else:
                    has_guard = (has_class_guard or has_method_guard) and not is_public
                    auth_guards = ["@UseGuards"] if has_guard else []

                routes.append(classify_route(
                    file_path=file_path,
                    line=line_no,
                    function=f"Nest_{verb}",
                    method=verb,
                    path=path or "/",
                    auth_guards=auth_guards,
                    has_user_check=has_guard,
                    has_tenant_check=False,
                    trusts_raw_headers=False,
                    is_gateway_exposed=True,
                    stack="typescript-nestjs"
                ))

    # Express.js (router.get, app.post)
    for m in RE_EXPRESS.finditer(content):
        verb = m.group(1).upper()
        path = m.group(2)
        middleware_block = m.group(3)
        has_auth = any(t in middleware_block.lower() for t in ["auth", "jwt", "guard", "protect", "verify", "role"])
        line_no = content[:m.start()].count("\n") + 1
        routes.append(classify_route(
            file_path=file_path,
            line=line_no,
            function=f"Express_{verb}",
            method=verb,
            path=path,
            auth_guards=["middleware"] if has_auth else [],
            has_user_check=has_auth,
            has_tenant_check=False,
            trusts_raw_headers=False,
            is_gateway_exposed=True,
            stack="javascript-express"
        ))

    return routes

# ----------------------------------------------------------------------
# 5. Java / Kotlin Parser (Spring Boot)
# ----------------------------------------------------------------------
RE_SPRING_CONTROLLER = re.compile(r"""@(RestController|Controller)""")
RE_SPRING_MAPPING = re.compile(r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", re.IGNORECASE)
RE_SPRING_AUTH = re.compile(r"""@(PreAuthorize|Secured|RolesAllowed)""")

def analyze_java_file(file_path):
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            content = "".join(lines)
    except Exception:
        return routes

    if not RE_SPRING_CONTROLLER.search(content):
        return routes

    has_class_auth = bool(RE_SPRING_AUTH.search(content[:content.find("class ")])) if "class " in content else False

    for line_no, line in enumerate(lines, 1):
        if line.strip().startswith(("//", "/*", "*")):
            continue
        m = RE_SPRING_MAPPING.search(line)
        if m:
            anno = m.group(1).upper()
            verb = "GET" if "GET" in anno else "POST" if "POST" in anno else "PUT" if "PUT" in anno else "DELETE" if "DELETE" in anno else "ALL"
            path = m.group(2)
            surrounding = "".join(lines[max(0, line_no-6):line_no])
            has_auth = has_class_auth or bool(RE_SPRING_AUTH.search(surrounding))

            routes.append(classify_route(
                file_path=file_path,
                line=line_no,
                function=f"Spring_{verb}",
                method=verb,
                path=path,
                auth_guards=["@PreAuthorize/@Secured"] if has_auth else [],
                has_user_check=has_auth,
                has_tenant_check=False,
                trusts_raw_headers=False,
                is_gateway_exposed=True,
                stack="java-spring"
            ))

    return routes

# ----------------------------------------------------------------------
# 6. Go Parser (Gin, Chi, Fiber, net/http)
# ----------------------------------------------------------------------
RE_GO_ROUTE = re.compile(r"""(?:r|router|api|v1|app|group)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["']([^"']+)["'],\s*(.*?)\)""", re.IGNORECASE)

def analyze_go_file(file_path):
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return routes

    for m in RE_GO_ROUTE.finditer(content):
        verb = m.group(1).upper()
        path = m.group(2)
        handlers = m.group(3)
        has_auth = any(t in handlers.lower() for t in ["auth", "jwt", "require", "middleware", "token"])
        line_no = content[:m.start()].count("\n") + 1
        routes.append(classify_route(
            file_path=file_path,
            line=line_no,
            function=f"Go_{verb}",
            method=verb,
            path=path,
            auth_guards=["HandlerMiddleware"] if has_auth else [],
            has_user_check=has_auth,
            has_tenant_check=False,
            trusts_raw_headers=False,
            is_gateway_exposed=True,
            stack="go-gin/fiber"
        ))
    return routes

# ----------------------------------------------------------------------
# 7. Common Classifier & Threat Archetype Triage
# ----------------------------------------------------------------------
def classify_route(file_path, line, function, method, path, auth_guards, has_user_check, has_tenant_check, trusts_raw_headers, is_gateway_exposed, stack):
    is_unauthenticated = len(auth_guards) == 0
    is_dangerous_verb = method in ("DELETE", "PUT", "PATCH", "POST")
    has_path_id = ("{" in path or ":" in path) and any(k in path.lower() for k in ["id", "key", "uuid", "email", "user"])

    threat_flags = []

    if is_unauthenticated and is_dangerous_verb:
        if is_gateway_exposed:
            threat_flags.append("CRITICAL: Public Unauthenticated Mutating Route (Gateway-Exposed F01/F03 archetype)")
        else:
            threat_flags.append("LOW: Internal-Only Unauthenticated Mutating Route (Unexposed via Gateway)")
    elif is_unauthenticated and has_path_id:
        if is_gateway_exposed:
            threat_flags.append("HIGH: Public Parameter Lookup without Auth (F02 Redis/Secret archetype)")
        else:
            threat_flags.append("LOW: Internal Parameter Lookup (Unexposed via Gateway)")
    elif is_dangerous_verb and has_path_id and not has_tenant_check and not has_user_check:
        threat_flags.append("HIGH: Potential BOLA / Missing Ownership Verification (F04 archetype)")

    if trusts_raw_headers:
        threat_flags.append("MEDIUM: Route Inspects Internal Headers without Caller Verification (R01 archetype)")

    return {
        "file": file_path.replace("\\", "/"),
        "line": line,
        "stack": stack,
        "function": function,
        "method": method,
        "path": path,
        "auth_guards": auth_guards,
        "is_unauthenticated": is_unauthenticated,
        "is_gateway_exposed": is_gateway_exposed,
        "has_path_id": has_path_id,
        "threat_flags": threat_flags
    }

# ----------------------------------------------------------------------
# 8. Main Walker
# ----------------------------------------------------------------------
def detect_global_auth_guards(root_dir):
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            if f.endswith((".module.ts", "main.ts", "bootstrap.ts", ".module.js", "main.js")):
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                        content = src.read()
                        if "APP_GUARD" in content and any(g in content for g in ["AuthGuard", "JwtAuthGuard", "JwtGuard", "TokenGuard"]):
                            return True
                        if "useGlobalGuards" in content and any(g in content for g in ["AuthGuard", "JwtAuthGuard", "JwtGuard"]):
                            return True
                except Exception:
                    continue
    return False

def scan_codebase(root_dir="."):
    all_routes = []
    flagged_threats = []
    ai_vulnerabilities = []

    # 1. Discover Gateway Mappings
    gateway_routes, public_prefixes = discover_gateway_mappings(root_dir)

    # 2. Discover NestJS Global Guards
    has_global_auth = detect_global_auth_guards(root_dir)

    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in (".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".java"):
                continue

            fpath = os.path.join(root, f)
            try:
                if os.path.getsize(fpath) > 1024 * 1024:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                    content = src.read()
            except Exception:
                continue

            # A. Scan for AI / LLM Vulnerabilities
            ai_vulns = scan_file_for_ai_vulnerabilities(fpath, content, ext)
            ai_vulnerabilities.extend(ai_vulns)

            # B. Scan Web Routes
            fname_lower = f.lower()
            is_web_file = any(t in fname_lower for t in ["route", "controller", "server", "app", "router", "endpoint", "api", "view"])

            if ext == ".py" and is_web_file:
                routes = analyze_python_file(fpath, gateway_routes=gateway_routes)
                all_routes.extend(routes)
            elif ext in (".ts", ".js", ".tsx", ".jsx") and (is_web_file or "route.ts" in fname_lower):
                routes = analyze_ts_js_file(fpath, has_global_auth=has_global_auth)
                all_routes.extend(routes)
            elif ext == ".go" and is_web_file:
                routes = analyze_go_file(fpath)
                all_routes.extend(routes)
            elif ext == ".java" and is_web_file:
                routes = analyze_java_file(fpath)
                all_routes.extend(routes)

    for r in all_routes:
        if r["threat_flags"]:
            flagged_threats.append(r)

    return {
        "gateway_routes_discovered": len(public_prefixes),
        "global_auth_enforced": has_global_auth,
        "total_endpoints": len(all_routes),
        "total_flagged_threats": len(flagged_threats),
        "total_ai_vulnerabilities": len(ai_vulnerabilities),
        "ai_vulnerabilities": ai_vulnerabilities,
        "flagged_threats": flagged_threats,
        "all_endpoints": all_routes
    }

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(".wstg-audit", "surface_map.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    result = scan_codebase(target)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"Polyglot + Gateway-Aware Surface Analysis Complete:")
    print(f"  • Gateway Routes Discovered: {result['gateway_routes_discovered']}")
    print(f"  • Global Auth Guard Detected: {result['global_auth_enforced']}")
    print(f"  • Total Web Endpoints: {result['total_endpoints']}")
    print(f"  • Flagged Architectural Threats: {result['total_flagged_threats']}")
    print(f"  • AI/LLM Vulnerabilities Detected: {result['total_ai_vulnerabilities']}")
    print(f"  • Output: {out}")
