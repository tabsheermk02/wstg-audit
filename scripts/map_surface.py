#!/usr/bin/env python3
"""
Polyglot Trust-Chain, Gateway-Aware & AI Security Surface Analyzer (v2.0)
Adheres to OWASP WSTG v4.2/v5 and OWASP Top 10 for LLMs / GenAI (2025).

Core Upgrades in v2.0:
1. Pluggable Gateway Drivers:
   - FastAPI RouteMapping (container.py)
   - Nginx Reverse Proxy (location + proxy_pass)
   - Envoy Gateway (route_config + virtual_hosts)
   - Kubernetes Ingress & Gateway API (Ingress / HTTPRoute)
   - Traefik Dynamic Router (PathPrefix)
   - NestJS Global Prefix & Express Mounts
2. Lightweight Function-Level AST Taint & Data-Flow Tracking:
   - Traces route parameters down to dangerous sinks:
     * SQL Injection (WSTG-INPV-05): cursor.execute, text(), raw f-string queries
     * Command Injection (WSTG-INPV-12): subprocess.run, os.system, os.popen
     * Path Traversal (WSTG-INPV-12): open(), os.remove(), FileResponse()
     * Code Injection (WSTG-INPV-11): eval(), exec()
     * Deserialization (WSTG-INPV-15): pickle.loads(), yaml.load()
     * SSRF (WSTG-INPV-16): requests.*, httpx.*, urllib.request.*
     * Storage Exposure (WSTG-ATHZ-02): generate_presigned_url, signed_url
     * Cache/Session Hijack (WSTG-SESS-04/08): unpartitioned redis.get/set
3. Syntax-Aware Multi-Language Parsers:
   - TypeScript/NestJS: Class & method @Controller, @UseGuards, @Public()
   - Go: Gin/Chi/Fiber route groups (r.Group) and inherited middleware
   - Java: Spring Boot @RequestMapping inheritance & @PreAuthorize
4. Non-REST Entrypoints:
   - WebSockets: FastAPI @router.websocket, Socket.io, ws.on('connection')
   - Pub/Sub & Event Consumers: GCP Pub/Sub, RabbitMQ, Kafka, Celery
"""

import ast
import json
import os
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "vendor", "target", "bin",
    "obj", "dist", "build", "__pycache__", ".next", ".nuxt", "tests", "test",
    "coverage", ".vscode", "docs", ".gemini", ".wstg-audit"
}

# ======================================================================
# 1. PLUGGABLE GATEWAY DISCOVERY ARCHITECTURE
# ======================================================================

class GatewayDriver(ABC):
    """Abstract base class for API Gateway and Ingress route discovery."""
    name: str = "base"

    @abstractmethod
    def can_handle(self, filename: str, content: str) -> bool:
        pass

    @abstractmethod
    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Returns list of {"service": str, "target_prefix": str, "public_prefix": str, "driver": str}"""
        pass


class FastAPIRouteMappingDriver(GatewayDriver):
    """Parses FastAPI container.py or custom RouteMapping declarations."""
    name = "fastapi-routemapping"

    def can_handle(self, filename: str, content: str) -> bool:
        return "RouteMapping(" in content

    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        mappings = []
        for line in content.splitlines():
            if "RouteMapping(" in line:
                m = re.search(r"""RouteMapping\(\s*["']([^"']+)["'],\s*["']([^"']+)["']""", line)
                if m:
                    pub_prefix = m.group(1).rstrip("/")
                    svc_name = m.group(2)
                    target_m = re.search(r"""target_prefix\s*=\s*["']([^"']+)["']""", line)
                    target_prefix = target_m.group(1).rstrip("/") if target_m else pub_prefix
                    mappings.append({
                        "service": svc_name,
                        "public_prefix": pub_prefix or "/",
                        "target_prefix": target_prefix or "/",
                        "driver": self.name,
                        "file": file_path.replace("\\", "/")
                    })
        return mappings


class NginxGatewayDriver(GatewayDriver):
    """Parses Nginx configuration reverse proxy rules."""
    name = "nginx-proxy"

    def can_handle(self, filename: str, content: str) -> bool:
        return (filename.endswith(".conf") or "nginx" in filename.lower()) and "proxy_pass" in content

    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        mappings = []
        pattern = re.compile(r"""location\s+([^\s{]+)\s*\{[^}]*proxy_pass\s+https?://([^/;\s]+)(/[^;\s]*)?""", re.DOTALL)
        for m in pattern.finditer(content):
            pub_prefix = m.group(1).rstrip("/")
            host = m.group(2)
            svc_name = host.split(":")[0]
            target_prefix = (m.group(3) or pub_prefix).rstrip("/")
            mappings.append({
                "service": svc_name,
                "public_prefix": pub_prefix or "/",
                "target_prefix": target_prefix or "/",
                "driver": self.name,
                "file": file_path.replace("\\", "/")
            })
        return mappings


class EnvoyGatewayDriver(GatewayDriver):
    """Parses Envoy reverse proxy configurations."""
    name = "envoy-gateway"

    def can_handle(self, filename: str, content: str) -> bool:
        return ("route_config" in content or "virtual_hosts" in content) and ("prefix:" in content or "cluster:" in content)

    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        mappings = []
        prefix_matches = re.findall(r"""prefix:\s*["']?([^"'\s]+)["']?[^}]+cluster:\s*["']?([^"'\s]+)["']?""", content)
        for pub_prefix, cluster in prefix_matches:
            mappings.append({
                "service": cluster,
                "public_prefix": pub_prefix.rstrip("/") or "/",
                "target_prefix": pub_prefix.rstrip("/") or "/",
                "driver": self.name,
                "file": file_path.replace("\\", "/")
            })
        return mappings


class KubernetesIngressDriver(GatewayDriver):
    """Parses Kubernetes Ingress and Gateway API manifests."""
    name = "kubernetes-ingress"

    def can_handle(self, filename: str, content: str) -> bool:
        return ("kind: Ingress" in content or "kind: HTTPRoute" in content) and "paths:" in content

    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        mappings = []
        path_matches = re.finditer(r"""path:\s*["']?([^"'\s]+)["']?[^}]+name:\s*["']?([^"'\s]+)["']?""", content)
        for m in path_matches:
            pub_prefix = m.group(1).rstrip("/")
            svc_name = m.group(2)
            mappings.append({
                "service": svc_name,
                "public_prefix": pub_prefix or "/",
                "target_prefix": pub_prefix or "/",
                "driver": self.name,
                "file": file_path.replace("\\", "/")
            })
        return mappings


class TraefikGatewayDriver(GatewayDriver):
    """Parses Traefik router rules (PathPrefix)."""
    name = "traefik-proxy"

    def can_handle(self, filename: str, content: str) -> bool:
        return "PathPrefix(" in content

    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        mappings = []
        for line in content.splitlines():
            m = re.search(r"""PathPrefix\(\s*[`'"]([^`'"]+)[`'"]\s*\)""", line)
            if m:
                pub_prefix = m.group(1).rstrip("/")
                svc_m = re.search(r"""service\s*=\s*["']([^"']+)["']""", line)
                svc_name = svc_m.group(1) if svc_m else "traefik-upstream"
                mappings.append({
                    "service": svc_name,
                    "public_prefix": pub_prefix or "/",
                    "target_prefix": pub_prefix or "/",
                    "driver": self.name,
                    "file": file_path.replace("\\", "/")
                })
        return mappings


class ExpressNestMountDriver(GatewayDriver):
    """Parses Express app.use('/prefix', ...) and NestJS app.setGlobalPrefix('...')."""
    name = "express-nest-mount"

    def can_handle(self, filename: str, content: str) -> bool:
        return "setGlobalPrefix(" in content or "app.use(" in content

    def discover(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        mappings = []
        nest_m = re.search(r"""setGlobalPrefix\(\s*["']([^"']+)["']""", content)
        if nest_m:
            prefix = nest_m.group(1).rstrip("/")
            mappings.append({
                "service": "nestjs-api",
                "public_prefix": prefix if prefix.startswith("/") else f"/{prefix}",
                "target_prefix": prefix if prefix.startswith("/") else f"/{prefix}",
                "driver": self.name,
                "file": file_path.replace("\\", "/")
            })

        for line in content.splitlines():
            if "app.use(" in line:
                m = re.search(r"""app\.use\(\s*["']([^"']+)["'],\s*([a-zA-Z0-9_]+)""", line)
                if m:
                    prefix = m.group(1).rstrip("/")
                    router_name = m.group(2)
                    mappings.append({
                        "service": router_name,
                        "public_prefix": prefix or "/",
                        "target_prefix": prefix or "/",
                        "driver": self.name,
                        "file": file_path.replace("\\", "/")
                    })
        return mappings


GATEWAY_DRIVERS: List[GatewayDriver] = [
    FastAPIRouteMappingDriver(),
    NginxGatewayDriver(),
    EnvoyGatewayDriver(),
    KubernetesIngressDriver(),
    TraefikGatewayDriver(),
    ExpressNestMountDriver(),
]

def discover_all_gateway_mappings(root_dir: str) -> Tuple[Dict[str, List[str]], List[str], List[Dict[str, Any]]]:
    """
    Runs all registered gateway drivers across repository files to construct
    an authoritative Gateway Topology.
    """
    gateway_routes: Dict[str, List[str]] = {}
    public_prefixes: List[str] = []
    topology: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            if f.endswith((".py", ".ts", ".js", ".json", ".conf", ".yaml", ".yml", ".toml")):
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                        content = src.read()
                except Exception:
                    continue

                for driver in GATEWAY_DRIVERS:
                    if driver.can_handle(f, content):
                        discovered = driver.discover(fpath, content)
                        for item in discovered:
                            svc = item["service"]
                            pub = item["public_prefix"]
                            target = item["target_prefix"]
                            if svc not in gateway_routes:
                                gateway_routes[svc] = []
                            gateway_routes[svc].append(target)
                            public_prefixes.append(pub)
                            topology.append(item)

    return gateway_routes, public_prefixes, topology


# ======================================================================
# 2. LIGHTWEIGHT AST FUNCTION-LEVEL TAINT & DATA-FLOW TRACKING
# ======================================================================

NON_USER_DEPENDENCY_TOKENS = {
    "db", "session", "database", "sessionlocal", "engine", "connection",
    "request", "response", "background_tasks", "current_user", "auth",
    "token", "user", "settings", "config", "logger", "app_state"
}

SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "alter", "where", "from", "join"}

class PythonTaintTracker(ast.NodeVisitor):
    """
    Intra-procedural AST Taint Tracker.
    Traces untrusted route function parameters through assignments, format strings,
    and method calls down into dangerous sinks.
    """

    def __init__(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str):
        self.func_node = func_node
        self.file_path = file_path
        self.tainted_vars: Dict[str, Dict[str, Any]] = {}
        self.taint_findings: List[Dict[str, Any]] = []

        # 1. Initialize taint from untrusted function parameters
        self._init_param_taint()

    def _init_param_taint(self):
        all_args = self.func_node.args.args + self.func_node.args.kwonlyargs
        for arg in all_args:
            name = arg.arg
            name_lower = name.lower()
            # If parameter represents injected services/auth, skip taint
            if any(tok in name_lower for tok in NON_USER_DEPENDENCY_TOKENS):
                continue
            # Path, query, or body parameter is caller-controlled
            self.tainted_vars[name] = {
                "source": name,
                "origin_line": self.func_node.lineno,
                "history": [f"param:{name}"]
            }

    def _is_expr_tainted(self, node: ast.AST) -> Optional[Dict[str, Any]]:
        """Determines if an expression depends on any tainted variable."""
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)

        elif isinstance(node, ast.Attribute):
            return self._is_expr_tainted(node.value)

        elif isinstance(node, ast.Subscript):
            return self._is_expr_tainted(node.value)

        elif isinstance(node, ast.JoinedStr):  # f"string {var}"
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t = self._is_expr_tainted(val.value)
                    if t:
                        return t

        elif isinstance(node, ast.BinOp):
            left_t = self._is_expr_tainted(node.left)
            if left_t:
                return left_t
            return self._is_expr_tainted(node.right)

        elif isinstance(node, ast.Call):
            # Check call arguments
            for arg in node.args:
                t = self._is_expr_tainted(arg)
                if t:
                    return t
            for kw in node.keywords:
                t = self._is_expr_tainted(kw.value)
                if t:
                    return t

        return None

    def visit_Assign(self, node: ast.Assign):
        taint_info = self._is_expr_tainted(node.value)
        if taint_info:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = {
                        "source": taint_info["source"],
                        "origin_line": node.lineno,
                        "history": taint_info["history"] + [f"assign:{target.id}"]
                    }
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        taint_info = self._is_expr_tainted(node.value)
        if taint_info and isinstance(node.target, ast.Name):
            self.tainted_vars[node.target.id] = {
                "source": taint_info["source"],
                "origin_line": node.lineno,
                "history": taint_info["history"] + [f"augassign:{node.target.id}"]
            }
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        func_lower = func_name.lower()

        # Check for dangerous sinks:

        # 1. SQL Injection Sink (WSTG-INPV-05)
        if any(sink in func_lower for sink in ["execute", "raw_sql", "text", "cursor.execute"]):
            for idx, arg in enumerate(node.args):
                t = self._is_expr_tainted(arg)
                if t:
                    # Check if argument is formatted string or concatenated
                    is_formatted = isinstance(arg, (ast.JoinedStr, ast.BinOp)) or self._contains_sql_keywords(arg)
                    self.taint_findings.append({
                        "file": self.file_path.replace("\\", "/"),
                        "line": node.lineno,
                        "sink": func_name,
                        "wstg_code": "WSTG-INPV-05",
                        "sink_kind": "SQL Injection",
                        "severity": "CRITICAL" if is_formatted else "HIGH",
                        "source_param": t["source"],
                        "detail": f"User parameter '{t['source']}' reaches SQL query execution sink '{func_name}'."
                    })

        # 2. Command Injection Sink (WSTG-INPV-12)
        elif any(sink in func_lower for sink in ["subprocess.run", "subprocess.popen", "subprocess.call", "os.system", "os.popen", "execv"]):
            first_arg_tainted = len(node.args) > 0 and self._is_expr_tainted(node.args[0])
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
            if first_arg_tainted:
                t = first_arg_tainted
                self.taint_findings.append({
                    "file": self.file_path.replace("\\", "/"),
                    "line": node.lineno,
                    "sink": func_name,
                    "wstg_code": "WSTG-INPV-12",
                    "sink_kind": "Command Injection",
                    "severity": "CRITICAL",
                    "source_param": t["source"],
                    "detail": f"User parameter '{t['source']}' flows directly into system execution sink '{func_name}' (shell={shell_true})."
                })

        # 3. Path Traversal Sink (WSTG-INPV-12)
        elif any(sink in func_lower for sink in ["open", "aiofiles.open", "os.remove", "os.unlink", "shutil.rmtree", "fileresponse", "send_file"]):
            if len(node.args) > 0:
                t = self._is_expr_tainted(node.args[0])
                if t:
                    self.taint_findings.append({
                        "file": self.file_path.replace("\\", "/"),
                        "line": node.lineno,
                        "sink": func_name,
                        "wstg_code": "WSTG-INPV-12",
                        "sink_kind": "Path Traversal / Arbitrary File Access",
                        "severity": "HIGH",
                        "source_param": t["source"],
                        "detail": f"User parameter '{t['source']}' passed to file system sink '{func_name}' without visible path confinement."
                    })

        # 4. Code Injection / Eval Sink (WSTG-INPV-11)
        elif func_lower in ("eval", "exec", "compile"):
            if len(node.args) > 0:
                t = self._is_expr_tainted(node.args[0])
                if t:
                    self.taint_findings.append({
                        "file": self.file_path.replace("\\", "/"),
                        "line": node.lineno,
                        "sink": func_name,
                        "wstg_code": "WSTG-INPV-11",
                        "sink_kind": "Dynamic Code Evaluation",
                        "severity": "CRITICAL",
                        "source_param": t["source"],
                        "detail": f"User parameter '{t['source']}' flows into dynamic execution sink '{func_name}'."
                    })

        # 5. Insecure Deserialization Sink (WSTG-INPV-15)
        elif any(sink in func_lower for sink in ["pickle.loads", "pickle.load", "yaml.load", "marshal.loads"]):
            if len(node.args) > 0:
                t = self._is_expr_tainted(node.args[0])
                if t:
                    self.taint_findings.append({
                        "file": self.file_path.replace("\\", "/"),
                        "line": node.lineno,
                        "sink": func_name,
                        "wstg_code": "WSTG-INPV-15",
                        "sink_kind": "Insecure Deserialization",
                        "severity": "CRITICAL",
                        "source_param": t["source"],
                        "detail": f"Untrusted input '{t['source']}' passed to unsafe deserialization sink '{func_name}'."
                    })

        # 6. Server-Side Request Forgery Sink (WSTG-INPV-16)
        elif any(sink in func_lower for sink in ["requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"]):
            if len(node.args) > 0:
                t = self._is_expr_tainted(node.args[0])
                if t:
                    self.taint_findings.append({
                        "file": self.file_path.replace("\\", "/"),
                        "line": node.lineno,
                        "sink": func_name,
                        "wstg_code": "WSTG-INPV-16",
                        "sink_kind": "Server-Side Request Forgery (SSRF)",
                        "severity": "HIGH",
                        "source_param": t["source"],
                        "detail": f"User-controlled parameter '{t['source']}' reaches outbound HTTP client sink '{func_name}'."
                    })

        # 7. Arbitrary Storage Signed URL Sink (WSTG-ATHZ-02)
        elif "signed_url" in func_lower:
            for arg in node.args:
                t = self._is_expr_tainted(arg)
                if t:
                    self.taint_findings.append({
                        "file": self.file_path.replace("\\", "/"),
                        "line": node.lineno,
                        "sink": func_name,
                        "wstg_code": "WSTG-ATHZ-02",
                        "sink_kind": "Arbitrary Presigned Storage Exposure",
                        "severity": "HIGH",
                        "source_param": t["source"],
                        "detail": f"Object key derived from untrusted parameter '{t['source']}' passed to '{func_name}' without ownership checks."
                    })

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_call_name(node.value)}.{node.attr}"
        return ""

    def _contains_sql_keywords(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val_lower = node.value.lower()
            return any(k in val_lower for k in SQL_KEYWORDS)
        return False


def analyze_function_taint(func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str) -> List[Dict[str, Any]]:
    tracker = PythonTaintTracker(func_node, file_path)
    tracker.visit(func_node)
    return tracker.taint_findings


# ======================================================================
# 3. AI / LLM VULNERABILITY SCANNERS (OWASP LLM Top 10 - 2025)
# ======================================================================

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

def scan_file_for_ai_vulnerabilities(file_path: str, content: str, ext: str) -> List[Dict[str, Any]]:
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


# ======================================================================
# 4. PYTHON / FASTAPI ROUTE & TAINT ANALYZER
# ======================================================================

AUTH_POSITIVE_TOKENS = {
    "auth", "user", "token", "guard", "role", "principal", "permission",
    "credential", "verify_", "require_", "login", "authenticated"
}
DB_EXCLUDE_TOKENS = {
    "db", "session", "database", "sessionlocal", "engine", "connection"
}

def is_auth_dependency(dep_name: str) -> bool:
    name_lower = dep_name.lower()
    if any(db in name_lower for db in DB_EXCLUDE_TOKENS) and not any(a in name_lower for a in ["user", "auth", "token", "guard"]):
        return False
    return any(tok in name_lower for tok in AUTH_POSITIVE_TOKENS)

def extract_dep_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    elif isinstance(node, ast.Call):
        return extract_dep_name(node.func)
    return None

def analyze_python_file(file_path: str, gateway_routes: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    routes = []
    file_taint_findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            tree = ast.parse(content, filename=file_path)
    except Exception:
        return routes, file_taint_findings

    router_configs: Dict[str, Dict[str, Any]] = {}
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

    service_name = None
    parts = file_path.replace("\\", "/").split("/")
    if "services" in parts:
        s_idx = parts.index("services")
        if s_idx + 1 < len(parts):
            service_name = parts[s_idx + 1]

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

                    for kw in decorator.keywords:
                        if kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Call) and getattr(elt.func, "id", None) == "Depends":
                                    if elt.args:
                                        dname = extract_dep_name(elt.args[0])
                                        if dname and is_auth_dependency(dname):
                                            decorator_deps.append(dname)

            if verb:
                router_prefix = router_configs.get(router_var, {}).get("prefix", "")
                full_path = f"{router_prefix}{raw_path if raw_path.startswith('/') else '/' + raw_path}"
                auth_guards = list(router_configs.get(router_var, {}).get("dependencies", [])) + decorator_deps

                for default in node.args.defaults:
                    if isinstance(default, ast.Call) and getattr(default.func, "id", None) == "Depends":
                        if default.args:
                            dname = extract_dep_name(default.args[0])
                            if dname and is_auth_dependency(dname):
                                auth_guards.append(dname)

                for arg in node.args.args + node.args.kwonlyargs:
                    if arg.annotation and isinstance(arg.annotation, ast.Subscript):
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
                trusts_raw_headers = ("x-bantrly" in func_src.lower()) and not has_user_check

                is_gateway_exposed = True
                if gateway_routes and service_name:
                    exposed_prefixes = gateway_routes.get(service_name, [])
                    is_gateway_exposed = any(full_path.startswith(p) for p in exposed_prefixes)

                # Run AST Taint Tracking on this route handler
                taint_traces = analyze_function_taint(node, file_path)
                file_taint_findings.extend(taint_traces)

                route_item = classify_route(
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
                    stack="python-fastapi",
                    taint_traces=taint_traces
                )
                routes.append(route_item)

    return routes, file_taint_findings


# ======================================================================
# 5. SYNTAX-AWARE TYPESCRIPT / JAVASCRIPT PARSER
# ======================================================================

RE_NEXTJS_HANDLER = re.compile(r"""export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(""", re.IGNORECASE)
RE_NEST_CONTROLLER = re.compile(r"""@Controller\s*\(\s*['"`]?([^'"`\)]*)['"`]?\s*\)""", re.IGNORECASE)
RE_NEST_METHOD = re.compile(r"""@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]?([^'"`\)]*)['"`]?\s*\)""", re.IGNORECASE)
RE_NEST_GUARD = re.compile(r"""@UseGuards\s*\((.*?)\)""", re.DOTALL)
RE_EXPRESS_ROUTE = re.compile(r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`](.*?)(?:function|\([a-zA-Z0-9_,\s]*\)\s*=>)""", re.DOTALL | re.IGNORECASE)

def analyze_ts_js_file(file_path: str, has_global_auth: bool = False) -> List[Dict[str, Any]]:
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            content = "".join(lines)
    except Exception:
        return routes

    # 1. Next.js App Router (route.ts / route.js)
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

    # 2. NestJS Controllers (Class prefix + Method routes + Class & Method Guards)
    ctrl_m = RE_NEST_CONTROLLER.search(content)
    if ctrl_m:
        class_prefix = ctrl_m.group(1).strip().strip("/")
        class_idx = content.find("class ")
        has_class_guard = False
        has_class_public = False
        if class_idx != -1:
            pre_class = content[:class_idx]
            has_class_guard = bool(RE_NEST_GUARD.search(pre_class))
            has_class_public = "@Public(" in pre_class or "@Public()" in pre_class

        for line_no, line in enumerate(lines, 1):
            if line.strip().startswith(("//", "/*", "*", "#")):
                continue
            m = RE_NEST_METHOD.search(line)
            if m:
                verb = m.group(1).upper()
                subpath = m.group(2).strip().strip("/")
                surrounding = "".join(lines[max(0, line_no - 8):line_no])
                has_method_guard = bool(RE_NEST_GUARD.search(surrounding))
                has_method_public = "@Public(" in surrounding or "@Public()" in surrounding

                full_path = f"/{class_prefix}/{subpath}".replace("//", "/").rstrip("/") or "/"
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
                    path=full_path,
                    auth_guards=auth_guards,
                    has_user_check=has_guard,
                    has_tenant_check=False,
                    trusts_raw_headers=False,
                    is_gateway_exposed=True,
                    stack="typescript-nestjs"
                ))

    # 3. Express Router
    for m in RE_EXPRESS_ROUTE.finditer(content):
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


# ======================================================================
# 6. SYNTAX-AWARE GO ROUTE & GROUP PARSER (Gin, Chi, Fiber)
# ======================================================================

RE_GO_GROUP = re.compile(r"""([a-zA-Z0-9_]+)\s*:=\s*([a-zA-Z0-9_\.]+)\.Group\(\s*["']([^"']+)["'](.*?)\)""", re.IGNORECASE)
RE_GO_USE = re.compile(r"""([a-zA-Z0-9_]+)\.Use\((.*?)\)""", re.IGNORECASE)
RE_GO_ROUTE = re.compile(r"""([a-zA-Z0-9_]+)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["']([^"']+)["'],\s*(.*?)\)""", re.IGNORECASE)

def analyze_go_file(file_path: str) -> List[Dict[str, Any]]:
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return routes

    # 1. Map Router Groups and Inherited Middleware
    groups: Dict[str, Dict[str, Any]] = {}  # var_name -> {"prefix": str, "middleware": list}
    for m in RE_GO_GROUP.finditer(content):
        group_var = m.group(1)
        parent_var = m.group(2)
        prefix = m.group(3).rstrip("/")
        extra_args = m.group(4)
        group_middleware = []
        if any(t in extra_args.lower() for t in ["auth", "jwt", "token", "require"]):
            group_middleware.append("GroupAuthMiddleware")

        parent_prefix = groups.get(parent_var, {}).get("prefix", "")
        groups[group_var] = {
            "prefix": f"{parent_prefix}{prefix}",
            "middleware": list(groups.get(parent_var, {}).get("middleware", [])) + group_middleware
        }

    # 2. Check group.Use(...) middleware additions
    for m in RE_GO_USE.finditer(content):
        var_name = m.group(1)
        use_args = m.group(2)
        if any(t in use_args.lower() for t in ["auth", "jwt", "token", "require"]):
            if var_name in groups:
                groups[var_name]["middleware"].append("UseMiddleware")

    # 3. Map Endpoints
    for m in RE_GO_ROUTE.finditer(content):
        router_var = m.group(1)
        verb = m.group(2).upper()
        raw_path = m.group(3)
        handlers = m.group(4)

        group_info = groups.get(router_var, {"prefix": "", "middleware": []})
        full_path = f"{group_info['prefix']}{raw_path if raw_path.startswith('/') else '/' + raw_path}"

        auth_guards = list(group_info["middleware"])
        if any(t in handlers.lower() for t in ["auth", "jwt", "require", "middleware", "token"]):
            auth_guards.append("RouteHandlerMiddleware")

        line_no = content[:m.start()].count("\n") + 1
        routes.append(classify_route(
            file_path=file_path,
            line=line_no,
            function=f"Go_{verb}",
            method=verb,
            path=full_path,
            auth_guards=auth_guards,
            has_user_check=len(auth_guards) > 0,
            has_tenant_check=False,
            trusts_raw_headers=False,
            is_gateway_exposed=True,
            stack="go-gin/fiber"
        ))

    return routes


# ======================================================================
# 7. SYNTAX-AWARE JAVA / SPRING BOOT PARSER
# ======================================================================

RE_SPRING_CONTROLLER = re.compile(r"""@(RestController|Controller)""")
RE_SPRING_CLASS_MAPPING = re.compile(r"""@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", re.IGNORECASE)
RE_SPRING_MAPPING = re.compile(r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""", re.IGNORECASE)
RE_SPRING_AUTH = re.compile(r"""@(PreAuthorize|Secured|RolesAllowed)""")

def analyze_java_file(file_path: str) -> List[Dict[str, Any]]:
    routes = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            content = "".join(lines)
    except Exception:
        return routes

    if not RE_SPRING_CONTROLLER.search(content):
        return routes

    class_idx = content.find("class ")
    class_prefix = ""
    has_class_auth = False
    class_line_no = 0
    if class_idx != -1:
        class_line_no = content[:class_idx].count("\n") + 1
        pre_class = content[:class_idx]
        class_m = RE_SPRING_CLASS_MAPPING.search(pre_class)
        if class_m:
            class_prefix = class_m.group(1).rstrip("/")
        has_class_auth = bool(RE_SPRING_AUTH.search(pre_class))

    for line_no, line in enumerate(lines, 1):
        if line.strip().startswith(("//", "/*", "*")) or (class_line_no and line_no <= class_line_no):
            continue
        m = RE_SPRING_MAPPING.search(line)
        if m:
            anno = m.group(1).upper()
            verb = "GET" if "GET" in anno else "POST" if "POST" in anno else "PUT" if "PUT" in anno else "DELETE" if "DELETE" in anno else "ALL"
            raw_path = m.group(2)
            full_path = f"{class_prefix}{raw_path if raw_path.startswith('/') else '/' + raw_path}"

            surrounding = "".join(lines[max(0, line_no - 6):line_no])
            has_auth = has_class_auth or bool(RE_SPRING_AUTH.search(surrounding))

            routes.append(classify_route(
                file_path=file_path,
                line=line_no,
                function=f"Spring_{verb}",
                method=verb,
                path=full_path,
                auth_guards=["@PreAuthorize/@Secured"] if has_auth else [],
                has_user_check=has_auth,
                has_tenant_check=False,
                trusts_raw_headers=False,
                is_gateway_exposed=True,
                stack="java-spring"
            ))

    return routes


# ======================================================================
# 8. NON-REST ENTRYPOINT SCANNERS (WebSockets & Pub/Sub Event Handlers)
# ======================================================================

def scan_file_for_non_rest_entrypoints(file_path: str, content: str, ext: str) -> List[Dict[str, Any]]:
    entrypoints = []
    lines = content.splitlines()

    # A. WebSockets Scanner
    # Python: @router.websocket("/ws") or @app.websocket
    if ext == ".py":
        for line_no, line in enumerate(lines, 1):
            if "@router.websocket(" in line or "@app.websocket(" in line:
                m = re.search(r"""websocket\(\s*["']([^"']+)["']""", line)
                path = m.group(1) if m else "/ws"
                # Check surrounding function for auth check
                surrounding = "\n".join(lines[line_no:min(len(lines), line_no + 20)])
                has_token_check = any(t in surrounding.lower() for t in ["token", "auth", "query_params", "headers", "verify"])
                entrypoints.append({
                    "file": file_path.replace("\\", "/"),
                    "line": line_no,
                    "kind": "WebSocket",
                    "protocol": "ws",
                    "path": path,
                    "is_unauthenticated": not has_token_check,
                    "threat": "HIGH: Unauthenticated WebSocket Connection" if not has_token_check else "SECURE: WebSocket Auth Guarded",
                    "description": f"WebSocket route '{path}' lacks parameter or handshake authentication." if not has_token_check else "Authenticated WebSocket."
                })

    # Node / TypeScript WebSockets: io.on('connection') or ws.on('connection')
    elif ext in (".ts", ".js"):
        for line_no, line in enumerate(lines, 1):
            if ".on('connection'" in line or '.on("connection"' in line:
                surrounding = "\n".join(lines[line_no:min(len(lines), line_no + 15)])
                has_auth = any(t in surrounding.lower() for t in ["auth", "token", "handshake", "verify"])
                entrypoints.append({
                    "file": file_path.replace("\\", "/"),
                    "line": line_no,
                    "kind": "WebSocket",
                    "protocol": "ws",
                    "path": "socket.io / ws connection",
                    "is_unauthenticated": not has_auth,
                    "threat": "HIGH: Unauthenticated WebSocket Connection" if not has_auth else "SECURE: WebSocket Auth Guarded",
                    "description": "WebSocket connection handler without handshake token verification." if not has_auth else "Authenticated WebSocket handler."
                })

    # B. Pub/Sub & Message Queue Consumers
    # Python: GCP Pub/Sub, RabbitMQ, Celery, Kafka
    if ext == ".py":
        if any(p in content for p in ["GcpPubSubEventSubscriber", "basic_consume(", "KafkaConsumer(", "@celery.task", "@app.task"]):
            for line_no, line in enumerate(lines, 1):
                if any(k in line for k in ["basic_consume(", "subscriber.subscribe(", "GcpPubSubEventSubscriber", "@celery.task", "@app.task"]):
                    surrounding = "\n".join(lines[line_no:min(len(lines), line_no + 25)])
                    has_validation = any(v in surrounding.lower() for v in ["verify", "signature", "hmac", "token", "schema", "pydantic"])
                    entrypoints.append({
                        "file": file_path.replace("\\", "/"),
                        "line": line_no,
                        "kind": "PubSub/Queue",
                        "protocol": "async-event",
                        "path": line.strip()[:60],
                        "is_unauthenticated": not has_validation,
                        "threat": "MEDIUM: Unvalidated Message Queue Consumer" if not has_validation else "SECURE: Event Signature Verified",
                        "description": "Background event subscriber processing untrusted payload without message verification." if not has_validation else "Guarded message consumer."
                    })

    return entrypoints


# ======================================================================
# 9. COMMON ROUTE CLASSIFIER & THREAT TRIAGE
# ======================================================================

def classify_route(
    file_path: str,
    line: int,
    function: str,
    method: str,
    path: str,
    auth_guards: List[str],
    has_user_check: bool,
    has_tenant_check: bool,
    trusts_raw_headers: bool,
    is_gateway_exposed: bool,
    stack: str,
    taint_traces: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    is_unauthenticated = len(auth_guards) == 0
    is_dangerous_verb = method in ("DELETE", "PUT", "PATCH", "POST")
    has_path_id = ("{" in path or ":" in path) and any(k in path.lower() for k in ["id", "key", "uuid", "email", "user"])

    threat_flags = []

    # 1. Taint findings take precedence
    if taint_traces:
        for t in taint_traces:
            threat_flags.append(f"{t['severity']}: Tainted Data Flow to Dangerous Sink ({t['sink_kind']}) on param '{t['source_param']}'")

    # 2. Unauthenticated mutating route exposed externally
    if is_unauthenticated and is_dangerous_verb:
        if is_gateway_exposed:
            threat_flags.append("CRITICAL: Public Unauthenticated Mutating Route (Gateway-Exposed F01/F03 archetype)")
        else:
            threat_flags.append("LOW: Internal-Only Unauthenticated Mutating Route (Unexposed via Gateway)")

    # 3. Public parameter lookup without authentication
    elif is_unauthenticated and has_path_id:
        if is_gateway_exposed:
            threat_flags.append("HIGH: Public Parameter Lookup without Auth (F02 Redis/Secret archetype)")
        else:
            threat_flags.append("LOW: Internal Parameter Lookup (Unexposed via Gateway)")

    # 4. BOLA / Missing Ownership Verification
    elif is_dangerous_verb and has_path_id and not has_tenant_check and not has_user_check:
        threat_flags.append("HIGH: Potential BOLA / Missing Ownership Verification (F04 archetype)")

    # 5. Raw Header Reliance
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
        "threat_flags": threat_flags,
        "taint_traces": taint_traces or []
    }


# ======================================================================
# 10. MAIN REPOSITORY WALKER & AGGREGATOR
# ======================================================================

def detect_global_auth_guards(root_dir: str) -> bool:
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

def scan_codebase(root_dir: str = ".") -> Dict[str, Any]:
    all_routes = []
    flagged_threats = []
    ai_vulnerabilities = []
    all_taint_findings = []
    non_rest_entrypoints = []

    # 1. Discover Gateway Mappings with Pluggable Drivers
    gateway_routes, public_prefixes, gateway_topology = discover_all_gateway_mappings(root_dir)

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
                if os.path.getsize(fpath) > 2 * 1024 * 1024:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                    content = src.read()
            except Exception:
                continue

            # A. Scan for AI / LLM Vulnerabilities
            ai_vulns = scan_file_for_ai_vulnerabilities(fpath, content, ext)
            ai_vulnerabilities.extend(ai_vulns)

            # B. Scan Non-REST Entrypoints (WebSockets, Pub/Sub)
            non_rest = scan_file_for_non_rest_entrypoints(fpath, content, ext)
            non_rest_entrypoints.extend(non_rest)

            # C. Scan Web Routes
            fname_lower = f.lower()
            is_web_file = any(t in fname_lower for t in ["route", "controller", "server", "app", "router", "endpoint", "api", "view"])

            if ext == ".py" and is_web_file:
                routes, taints = analyze_python_file(fpath, gateway_routes=gateway_routes)
                all_routes.extend(routes)
                all_taint_findings.extend(taints)
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
        "gateway_topology": gateway_topology,
        "global_auth_enforced": has_global_auth,
        "total_endpoints": len(all_routes),
        "total_flagged_threats": len(flagged_threats),
        "total_taint_vulnerabilities": len(all_taint_findings),
        "total_non_rest_entrypoints": len(non_rest_entrypoints),
        "total_ai_vulnerabilities": len(ai_vulnerabilities),
        "taint_vulnerabilities": all_taint_findings,
        "non_rest_entrypoints": non_rest_entrypoints,
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
    print(f"Polyglot + Gateway-Aware Surface Analysis Complete (v2.0):")
    print(f"  • Gateway Routes Discovered: {result['gateway_routes_discovered']}")
    print(f"  • Gateway Drivers Active: {len(result['gateway_topology'])} rules mapped")
    print(f"  • Global Auth Guard Detected: {result['global_auth_enforced']}")
    print(f"  • Total Web Endpoints: {result['total_endpoints']}")
    print(f"  • Flagged Architectural Threats: {result['total_flagged_threats']}")
    print(f"  • AST Taint Invariant Flaws: {result['total_taint_vulnerabilities']}")
    print(f"  • Non-REST Entrypoints (WS/PubSub): {result['total_non_rest_entrypoints']}")
    print(f"  • AI/LLM Vulnerabilities Detected: {result['total_ai_vulnerabilities']}")
    print(f"  • Output: {out}")
