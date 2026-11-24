#!/usr/bin/env python3
"""
Comprehensive Test Suite for wstg-audit v2.0
Validates AST Taint Tracking, Pluggable Gateway Drivers, Syntax Parsers,
Non-REST Entrypoints, and Automated Patch Generation.
"""

import ast
import json
import os
import shutil
import tempfile
import unittest

from scripts.map_surface import (
    GATEWAY_DRIVERS,
    FastAPIRouteMappingDriver,
    NginxGatewayDriver,
    EnvoyGatewayDriver,
    KubernetesIngressDriver,
    TraefikGatewayDriver,
    ExpressNestMountDriver,
    discover_all_gateway_mappings,
    PythonTaintTracker,
    analyze_python_file,
    analyze_ts_js_file,
    analyze_go_file,
    analyze_java_file,
    scan_file_for_non_rest_entrypoints,
    scan_file_for_ai_vulnerabilities,
    scan_codebase
)

from scripts.validate_findings import validate_findings_file
from scripts.generate_report import generate_report

class TestWSTGAuditV2(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # 1. AST Taint Tracking Tests
    # ------------------------------------------------------------------
    def test_sql_injection_taint(self):
        code = """
@router.post("/search")
def search_items(query: str, db: Session = Depends(get_db)):
    sql = f"SELECT * FROM items WHERE name = '{query}'"
    cursor.execute(sql)
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        tracker = PythonTaintTracker(func_node, "test_api.py")
        tracker.visit(func_node)

        self.assertEqual(len(tracker.taint_findings), 1)
        finding = tracker.taint_findings[0]
        self.assertEqual(finding["wstg_code"], "WSTG-INPV-05")
        self.assertEqual(finding["source_param"], "query")
        self.assertEqual(finding["sink_kind"], "SQL Injection")

    def test_command_injection_taint(self):
        code = """
@router.post("/ping")
def ping_host(target_ip: str):
    cmd = f"ping -c 1 {target_ip}"
    subprocess.run(cmd, shell=True)
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        tracker = PythonTaintTracker(func_node, "test_cmd.py")
        tracker.visit(func_node)

        self.assertEqual(len(tracker.taint_findings), 1)
        finding = tracker.taint_findings[0]
        self.assertEqual(finding["wstg_code"], "WSTG-INPV-12")
        self.assertEqual(finding["source_param"], "target_ip")
        self.assertEqual(finding["sink_kind"], "Command Injection")

    def test_path_traversal_taint(self):
        code = """
@router.get("/download")
def download_file(filename: str):
    filepath = "/data/files/" + filename
    with open(filepath, "r") as f:
        return f.read()
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        tracker = PythonTaintTracker(func_node, "test_path.py")
        tracker.visit(func_node)

        self.assertEqual(len(tracker.taint_findings), 1)
        finding = tracker.taint_findings[0]
        self.assertEqual(finding["wstg_code"], "WSTG-INPV-12")
        self.assertEqual(finding["source_param"], "filename")
        self.assertEqual(finding["sink_kind"], "Path Traversal / Arbitrary File Access")

    def test_safe_dependency_not_tainted(self):
        code = """
@router.get("/profile")
def get_profile(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user.id
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        tracker = PythonTaintTracker(func_node, "test_safe.py")
        tracker.visit(func_node)

        # current_user and db are known injected services, not untrusted caller parameters
        self.assertEqual(len(tracker.taint_findings), 0)

    # ------------------------------------------------------------------
    # 2. Pluggable Gateway Drivers Tests
    # ------------------------------------------------------------------
    def test_fastapi_routemapping_driver(self):
        driver = FastAPIRouteMappingDriver()
        content = """
routes = [
    RouteMapping("/api/v1/auth", "auth-service", target_prefix="/auth"),
    RouteMapping("/api/v1/users", "user-service")
]
"""
        mappings = driver.discover("container.py", content)
        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[0]["service"], "auth-service")
        self.assertEqual(mappings[0]["public_prefix"], "/api/v1/auth")
        self.assertEqual(mappings[0]["target_prefix"], "/auth")

    def test_nginx_gateway_driver(self):
        driver = NginxGatewayDriver()
        content = """
server {
    location /api/billing {
        proxy_pass http://billing-service:8080/billing;
    }
}
"""
        mappings = driver.discover("nginx.conf", content)
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["service"], "billing-service")
        self.assertEqual(mappings[0]["public_prefix"], "/api/billing")

    def test_k8s_ingress_driver(self):
        driver = KubernetesIngressDriver()
        content = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
spec:
  rules:
  - http:
      paths:
      - path: /payments
        backend:
          service:
            name: payment-svc
"""
        mappings = driver.discover("ingress.yaml", content)
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["service"], "payment-svc")
        self.assertEqual(mappings[0]["public_prefix"], "/payments")

    # ------------------------------------------------------------------
    # 3. Non-Python Syntax Parsers Tests
    # ------------------------------------------------------------------
    def test_go_group_middleware_inheritance(self):
        fpath = os.path.join(self.test_dir, "routes.go")
        content = """
package main
func setupRoutes(r *gin.Engine) {
    v1 := r.Group("/api/v1", AuthMiddleware())
    v1.POST("/users", CreateUser)
    v1.DELETE("/users/:id", DeleteUser)
}
"""
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

        routes = analyze_go_file(fpath)
        self.assertEqual(len(routes), 2)
        # Should inherit path prefix and auth middleware
        self.assertEqual(routes[0]["path"], "/api/v1/users")
        self.assertEqual(routes[0]["is_unauthenticated"], False)
        self.assertEqual(routes[1]["path"], "/api/v1/users/:id")
        self.assertEqual(routes[1]["is_unauthenticated"], False)

    def test_nestjs_class_guard_and_public(self):
        fpath = os.path.join(self.test_dir, "users.controller.ts")
        content = """
@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
    @Get()
    findAll() {}

    @Public()
    @Post('register')
    register() {}
}
"""
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

        routes = analyze_ts_js_file(fpath)
        self.assertEqual(len(routes), 2)

        get_route = next(r for r in routes if r["method"] == "GET")
        post_route = next(r for r in routes if r["method"] == "POST")

        self.assertEqual(get_route["path"], "/users")
        self.assertEqual(get_route["is_unauthenticated"], False)

        self.assertEqual(post_route["path"], "/users/register")
        self.assertEqual(post_route["is_unauthenticated"], True) # @Public() opted out!

    def test_spring_boot_controller_inheritance(self):
        fpath = os.path.join(self.test_dir, "OrderController.java")
        content = """
@RestController
@RequestMapping("/api/orders")
@PreAuthorize("hasRole('ADMIN')")
public class OrderController {
    @GetMapping("/{id}")
    public Order getOrder() {}
}
"""
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

        routes = analyze_java_file(fpath)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["path"], "/api/orders/{id}")
        self.assertEqual(routes[0]["is_unauthenticated"], False)

    # ------------------------------------------------------------------
    # 4. Non-REST Entrypoints Tests
    # ------------------------------------------------------------------
    def test_websocket_scanner(self):
        content = """
@router.websocket("/ws/chat")
async def chat_ws(websocket: WebSocket):
    await websocket.accept()
"""
        entries = scan_file_for_non_rest_entrypoints("chat.py", content, ".py")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["kind"], "WebSocket")
        self.assertTrue(entries[0]["is_unauthenticated"])

    def test_pubsub_consumer_scanner(self):
        content = """
class OrderSubscriber(GcpPubSubEventSubscriber):
    def handle_message(self, message):
        data = json.loads(message.data)
"""
        entries = scan_file_for_non_rest_entrypoints("consumer.py", content, ".py")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["kind"], "PubSub/Queue")

    # ------------------------------------------------------------------
    # 5. Deterministic Findings & Invariant Validator Tests
    # ------------------------------------------------------------------
    def test_validate_findings_success(self):
        target_file = os.path.join(self.test_dir, "auth_routes.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("@router.post('/delete/{email}')\ndef delete_user(email: str):\n    pass\n")

        valid_findings = {
            "findings": [
                {
                    "wstg_code": "WSTG-ATHN-04",
                    "severity": "CRITICAL",
                    "status": "confirmed",
                    "title": "Unauthenticated user deletion",
                    "description": "Endpoint lacks authentication.",
                    "root_cause": "Missing dependency guard on delete route.",
                    "intended_behavior": "Only authenticated admins can invoke deletion.",
                    "file": "auth_routes.py",
                    "line": 1,
                    "conditions": ["Route exposed via gateway"],
                    "trace": [
                        {"kind": "entrypoint", "file": "auth_routes.py", "line": 1, "scope": "delete_user", "description": "Entrypoint"},
                        {"kind": "sink", "file": "auth_routes.py", "line": 2, "scope": "delete_user", "description": "Deletion sink"}
                    ],
                    "remediation": "Add Depends(get_current_admin).",
                    "regression_test": "test_unauthenticated_delete_returns_401()"
                }
            ]
        }
        findings_json = os.path.join(self.test_dir, "findings.json")
        with open(findings_json, "w", encoding="utf-8") as f:
            json.dump(valid_findings, f)

        is_valid, errors, warnings = validate_findings_file(findings_json, repo_dir=self.test_dir)
        self.assertTrue(is_valid, f"Validation failed unexpectedly: {errors}")
        self.assertEqual(len(errors), 0)

    def test_validate_findings_catches_nonexistent_file(self):
        invalid_findings = {
            "findings": [
                {
                    "wstg_code": "WSTG-ATHN-04",
                    "severity": "CRITICAL",
                    "status": "confirmed",
                    "title": "Fake finding",
                    "description": "Desc",
                    "root_cause": "Cause",
                    "intended_behavior": "Behavior",
                    "file": "nonexistent_file_hallucinated.py",
                    "line": 10,
                    "trace": [
                        {"kind": "entrypoint", "file": "nonexistent_file_hallucinated.py", "line": 1, "scope": "a", "description": "b"},
                        {"kind": "sink", "file": "nonexistent_file_hallucinated.py", "line": 2, "scope": "a", "description": "b"}
                    ],
                    "remediation": "Fix"
                }
            ]
        }
        findings_json = os.path.join(self.test_dir, "invalid_findings.json")
        with open(findings_json, "w", encoding="utf-8") as f:
            json.dump(invalid_findings, f)

        is_valid, errors, warnings = validate_findings_file(findings_json, repo_dir=self.test_dir)
        self.assertFalse(is_valid)
        self.assertTrue(any("Target file does not exist" in e for e in errors))

    def test_validate_findings_catches_missing_sink_in_trace(self):
        target_file = os.path.join(self.test_dir, "auth_routes.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("@router.post('/test')\ndef test(): pass\n")

        invalid_trace = {
            "findings": [
                {
                    "wstg_code": "WSTG-ATHN-04",
                    "severity": "CRITICAL",
                    "status": "confirmed",
                    "title": "Missing sink finding",
                    "description": "Desc",
                    "root_cause": "Cause",
                    "intended_behavior": "Behavior",
                    "file": "auth_routes.py",
                    "line": 1,
                    "trace": [
                        {"kind": "entrypoint", "file": "auth_routes.py", "line": 1, "scope": "test", "description": "Entrypoint"}
                    ],
                    "remediation": "Fix"
                }
            ]
        }
        findings_json = os.path.join(self.test_dir, "invalid_trace.json")
        with open(findings_json, "w", encoding="utf-8") as f:
            json.dump(invalid_trace, f)

        is_valid, errors, warnings = validate_findings_file(findings_json, repo_dir=self.test_dir)
        self.assertFalse(is_valid)
        self.assertTrue(any("missing a 'sink' step" in e for e in errors))

if __name__ == "__main__":
    unittest.main()
