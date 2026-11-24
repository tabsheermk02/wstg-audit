#!/usr/bin/env python3
"""
Unit Tests for Automated Invariant Critic (CRITIC_MODE)
Validates that the critic successfully hunts for mitigating controls across
all 5 defense vectors and properly refutes or confirms candidate findings.
"""

import json
import os
import shutil
import tempfile
import unittest

from scripts.run_critic import (
    evaluate_finding_with_critic,
    evaluate_vector_1_gateway,
    evaluate_vector_2_middlewares,
    evaluate_vector_3_dto_and_typing,
    evaluate_vector_4_data_layer,
    evaluate_vector_5_intraprocedural_invariants,
    run_critic_pipeline,
)
from scripts.validate_findings import validate_findings_file


class TestInvariantCritic(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_vector_1_gateway_unprotected(self):
        # Create an unprotected gateway container
        gw_dir = os.path.join(self.test_dir, "gateway")
        os.makedirs(gw_dir, exist_ok=True)
        container_file = os.path.join(gw_dir, "container.py")
        with open(container_file, "w") as f:
            f.write("""
routes = [
    RouteMapping("/api/auth", "identity-service", target_prefix="/auth")
]
""")
        finding = {
            "file": "services/auth/router.py",
            "trace": [{"kind": "entrypoint", "scope": "/api/auth/delete"}]
        }
        res = evaluate_vector_1_gateway(self.test_dir, finding)
        self.assertFalse(res.mitigating_control_found)
        self.assertIn("without enforcing perimeter-level auth", res.details)

    def test_vector_1_gateway_protected(self):
        # Create a protected gateway container
        gw_dir = os.path.join(self.test_dir, "gateway")
        os.makedirs(gw_dir, exist_ok=True)
        container_file = os.path.join(gw_dir, "container.py")
        with open(container_file, "w") as f:
            f.write("""
routes = [
    RouteMapping("/api/admin", "admin-service", guard=require_auth)
]
""")
        finding = {
            "file": "services/admin/router.py",
            "trace": [{"kind": "entrypoint", "scope": "/api/admin/users"}]
        }
        res = evaluate_vector_1_gateway(self.test_dir, finding)
        self.assertTrue(res.mitigating_control_found)
        self.assertIn("enforces perimeter authentication", res.details)

    def test_vector_2_global_middleware(self):
        app_file = os.path.join(self.test_dir, "app.py")
        with open(app_file, "w") as f:
            f.write("""
from fastapi import FastAPI
app = FastAPI()
app.add_middleware(AuthenticationMiddleware)
""")
        finding = {"file": "router.py"}
        res = evaluate_vector_2_middlewares(self.test_dir, finding)
        self.assertTrue(res.mitigating_control_found)
        self.assertIn("Global security middleware", res.details)

    def test_vector_3_handler_auth_guard(self):
        router_file = os.path.join(self.test_dir, "protected_router.py")
        with open(router_file, "w") as f:
            f.write("""
@router.post("/delete")
async def delete_user(user: dict = Depends(require_roles(["ADMIN"]))):
    pass
""")
        finding = {
            "file": "protected_router.py",
            "line": 3
        }
        res = evaluate_vector_3_dto_and_typing(self.test_dir, finding)
        self.assertTrue(res.mitigating_control_found)
        self.assertIn("explicit authentication dependency", res.details)

    def test_vector_4_parameterized_sql_sink(self):
        repo_file = os.path.join(self.test_dir, "user_repo.py")
        with open(repo_file, "w") as f:
            f.write("""
def get_user(email):
    query = text("SELECT * FROM users WHERE email = :email")
    return session.execute(query, {"email": email})
""")
        finding = {
            "wstg_code": "WSTG-INPV-05",
            "file": "user_repo.py",
            "line": 4,
            "trace": [{"kind": "sink", "file": "user_repo.py", "line": 4}]
        }
        res = evaluate_vector_4_data_layer(self.test_dir, finding)
        self.assertTrue(res.mitigating_control_found)
        self.assertIn("parameterized query", res.details)

    def test_vector_5_service_tenant_check(self):
        service_file = os.path.join(self.test_dir, "order_service.py")
        with open(service_file, "w") as f:
            f.write("""
def delete_order(user_id, order_id):
    order = db.get(order_id)
    if order.user_id != current_user.id:
        raise UnauthorizedException()
    db.delete(order)
""")
        finding = {
            "file": "order_service.py",
            "trace": [
                {"kind": "entrypoint", "file": "order_service.py", "line": 2},
                {"kind": "sink", "file": "order_service.py", "line": 6}
            ]
        }
        res = evaluate_vector_5_intraprocedural_invariants(self.test_dir, finding)
        self.assertTrue(res.mitigating_control_found)
        self.assertIn("enforces authorization check", res.details)

    def test_critic_refutation_end_to_end(self):
        # A finding that is refuted by code in the repo
        router_file = os.path.join(self.test_dir, "guarded_router.py")
        with open(router_file, "w") as f:
            f.write("""
@router.post("/items")
async def create_item(current_user=Depends(get_current_user)):
    return {"status": "ok"}
""")
        finding = {
            "wstg_code": "WSTG-ATHN-04",
            "title": "Bypass on Items Endpoint",
            "file": "guarded_router.py",
            "line": 3,
            "status": "confirmed",
            "trace": [
                {"kind": "entrypoint", "file": "guarded_router.py", "line": 3},
                {"kind": "sink", "file": "guarded_router.py", "line": 4}
            ]
        }
        eval_result = evaluate_finding_with_critic(self.test_dir, finding)
        self.assertEqual(eval_result["verdict"], "REFUTED")
        self.assertEqual(eval_result["disposition_decision"], "DOWNGRADE_TO_SUPPRESSED")
        self.assertGreaterEqual(eval_result["mitigations_discovered"], 1)

    def test_critic_confirmation_end_to_end(self):
        # A finding that has zero mitigations and survives all 5 vectors
        router_file = os.path.join(self.test_dir, "raw_router.py")
        with open(router_file, "w") as f:
            f.write("""
@router.post("/purge")
async def purge_data(target_id: str):
    db.delete_everything(target_id)
""")
        finding = {
            "wstg_code": "WSTG-ATHN-04",
            "title": "Unauthenticated Data Purge",
            "file": "raw_router.py",
            "line": 3,
            "status": "confirmed",
            "trace": [
                {"kind": "entrypoint", "file": "raw_router.py", "line": 3},
                {"kind": "sink", "file": "raw_router.py", "line": 4}
            ]
        }
        eval_result = evaluate_finding_with_critic(self.test_dir, finding)
        self.assertEqual(eval_result["verdict"], "CONFIRMED")
        self.assertEqual(eval_result["disposition_decision"], "PROMOTE_TO_CONFIRMED")
        self.assertEqual(eval_result["mitigations_discovered"], 0)


if __name__ == "__main__":
    unittest.main()
