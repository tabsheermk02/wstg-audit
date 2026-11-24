# Data Isolation, Multi-Tenancy & Trust Boundary Attack Guide

This reference guides the auditor through evaluating tenant boundaries, authorization logic, object ownership, and inter-service trust under OWASP WSTG v4.2/v5.

---

## 1. Core Multi-Tenancy Discipline

Enforce these verification rules for every multi-tenant or shared-resource target:
* **The Invariant Rule:** A tenant boundary is violated if a principal belonging to Tenant A can view, mutate, execute, or delete resources belonging to Tenant B without explicit inter-tenant authorization.
* **Separation of Authentication and Authorization:** Gating an endpoint on valid authentication (e.g. `Depends(get_current_user)`) does NOT prove authorization. Every query must bind to the caller's specific tenant or ownership scope.
* **No Implicit Trust Across Microservices:** In microservice topologies, downstream services must not trust caller-supplied headers (`x-user-id`, `x-tenant-id`, `x-role`) unless the network connection carries a verified cryptographic service token (HMAC/mTLS) from a trusted gateway.

---

## 2. Broken Object-Level Authorization (BOLA / IDOR) (`WSTG-ATHZ-02`)

Audit every endpoint accepting resource identifiers (`/api/items/{id}`, `/users/{user_id}/orders`, `/documents/{uuid}`):
1. **Direct Database Lookups without Tenant Scoping:**
   - Does the database query filter exclusively on the item ID?
     - *Vulnerable:* `db.query(Document).filter(Document.id == doc_id).first()`
     - *Secure:* `db.query(Document).filter(Document.id == doc_id, Document.tenant_id == current_user.tenant_id).first()`
2. **Numeric Sequential ID Enumeration:**
   - Are database primary keys auto-incrementing integers (`/invoices/10045`), enabling trivial full database enumeration?
3. **Storage & Blob Signed URL Object Tampering:**
   - Does a signed URL generation endpoint (`/storage/signed_url?key=...`) allow arbitrary client-specified keys, permitting callers to download other tenants' documents or upload malicious overwrites?

---

## 3. Shared Cache, Redis & Memory Space Isolation (`WSTG-SESS-04`, `WSTG-SESS-08`)

When multiple tenants or microservices share a cache or session store:
1. **Unpartitioned Keyspace / Session Puzzling:**
   - Are Redis/Memcached keys constructed using client-controlled parameters without tenant prefixes?
     - *Vulnerable:* `redis.set(f"session:{session_id}", user_data)`
     - *Secure:* `redis.set(f"tenant:{tenant_id}:session:{session_id}", user_data)`
   - Can Tenant A overwrite or read Tenant B's session data by choosing an identical `session_id`?
2. **Cache Tag & Invalidation Collisions:**
   - Does a cache invalidation request from Tenant A trigger global cache flushes, causing denial of service for Tenant B?

---

## 4. Lifecycle Operations: Soft-Delete, Export & Restore (`WSTG-ATHZ-03`)

Special attention must be paid to non-standard CRUD operations:
1. **Soft-Delete Bypass:**
   - Do bulk queries, search indexes, or nested relationship lookups include records where `deleted_at IS NOT NULL`?
   - Can a user re-activate a soft-deleted item belonging to another user?
2. **Export / Backup as Unauthorized Exfiltration:**
   - When an export or report generation task runs asynchronously (e.g. via Celery/RabbitMQ), does the background worker re-verify tenant boundaries, or does it run with superuser database privileges?
3. **Bulk Operations:**
   - Do bulk update endpoints (`PATCH /api/items/batch`) verify ownership of *every* item in the batch array, or do they only check the first item?

---

## 5. Gateway-to-Service Trust Boundaries (`WSTG-ATHN-04`)

In distributed and microservice systems:
1. **Internal Header Spoofing:**
   - Can an external client send `x-bantrly-user-id: admin` or `x-user-role: superuser` through the gateway and have it forwarded untouched to an internal microservice?
   - Does the gateway actively strip all `x-*` internal headers from incoming external requests?
2. **Unmapped Downstream Microservice Routes:**
   - Does an internal microservice have dangerous administrative endpoints (`POST /users/delete`, `POST /admin/reset`) that are accidentally forwarded by wildcard gateway routing (`/api/identity/*` $\rightarrow$ `identity-service/*`)?
3. **Asynchronous Queue Trust:**
   - When consuming messages from GCP Pub/Sub, SQS, or RabbitMQ, does the consumer verify that the event payload's tenant ID matches the topic/subscription scope, or does it blindly execute operations against whatever tenant ID is serialized in the message JSON?
