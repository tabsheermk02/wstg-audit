# Web Protocol, HTTP Framing & Authentication Attack Guide

This reference equips the auditor to investigate and verify vulnerabilities across the HTTP protocol, caching, browser-session, and authentication boundaries under OWASP WSTG v4.2/v5.

---

## 1. Core Verification Discipline

Before declaring any finding under this domain, enforce these mandatory invariant rules:
* **Two Interpretations Required for Cache/Framing:** Request framing and cache findings require demonstrating two divergent interpretations of the same request, response, or key by different components (e.g. Gateway vs Upstream Service).
* **Cryptographic & Binding Verification:** For every credential (JWT, session token, API key), verify signature validation AND all contextual bindings: `issuer`, `audience`, `origin`, `principal`, `tenant`, `assurance_level`, `expiry`, and `one-time` state.
* **Header Trust Verification:** `Host`, `Forwarded`, `X-Forwarded-*`, `Origin`, `Referer`, redirect targets, and callback URLs are trust decisions. Trace whether the perimeter gateway actively sanitizes client-supplied copies before downstream consumption.
* **Absence vs Defect:** A missing cookie flag or header is only a finding if it leads to an accepted cross-principal request, credential disclosure, or assurance downgrade.

---

## 2. JSON Web Token (JWT) Attack Classes (`WSTG-ATHN-11`)

When auditing JWT implementations:
1. **Algorithm Confusion & `none` Algorithm:**
   - Does the verification library pin the accepted algorithm (e.g. `algorithms=["RS256"]`)?
   - Can an attacker pass an HMAC-SHA256 token signed with the server's public RSA key to a server expecting RSA?
   - Does the parser accept `alg: "none"` or case variants?
2. **Key Injection via Header Parameters (`kid`, `jku`, `x5u`):**
   - Is `kid` (Key ID) vulnerable to path traversal (e.g. `../../../../dev/null`) or SQL injection?
   - Does the server fetch public keys from client-supplied `jku` (JWK Set URL) or `x5u` URLs without a strict whitelist?
3. **Claim & Audience Binding:**
   - Does the token consumer verify `aud` (audience) and `iss` (issuer)?
   - Can a token issued for a public mobile app be replayed against an administrative internal service?
4. **Decode-Without-Verify Paths:**
   - Does any middleware or handler use `jwt.decode(..., options={"verify_signature": False})` to extract claims before authentication completes?

---

## 3. HTTP Framing, Ingress & Cache Attack Classes (`WSTG-CONF-07`, `WSTG-SESS-04`)

1. **Request Framing & Desynchronization (HTTP Request Smuggling):**
   - Disagreements between edge proxy (Envoy, Nginx, Cloudflare) and backend microservice on `Content-Length` vs `Transfer-Encoding: chunked`.
   - Normalization differences in CR/LF, invalid whitespace before colons in headers (`Header : value`), or HTTP/2-to-HTTP/1.1 downgrade.
2. **Web Cache Poisoning via Unkeyed Input:**
   - Do unkeyed request headers (e.g. `X-Forwarded-Host`, `X-Original-URL`, `Origin`) alter the response body or reflected scripts in a cached response?
   - Does the cache key omit query parameter normalization or language headers while the response dynamically reflects them?
3. **Web Cache Deception:**
   - Does the edge proxy treat dynamic user-authenticated paths (`/api/user/profile.jpg` or `/dashboard;static.css`) as public static assets and cache private PII?
4. **Host and Forwarded-Header Trust:**
   - Does the application construct password reset links, OAuth redirect URIs, or email verification links from the incoming `Host` or `X-Forwarded-Host` header without domain allowlisting?

---

## 4. Browser Session & CSRF Attack Classes (`WSTG-SESS-01` to `08`)

1. **Session Fixation & Replay:**
   - Is the session token or cookie rotated immediately upon login, privilege escalation, or MFA verification?
   - Does an old session remain valid after password change, account deletion, or explicit logout?
2. **State-Changing CSRF:**
   - Do mutating endpoints (`POST`, `PUT`, `DELETE`, `PATCH`) accept ambient cookie credentials without an anti-CSRF token, custom request header (`X-Requested-With`), or strict `SameSite=Lax/Strict` cookie enforcement?
3. **Cross-Site WebSocket Hijacking (CSWSH):**
   - Does the WebSocket handshake endpoint rely purely on cookies without verifying the `Origin` header or requiring an ephemeral handshake token?

---

## 5. Federated Identity, OAuth2 & OIDC Attack Classes (`WSTG-ATHN-04`)

1. **`state` Parameter Validation & CSRF:**
   - Does the OAuth callback endpoint strictly validate that the `state` parameter matches the session that initiated the authorization flow?
2. **Redirect URI Manipulation:**
   - Does the authorization server allow wildcards, path traversal, or regex flaws in `redirect_uri` (e.g. `attacker.com` or `target.com.attacker.com`)?
3. **PKCE Enforcement:**
   - Is PKCE (`code_challenge` / `code_verifier`) enforced for public single-page applications and native mobile clients?
4. **Account Linking Collision:**
   - When a user logs in via Google/Apple SSO with an existing email, does the application link accounts automatically without requiring the user to prove ownership of the existing password?
