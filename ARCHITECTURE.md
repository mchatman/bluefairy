# Bluefairy — System Architecture

## What It Is

Bluefairy is the control plane for **Aware** (wareit.ai), a multi-tenant SaaS that gives each user their own isolated **OpenClaw** AI workspace. It handles authentication, tenant provisioning, and reverse-proxying — all in a single Go binary.

## The Big Picture

```
                         ┌─────────────────────────────────┐
   Users (browsers)      │        Cloudflare               │
         │               │  dashboard.wareit.ai            │
         │               │  api.wareit.ai                  │
         ▼               └────────────┬──────────────────  ┘
                                      │
                    ┌─────────────────▼────────────────────┐
                    │   DigitalOcean App Platform           │
                    │                                       │
                    │   ┌───────────────────────────────┐   │
                    │   │   bluefairy (×2 instances)     │   │
                    │   │   Go binary, port 8080         │   │
                    │   │                                │   │
                    │   │  Host: dashboard.wareit.ai     │   │
                    │   │    → DashboardHandler          │   │
                    │   │    → cookie auth + proxy       │   │
                    │   │                                │   │
                    │   │  Host: api.wareit.ai           │   │
                    │   │    → REST API                  │   │
                    │   │    → Bearer token auth + proxy │   │
                    │   └───────────────┬───────────────┘   │
                    │                   │                    │
                    │   ┌───────────────▼───────────────┐   │
                    │   │   PostgreSQL (PG 16)           │   │
                    │   │   accounts, users,             │   │
                    │   │   refresh_tokens               │   │
                    │   └───────────────────────────────┘   │
                    └───────────────────┬───────────────────┘
                                        │
          ┌─────────────────────────────┤
          │  Orchestrator API           │  Direct to LB IP
          │  (tenant lookup)            │  (proxy traffic)
          ▼                             ▼
┌──────────────────┐    ┌──────────────────────────────────┐
│ tenant-orchestr. │    │   DigitalOcean Kubernetes (DOKS)  │
│ (DO App Platform)│    │                                   │
│                  │    │   nginx ingress ──► LB 24.199.73.199
│ Knows which user │    │                                   │
│ has which tenant │    │   ┌─────────────┐ ┌─────────────┐│
└──────────────────┘    │   │tenant-1c9de │ │tenant-0026d ││
                        │   │(OpenClaw pod)│ │(OpenClaw pod)││
                        │   │  port 18789  │ │  port 18789  ││
                        │   └─────────────┘ └─────────────┘│
                        │                                   │
                        │   openclaw-operator               │
                        │   (watches OpenClawInstance CRDs) │
                        │                                   │
                        │   proxy-auth-check (nginx sidecar)│
                        │   (validates X-Proxy-Secret)      │
                        └──────────────────────────────────┘
```

## Components

### 1. Bluefairy (this repo) — The Control Plane

A single Go binary deployed on DigitalOcean App Platform (2 instances). It does **three jobs**:

**Job 1: Authentication**
- Signup: create account + user → provision tenant → return JWT + refresh token
- Login: verify password → return JWT + refresh token
- Refresh: rotate refresh tokens (old one revoked, new one issued)
- JWTs: HS256, 15-minute TTL, claims include `sub` (userID), `email`, `tier`
- Passwords: Argon2id (primary) with bcrypt legacy support
- Refresh tokens: 32-byte random, stored as SHA256 hash in PostgreSQL

**Job 2: Tenant Resolution**
- Given a userID, find their OpenClaw instance endpoint
- **Two strategies** (auto-detected at startup):
  - **K8sClient**: reads `OpenClawInstance` CRDs directly from k8s API (used when running inside the cluster)
  - **HTTP Client**: calls the tenant-orchestrator API (used on App Platform)
- Results are cached in-memory

**Job 3: Reverse Proxy**
- After authenticating a user, proxy all their HTTP/WebSocket traffic to their tenant pod
- Two entry points:
  - `dashboard.wareit.ai` — cookie-based auth for browsers
  - `api.wareit.ai/api/*` — Bearer token auth for API clients

### 2. Tenant Orchestrator — Instance Registry

A separate DO App Platform service (`tenant-orchestrator-qsha7.ondigitalocean.app`). Bluefairy calls it to look up or create tenant instances:
- `GET /tenants/{userID}/instance` — look up existing
- `POST /tenants/{userID}/instance` — create new
- Returns: `{endpoint: "tenant-1c9de7b5", status: "running", gateway_token: "..."}`

### 3. Kubernetes Cluster (DOKS) — Tenant Runtime

A DigitalOcean Kubernetes cluster running the actual OpenClaw workspaces:

| Component | Role |
|-----------|------|
| **openclaw-operator** | Watches `OpenClawInstance` CRDs, creates pods/services/ingresses |
| **tenant pods** | Per-user OpenClaw instances (StatefulSet pods, port 18789) |
| **nginx ingress** | Routes external traffic to tenant pods by Host header |
| **proxy-auth-check** | nginx sidecar that validates `X-Proxy-Secret` header on every request |
| **cert-manager** | TLS certificates (for public `*.wareit.ai` hosts) |

### 4. PostgreSQL — User Data

Managed PG 16 on App Platform. Three tables:

| Table | Purpose |
|-------|--------|
| `accounts` | Organization/billing entity (has Stripe fields) |
| `users` | Individual users, belong to an account |
| `refresh_tokens` | Token hashes with expiry + revocation tracking |

## Request Flows

### Browser Login → Dashboard

```
1. Browser → POST dashboard.wareit.ai/auth/login {email, password}
2. Bluefairy verifies password, issues JWT + refresh token
3. JS redirects to /auth/callback?token=JWT&refresh_token=RT
4. Bluefairy sets HttpOnly cookies (aware_dashboard, aware_refresh)
5. Redirects to /?token=GATEWAY_TOKEN
6. Browser → GET dashboard.wareit.ai/
7. Bluefairy reads cookie, verifies JWT
8. Calls orchestrator: GET /tenants/{userID}/instance
   → Returns: name="tenant-1c9de7b5"
9. Builds endpoint: http://24.199.73.199 (from TENANT_BASE_URL)
   Builds Host header: tenant-1c9de7b5.internal.wareit.ai (from TENANT_HOST_TEMPLATE)
10. httputil.ReverseProxy → connects to 24.199.73.199:80
    Sets Host: tenant-1c9de7b5.internal.wareit.ai
    Sets X-Proxy-Secret, X-User-ID, X-User-Email, ?token=GATEWAY_TOKEN
11. nginx ingress matches Host → routes to tenant-1c9de7b5 service → pod
12. proxy-auth-check validates X-Proxy-Secret → 200
13. OpenClaw pod serves the SPA HTML
14. Browser renders the OpenClaw dashboard
```

### WebSocket Connection (Dashboard)

```
1. Browser → WS dashboard.wareit.ai/ws/... (Connection: Upgrade)
2. Bluefairy verifies cookie JWT, resolves tenant
3. Hijacks the HTTP connection (gets raw net.Conn)
4. Dials backend: TCP to 24.199.73.199:80
5. Builds HTTP upgrade request with:
   - Host: tenant-1c9de7b5.internal.wareit.ai
   - Original Upgrade/Sec-WebSocket headers
   - Injected: X-Proxy-Secret, X-User-ID, ?token=GATEWAY_TOKEN
6. Writes upgrade request to backend
7. Bidirectional io.Copy splice (zero-copy, no WS library)
8. Both directions run until either side closes
```

### Transparent Token Refresh

```
1. Browser → GET dashboard.wareit.ai/anything (cookie has expired JWT)
2. Bluefairy: VerifyAccessToken() fails (expired)
3. Reads aware_refresh cookie → SHA256 hash → DB lookup
4. If valid: revoke old refresh token, issue new JWT + new refresh token
5. Set new cookies on the response
6. Continue proxying — user never sees a login page
```

## The DNS Bypass (Why the Proxy is Complex)

The original design was:
- Each tenant gets a DNS record: `tenant-XXXX.wareit.ai` → LB IP
- The proxy would connect using the hostname directly

**The problem:** The `wareit.ai` domain uses Porkbun nameservers, but wildcard DNS was set up in DigitalOcean's DNS panel — so the records never resolved.

**The fix (what we implemented):**
- `TENANT_BASE_URL=http://24.199.73.199` — connect to the LB IP directly (no DNS)
- `TENANT_HOST_TEMPLATE={name}.internal.wareit.ai` — set the Host header so nginx ingress routes correctly
- Disabled `ssl-redirect` on ingresses — so HTTP works without TLS certs
- proxy-auth-check nginx validates `X-Proxy-Secret` on every request

## Key Environment Variables

| Variable | Value in Production | Purpose |
|----------|--------------------|---------|
| `DATABASE_URL` | (managed PG) | PostgreSQL connection |
| `JWT_SECRET` | (secret) | Signs/verifies all JWTs |
| `TENANT_ORCHESTRATOR_URL` | `https://tenant-orchestrator-qsha7.ondigitalocean.app` | Tenant instance lookup API |
| `TENANT_BASE_URL` | `http://24.199.73.199` | TCP connection target for proxied requests |
| `TENANT_HOST_TEMPLATE` | `{name}.internal.wareit.ai` | Host header for nginx ingress routing |
| `PROXY_SECRET` | (secret) | Shared secret sent as X-Proxy-Secret |
| `PORT` | `8080` | HTTP listen port |

## File Structure

```
cmd/
  api/
    main.go          # Entrypoint: config → DB → migrate → routes → serve
    routes.go        # Host-based routing: dashboard vs API
  migrate/
    main.go          # Standalone migration CLI

internal/
  config/config.go   # All env var loading + validation
  db/db.go           # pgxpool connection management
  migrate/migrate.go # golang-migrate runner with fallback

  auth/
    handler.go       # Signup, Login, Refresh HTTP handlers
    jwt.go           # HS256 JWT sign/verify, opaque token generation
    middleware.go    # Bearer token extraction middleware
    password.go      # Argon2id + bcrypt password hashing
    refresh_store.go # Refresh token CRUD in PostgreSQL

  user/
    service.go       # User business logic
    repository.go    # User SQL queries

  account/
    service.go       # Account business logic
    repository.go    # Account SQL queries

  tenant/
    tenant.go        # Resolver interface + Instance struct
    client.go        # HTTP orchestrator client (used on App Platform)
    k8s.go           # Kubernetes CRD client (used in-cluster)

  proxy/
    dashboard.go     # Cookie-auth reverse proxy for dashboard.wareit.ai
    handler.go       # Bearer-auth reverse proxy for /api/* routes
    ws.go            # Direct WebSocket proxy for /gw/{userId}
    landing.go       # Single-gateway landing page
    ui.go            # UI proxy with script injection
    idle.go          # WebSocket connection tracking + idle auto-stop
    static/embed.go  # Embedded login.html

  gateway/           # Self-contained gateway lifecycle (Docker/Fly)
    provisioner.go   # Core provision/stop orchestration
    docker.go        # Docker container runtime
    fly.go           # Fly Machines runtime
    config.go        # Gateway config file writer
    health.go        # TCP health checker
    routes.go        # Gateway management REST API
    cleanup.go       # Expired token cleanup
```

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Browser → Bluefairy** | HTTPS (Cloudflare), HttpOnly/Secure/SameSite cookies |
| **API → Bluefairy** | HTTPS, Bearer JWT in Authorization header |
| **Bluefairy → Tenant Pod** | `X-Proxy-Secret` header (shared secret) |
| **nginx ingress → Tenant Pod** | `proxy-auth-check` external auth service validates X-Proxy-Secret |
| **Tenant Pod auth** | `?token=GATEWAY_TOKEN` query param on every request |
| **Password storage** | Argon2id (64MB memory, 3 iterations) or bcrypt (legacy) |
| **Refresh tokens** | SHA256 hashed in DB, single-use rotation, revocation support |

## Gateway Module (Not Active in Production)

The `internal/gateway/` package is a **self-contained gateway lifecycle manager** that can provision OpenClaw instances via Docker or Fly Machines directly. It includes:
- Container lifecycle (start/stop/reconcile)
- Port allocation via SQL function
- Health checking (TCP probe)
- Idle detection (WebSocket connection tracking → auto-stop)
- Fly Machines integration (persistent machines + volumes)

This module is **not wired into the production routes** — it was likely the v1 approach before the system moved to the Kubernetes operator + external orchestrator model. The code remains in the repo as an alternative runtime option.
