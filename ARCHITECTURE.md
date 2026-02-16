# Bluefairy — System Architecture

## What It Is

Bluefairy is the control plane for **Aware** (wareit.ai), a multi-tenant SaaS that gives each user their own isolated AI workspace. It handles authentication, account management, tenant orchestration, and (temporarily) reverse-proxying to tenant instances.

## The Big Picture

```
   Users (browsers)
         │
         ▼
   ┌──────────────┐        ┌────────────────────┐
   │  aware-web   │───────▶│  bluefairy          │
   │  (Vercel)    │  API   │  (DO App Platform)  │
   │  Next.js     │        │  Go binary ×2       │
   └──────────────┘        │                     │
     future frontend       │  api.wareit.ai      │
                           │  dashboard.wareit.ai│
                           └──────┬──────────────┘
                                  │
                    ┌─────────────┼──────────────────┐
                    │             │                   │
                    ▼             ▼                   ▼
              ┌──────────┐ ┌───────────────┐ ┌──────────────┐
              │PostgreSQL│ │tenant-         │ │  DOKS (k8s)  │
              │  (PG 16) │ │orchestrator   │ │              │
              │          │ │(DO App Platf.)│ │ nginx ingress│
              │accounts  │ │               │ │      │       │
              │users     │ │Manages k8s    │ │ ┌────▼─────┐ │
              │refresh_  │ │CRDs via API   │ │ │tenant pod│ │
              │tokens    │ │               │ │ │port 18789│ │
              └──────────┘ └───────────────┘ │ └──────────┘ │
                                             │              │
                                             │ openclaw-    │
                                             │ operator     │
                                             └──────────────┘
```

## Request Flow

### Authentication (API)
1. User submits credentials to `api.wareit.ai/auth/login`
2. Bluefairy verifies password (argon2id, with bcrypt legacy support)
3. Returns short-lived JWT (15 min) + opaque refresh token
4. Refresh tokens are SHA-256 hashed and stored in Postgres
5. Token rotation on every refresh — old token revoked, new one issued

### Signup
1. Creates account + user in Postgres
2. Calls tenant-provisioner to provision an OpenClaw instance
3. Orchestrator creates an OpenClawInstance CRD in k8s
4. Returns JWT + refresh token

### Dashboard Proxy (temporary)
1. Request hits `dashboard.wareit.ai/*`
2. JWT validated from cookie; transparent refresh if expired
3. Tenant instance looked up via orchestrator API
4. Request reverse-proxied to `http://{name}.wareit.ai`
5. Gateway token injected as `?token=` query param
6. WebSocket upgrades handled via TCP hijack+splice

> **Note:** The proxy layer is temporary. Once aware-web handles direct
> tenant connections, the entire `internal/proxy` package will be removed.

## Tenant Resolution

Bluefairy resolves tenant instances by calling the tenant-provisioner
HTTP API. It never talks to Kubernetes directly.

- `GET /tenants/{userID}/instance` — lookup
- `POST /tenants/{userID}/instance` — provision (signup only)

The orchestrator returns an instance name (e.g. `tenant-1c9de7b5`),
which bluefairy expands to a URL via the `TENANT_BASE_URL` template:
`http://{name}.wareit.ai`

## Configuration

All config is loaded from environment variables at startup via `config.Load()`.
Required vars fail fast — the app won't start without them.

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `JWT_SECRET` | Yes | HMAC secret for JWT signing |
| `TENANT_ORCHESTRATOR_URL` | Yes | Tenant orchestrator API base URL |
| `TENANT_BASE_URL` | Yes | URL template, e.g. `http://{name}.wareit.ai` |
| `PORT` | No (8000) | HTTP listen port |
| `PROXY_SECRET` | No | Shared secret for tenant request verification |

## Project Structure

```
cmd/
  api/main.go          Entry point, server lifecycle
  api/routes.go        Route setup, host-based routing
  migrate/main.go      Standalone migration CLI

internal/
  account/             Account repository + service (Stripe later)
  auth/                JWT, passwords, middleware, refresh tokens
  config/              Centralised env-based configuration
  db/                  PostgreSQL connection pool
  migrate/             golang-migrate wrapper
  proxy/               Reverse proxy to tenant instances (temporary)
    dashboard.go       Cookie auth + proxy for dashboard.wareit.ai
    handler.go         Bearer auth + proxy for API routes
    reverse.go         Shared reverse proxy builder
    websocket.go       WebSocket hijack+splice
    static/            Embedded HTML (login, loading — will be replaced by aware-web)
  tenant/              HTTP client for tenant-provisioner API
  user/                User repository + service

migrations/            SQL migration files (golang-migrate)
```

## Future Direction

- **aware-web** (Next.js on Vercel) will replace the embedded login/loading
  HTML and become the primary frontend on `dashboard.wareit.ai`
- **Custom gateway** will replace OpenClaw, with its own auth mechanism
- **Proxy removal** — once users connect to tenant instances directly,
  the entire `internal/proxy` package gets deleted
- **Stripe integration** — account service will handle billing
