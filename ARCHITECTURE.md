# Bluefairy — System Architecture

## What It Is

Bluefairy is the control plane for **Aware** (wareit.ai), a multi-tenant SaaS that gives each user their own isolated AI workspace. It handles authentication, account management, tenant provisioning, and reverse-proxying to tenant instances.

## The Big Picture

```
   Users (browsers)
         │
         ▼
   dashboard.wareit.ai  (bluefairy on DO App Platform)
         │
         ├─ UI routes (/dashboard, /signup, /api/auth/*, /_next/*)
         │     └─▶ reverse proxy to aware-web (Vercel)
         │
         ├─ / (authenticated) + all other paths
         │     └─▶ reverse proxy to tenant instance (HTTP)
         │
         └─ WebSocket (wss://dashboard.wareit.ai/)
               └─▶ hijack + splice to tenant instance

   api.wareit.ai  (same bluefairy instance)
         │
         ├─ /auth/*     Auth endpoints (login, signup, refresh)
         ├─ /instance   Tenant instance lookup
         ├─ /me         User info
         └─ /health     Health check

                    ┌─────────────┬──────────────────┐
                    │             │                   │
                    ▼             ▼                   ▼
              ┌──────────┐ ┌───────────────┐ ┌──────────────┐
              │PostgreSQL│ │tenant-         │ │  DOKS (k8s)  │
              │  (PG 16) │ │provisioner     │ │              │
              │          │ │(DO App Platf.) │ │ nginx ingress│
              │accounts  │ │               │ │      │       │
              │users     │ │Manages k8s    │ │ ┌────▼─────┐ │
              │refresh_  │ │CRDs via API   │ │ │tenant pod│ │
              │tokens    │ │               │ │ │port 18789│ │
              └──────────┘ └───────────────┘ │ └──────────┘ │
                                             │ openclaw-    │
                                             │ operator     │
                                             └──────────────┘
```

## Request Flow

### Login (dashboard.wareit.ai)
1. Browser loads `dashboard.wareit.ai/` → bluefairy proxies to aware-web on Vercel → login page
2. User submits credentials → `POST /api/auth/login` → proxied to aware-web
3. aware-web calls `api.wareit.ai/auth/login` server-side → bluefairy verifies password
4. aware-web sets httpOnly cookies (`token` + `aware_refresh`) and returns success
5. Client navigates to `/dashboard` → proxied to aware-web → loading screen
6. Loading screen polls `GET /api/connect` until tenant is ready
7. When ready, navigates to `/` → bluefairy sees auth cookie → proxies to tenant

### Workspace (dashboard.wareit.ai)
1. Authenticated request to `/` → AppHandler reads JWT from `token` cookie
2. If JWT expired, transparent refresh via `aware_refresh` cookie
3. Tenant instance looked up via tenant-provisioner API
4. HTTP requests reverse-proxied to `http://{name}.wareit.ai`
5. WebSocket upgrades handled via TCP hijack+splice
6. Gateway token injected as `?token=` query param on proxied requests

### Authentication (api.wareit.ai)
1. `POST /auth/login` — verifies password (argon2id, bcrypt legacy), returns JWT + refresh token
2. `POST /auth/signup` — creates account + user, provisions tenant, returns tokens
3. `POST /auth/refresh` — rotates refresh token, issues new token pair
4. JWT: 15 min TTL, HMAC-signed. Refresh tokens: SHA-256 hashed, stored in Postgres.

## Host-Based Routing

Bluefairy uses the `Host` header to route requests:

- `dashboard.wareit.ai` → **AppHandler** — proxies UI to Vercel, workspace to tenant
- `api.wareit.ai` (and all other hosts) → **API router** — JSON API endpoints

The AppHandler decides where to proxy based on path and auth state:

| Path | Auth? | Destination |
|---|---|---|
| `/_next/*`, `/api/*`, `/favicon.ico` | any | aware-web (Vercel) |
| `/dashboard`, `/signup`, `/logout` | any | aware-web (Vercel) |
| `/` | no cookie | aware-web (login page) |
| `/` | has cookie | tenant (workspace) |
| `/*` | has cookie | tenant (workspace) |
| WebSocket | has cookie | tenant (gateway) |

## Tenant Resolution

Bluefairy resolves tenant instances by calling the tenant-provisioner HTTP API:

- `GET /tenants/{userID}/instance` — lookup
- `POST /tenants/{userID}/instance` — provision (signup only)

The provisioner returns an instance name (e.g. `tenant-1c9de7b5`),
which bluefairy expands via the `TENANT_BASE_URL` template:
`http://{name}.wareit.ai`

## Configuration

All config is loaded from environment variables at startup via `config.Load()`.
Required vars fail fast — the app won't start without them.

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `JWT_SECRET` | Yes | HMAC secret for JWT signing |
| `TENANT_PROVISIONER_URL` | Yes | Tenant provisioner API base URL |
| `TENANT_BASE_URL` | Yes | URL template, e.g. `http://{name}.wareit.ai` |
| `FRONTEND_URL` | Yes | aware-web Vercel URL (e.g. `https://xxx.vercel.app`) |
| `PORT` | No (8000) | HTTP listen port |
| `DASHBOARD_HOST` | No (dashboard.wareit.ai) | Hostname for dashboard routing |
| `PROXY_SECRET` | No | Shared secret for tenant request verification |

## Project Structure

```
cmd/
  api/main.go          Entry point, server lifecycle
  api/routes.go        Route setup, host-based routing
  migrate/main.go      Standalone migration CLI

internal/
  account/             Account repository + service
  auth/                JWT, passwords, middleware, refresh tokens
  config/              Centralised env-based configuration
  db/                  PostgreSQL connection pool
  migrate/             golang-migrate wrapper
  proxy/               Reverse proxy layer
    app.go             AppHandler — unified dashboard routing
    reverse.go         Shared reverse proxy builder
    websocket.go       WebSocket hijack+splice
  tenant/              HTTP client for tenant-provisioner API
  user/                User repository + service

migrations/            SQL migration files (golang-migrate)
```

## Related Services

- **aware-web** (Next.js on Vercel) — login/signup UI, served through bluefairy's proxy on `dashboard.wareit.ai`
- **tenant-provisioner** (DO App Platform) — manages OpenClaw k8s CRDs
- **openclaw-operator** (DOKS) — reconciles CRDs into tenant pods

## Future Direction

- **Custom gateway** will replace OpenClaw, with its own auth mechanism
- **Stripe integration** — account service will handle billing
- **Direct tenant connection** — once the custom gateway is built, the proxy layer can be simplified or removed
