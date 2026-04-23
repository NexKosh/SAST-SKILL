---
name: sast-analysis
description: >-
  Perform codebase analysis and architecture mapping as the first phase of a
  security assessment. Explores the tech stack, frameworks, entry points, data
  flows, and trust boundaries. Outputs sast/architecture.md. Run this before any
  vulnerability detection skill. Use when asked to analyze a codebase for
  security or when sast/architecture.md does not yet exist.
---

# Codebase Analysis

You are performing the first phase of a security assessment. Your goal is to deeply understand the codebase. You are NOT looking for specific vulnerabilities yet. This is pure reconnaissance.

Create a `sast/` folder in the project root (if it doesn't already exist). This phase produces one output file inside it:

`sast/architecture.md` — technology stack, architecture, entry points, data flows

## Phase 1: Technology Reconnaissance

Explore the codebase and identify:

- **Languages**: All programming languages used and their versions if specified
- **Frameworks**: Web frameworks, ORM layers, template engines, task queues.
  For Node.js projects specifically, detect:
  - **Express**: `express()` app, `Router()` usage, `.use()` / `.get()` / `.post()` / `.put()` / `.delete()` / `.patch()` chains; global middleware ordering
  - **NestJS**: `@Controller(...)`, `@Get(...)`, `@Post(...)`, `@Put(...)`, `@Delete(...)`, `@Patch(...)`, `@Module(...)`, `@Injectable()` decorators; `@UseGuards(...)`, `@Roles(...)`, global guards registered in `AppModule`; `@Body()`, `@Param()`, `@Query()`, `@Headers()` parameter decorators; app bootstrap in `main.ts`
  - **Fastify**: `fastify()` / `Fastify()` instance, `fastify.get/post/put/delete/patch/route`, plugin system via `fastify.register()`, route prefixes; `preHandler`, `onRequest`, `preValidation` lifecycle hooks
  - **Koa**: `new Koa()`, `app.use()`, `koa-router` (`router.get/post/put/del`), `ctx.request.body`, `ctx.query`, `ctx.params`
  - **Hapi**: `Hapi.server()`, `server.route({method, path, handler})`, `options.auth` field per route, server lifecycle extensions
  - **Restify**: `restify.createServer()`, `server.get/post/put/del/patch`, `server.use()` middleware
  - **Next.js App Router**: presence of `app/` or `src/app/` directory with `page.tsx`/`page.js` and/or `route.ts`/`route.js` files; `next.config.js` / `next.config.ts`; `middleware.ts` / `middleware.js` at the project root or inside `src/`
- **Node.js config patterns**: `dotenv` (`.env` files, `process.env.*`), `config` npm package (`config/default.json`, `config/production.json`), `convict`, `nconf`
- **Package managers & dependencies**: Lock files, dependency manifests (package.json, requirements.txt, go.mod, Gemfile, pom.xml, etc.)
- **Infrastructure hints**: Dockerfiles, docker-compose, Kubernetes manifests, Terraform, CI/CD configs
- **Databases**: SQL, NoSQL, cache layers, message brokers — look at connection strings, ORM models, migration files
- **Authentication & authorization**: Auth libraries, middleware, session configs, OAuth/OIDC providers, JWT usage, API key patterns
- **External integrations**: Third-party APIs, payment processors, email services, cloud SDKs, webhook handlers
- **Entry points**: HTTP routes, GraphQL schemas, gRPC service definitions, CLI commands, WebSocket handlers, scheduled jobs, message consumers

Start by reading dependency manifests, project configs, and directory structure. Then drill into source code to confirm findings.

## Phase 2: Architecture Mapping

Based on Phase 1, build a mental model of:

1. **Service boundaries**: Is this a monolith or microservices? What talks to what?
2. **Data flow**: How does user input enter the system, get processed, get stored, and get returned?
3. **Trust boundaries**: Where does the system transition between trusted and untrusted contexts? (e.g., user input -> backend, backend -> database, service -> service, server -> client)
4. **Privilege levels**: What roles/permissions exist? How are they enforced? Is there an admin panel?
5. **Sensitive data inventory**: PII, credentials, tokens, financial data, health records — where is each stored and how does it move?

### Node.js Route & Middleware Discovery (perform if Node.js is detected)

If the project uses any Node.js framework, perform these additional reconnaissance steps before writing the output file:

**Express route discovery:**
- Search for `app.get(`, `app.post(`, `app.put(`, `app.delete(`, `app.patch(`, `app.use(`, `router.get(`, `router.post(`, `router.put(`, `router.delete(` etc.
- For each route, record: HTTP method, path pattern, handler function name(s), and any middleware arguments listed before the final handler (e.g., `router.delete('/users/:id', auth, requireAdmin, handler)` → middleware chain is `auth → requireAdmin`).
- Trace global middleware registered with `app.use()` and note which routes each covers (middleware registered after a route does NOT protect that route — ordering is critical).
- For each inline or referenced middleware function that is project-defined (not from `node_modules`), read its source and summarize what it enforces (authentication, rate limiting, CSRF, input validation, role check, logging, etc.).

**NestJS controller discovery:**
- Search for `@Controller(` decorators — note the base path.
- Within each controller class, find `@Get(`, `@Post(`, `@Put(`, `@Delete(`, `@Patch(`, `@All(` — note the sub-path and handler method name.
- Check for guards: `@UseGuards(...)` at controller or method level, `@Roles(...)` decorators, and global guards registered in `AppModule` providers.
- Note `@Body()`, `@Param()`, `@Query()`, `@Headers()` decorators — these mark where user input enters handler parameters.
- Check `ValidationPipe` configuration: is it applied globally (`app.useGlobalPipes(...)`) or per-handler? Are `whitelist` and `forbidNonWhitelisted` options enabled?

**Fastify route & plugin discovery:**
- Search for `fastify.get(`, `fastify.post(`, `fastify.route(`, `fastify.register(`.
- For plugins, note the prefix and what routes/hooks each plugin registers.
- Identify `preHandler`, `onRequest`, and `preValidation` hooks — these are the equivalent of Express middleware.

**Koa route discovery:**
- Search for `router.get(`, `router.post(`, `router.put(`, `router.del(`, `app.use(` with router middleware.
- Note `ctx.request.body`, `ctx.query`, `ctx.params` as user input entry points.

**Hapi route discovery:**
- Search for `server.route({` — extract `method`, `path`, `handler`, and `options.auth`.
- A route with `options.auth: false` is explicitly unauthenticated even if a default auth scheme is configured.

**Next.js App Router discovery (perform when `app/` or `src/app/` directory is present):**

Next.js App Router uses the file system as its router. Its structure is fundamentally different from Express-style routing and requires dedicated analysis.

> ⚠️ **Critical concept — Route Groups**: Folders named with parentheses like `(auth)`, `(dashboard)`, `(public)` are "Route Groups". They organize routes but their names **do NOT appear in the URL**. For example, `app/(dashboard)/settings/page.tsx` is served at `/settings`, NOT `/dashboard/settings`. This is a common source of middleware bypass vulnerabilities.

1. **Map the `app/` directory tree**:
   - List every subdirectory. Identify which are Route Groups (names in parentheses) vs regular path segments.
   - For each `page.tsx` / `page.js`: compute the effective URL by stripping the `app/` prefix and removing any `(groupName)` segments. Dynamic segments stay: `[id]` → `:id`, `[...slug]` → `*slug`.
   - For each `route.ts` / `route.js`: same URL computation. Also read the file to identify which HTTP methods are exported (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`). Each exported method is a separate entry point.

2. **Analyze `middleware.ts` / `middleware.js`** (at project root or inside `src/`):
   - Read and record the full `matcher` config from `export const config = { matcher: [...] }`. If no matcher is present, the middleware runs on **all** routes.
   - Read the middleware function body. Determine what it actually does:
     - Does it verify a session, JWT, or cookie and redirect on failure? → **auth enforcement**
     - Does it only set headers, log, or call `NextResponse.next()` unconditionally? → **no auth enforcement** (provides no protection even if matcher covers the route)
   - For each enumerated route (pages + API handlers), evaluate whether its effective URL matches the matcher:
     - **Covered**: at least one matcher pattern positively matches the URL.
     - **NOT covered**: no pattern matches, or the route is excluded by a negative lookahead.
   - Note: matcher patterns use path-to-regexp syntax, not glob syntax. A pattern like `/dashboard/:path*` does NOT cover `/settings` even if `/settings` is inside a `(dashboard)` route group.

3. **Analyze `layout.tsx` / `layout.js` for server-side auth guards**:
   - For each Route Group folder, read its `layout.tsx`. Check if it performs server-side auth:
     - Calls `getServerSession()`, `auth()`, `getSession()`, `cookies()` to read a session/token
     - Calls `redirect(...)` if no valid session exists
   - A layout that performs these checks acts as a **server-side auth gate** for all pages under that group.
   - A layout with NO auth check makes every page under that group rely entirely on middleware for protection.
   - API route handlers (`route.ts`) are NOT affected by layouts — they have no layout layer.

4. **Cross-reference middleware coverage with layout auth** for each route:
   - ✅ Middleware covers it AND layout has auth → double-protected
   - ⚠️ Middleware covers it BUT layout has no auth → middleware-only (check middleware actually enforces auth)
   - ⚠️ Middleware does NOT cover it BUT layout has auth → layout-only (server component check)
   - 🔴 Middleware does NOT cover it AND layout has no auth → **potentially unprotected**
   - 🔴 `route.ts` API handler: not covered by middleware AND no in-handler auth check → **unprotected API endpoint**

**Write the results of Phase 1 and Phase 2 to `sast/architecture.md`.** Use this format:

```markdown
# Architecture: [Project Name]

## Technology Stack

| Category | Details |
|---|---|
| Languages | ... |
| Frameworks | ... |
| Databases | ... |
| Auth mechanism | ... |
| Infrastructure | ... |
| External services | ... |

## Architecture Overview

[Describe the architecture: monolith vs microservices, how components interact,
main modules and their responsibilities]

## Data Flow

[Trace how user input enters the system, gets processed, stored, and returned.
Cover the primary flows (e.g., registration, login, core business actions).]

## Entry Points

| Entry Point | Type | Auth Required | Handler | File | Middleware Chain | Description |
|---|---|---|---|---|---|---|
| `GET /api/users/:id` | HTTP | Yes | `getUser()` | `src/users/users.controller.ts` | `authMiddleware → requireRole('admin')` | Fetch user by ID |
| ... | | | | | | |

> **Middleware Chain column**: List each middleware function applied to this route in execution order, left to right. For project-defined middleware, read the source and summarize what it enforces (e.g., `verifyJWT` → authentication check, `requireRole('admin')` → role guard). If no middleware applies, write `none`.

## [Next.js only] Route Group Map

> Include this section only if the project uses Next.js App Router.
>
> ⚠️ Route Group folder names in parentheses do NOT appear in URLs. List them explicitly so downstream skills understand the mapping.

### Route Groups

| Route Group Folder | Effective URL Prefix | Layout auth guard? | Auth method |
|---|---|---|---|
| `app/(dashboard)` | `/` (no prefix — routes appear at top level) | Yes | `getServerSession()` + `redirect('/login')` |
| `app/(auth)` | `/` (login, register, etc.) | No | — |
| `app/(public)` | `/` (marketing pages) | No | — |
| `app/api` | `/api` | No layout | — |

### middleware.ts Analysis

- **File**: `middleware.ts` / `src/middleware.ts` / not found
- **Matcher patterns**: [exact strings, e.g. `['/((?!login|register|_next/static|_next/image|favicon\.ico).*)']`]
- **Middleware actually enforces**: [auth redirect / session check / headers only / analytics / none]
- **Routes NOT covered by matcher**:
  - [list each route or route group whose effective URL is not matched]

### Route Coverage Summary

| Route | Route Group | Effective URL | Middleware covers? | Layout auth? | Overall posture |
|---|---|---|---|---|---|
| `app/(dashboard)/settings/page.tsx` | `(dashboard)` | `/settings` | 🔴 NO | ✅ Yes | ⚠️ Partial |
| `app/api/user/route.ts` | none | `/api/user` | ✅ Yes | N/A | ✅ Protected |
| `app/(public)/about/page.tsx` | `(public)` | `/about` | 🔴 NO | 🔴 No | ✅ Intentionally public |

## Trust Boundaries

[List each trust boundary and what crosses it]

## Sensitive Data Inventory

| Data Type | Where Stored | How Accessed | Protection |
|---|---|---|---|
| ... | ... | ... | ... |
```

## Important Reminders

- Do NOT report specific vulnerabilities (like "line 42 has SQL injection"). That comes in later phases.
- Be thorough in exploration. Read actual source code, not just config files. Look at how auth middleware is applied, how queries are built, how file uploads are handled.
- If the codebase is large, prioritize security-sensitive areas: auth, payment, data access, file handling, admin functionality.
