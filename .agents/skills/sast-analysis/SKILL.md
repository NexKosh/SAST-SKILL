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
