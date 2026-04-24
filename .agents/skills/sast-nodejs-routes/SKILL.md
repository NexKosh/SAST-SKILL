---
name: sast-nodejs-routes
description: >-
  Enumerate every API route in a Node.js codebase and perform unlimited-depth
  function call tracing from each route handler through all project-defined code.
  Produces a complete route-to-callgraph map with security-sensitive operations
  flagged at every layer. Uses a three-phase approach: recon (enumerate all
  routes and their handlers), batched trace (3 routes per batch, recursive
  call tracing with no layer limit), and merge (consolidate into
  sast/nodejs-routes.md). Requires sast/architecture.md (run sast-analysis
  first). Use when asked to do a thorough Node.js security review, map all API
  endpoints, trace call chains from routes, or before running other Node.js
  vulnerability skills — the route call graph provides context that improves
  detection accuracy across all other skills.
---

# Node.js Route Enumeration & Deep Call Graph

You are building a complete security-oriented call graph for a Node.js codebase. Starting from every API route entry point, you will recursively trace all project-defined function calls — with no layer limit — until every call chain terminates at an external library boundary, a leaf function, or a known-safe operation.

The output is a structured map: **route → handler → full call tree → security-sensitive operations flagged at each node**.

This is a **source-first** approach. Rather than searching for known dangerous sinks and tracing backward, you start from every route and trace forward. This catches vulnerabilities that sink-first analysis misses — including multi-hop taint flows through unfamiliar helper functions, custom abstractions over dangerous operations, and business logic flaws where no single line looks dangerous in isolation.

**Prerequisites**: `sast/architecture.md` must exist. Run `sast-analysis` first if it doesn't.

---

## What to Trace

### Frameworks supported

Enumerate routes from all of the following (use whatever is present in the project):

- **Express / Connect**: `app.get/post/put/delete/patch/all(path, ...handlers)`, `router.get/post/...`, `app.use(path, handler)`, `router.use(path, handler)`
- **NestJS**: `@Get(...)`, `@Post(...)`, `@Put(...)`, `@Delete(...)`, `@Patch(...)`, `@All(...)` on controller methods; read the `@Controller(basePath)` to compute the full path
- **Fastify**: `fastify.get/post/put/delete/patch(path, opts, handler)`, routes registered via `fastify.register()` with a prefix
- **Koa**: `router.get/post/put/del/patch(path, handler)` via `koa-router`
- **Hapi**: `server.route({ method, path, handler })` — extract all three fields
- **Restify**: `server.get/post/put/del/patch(path, handler)`
- **Next.js App Router**: file-system routes under `app/` — `page.tsx`, `route.ts`, and route groups in `(parenthesized)` folders

### What counts as a "project-defined function"

Trace recursively into any function whose definition exists in the project source tree (not in `node_modules/`). This includes:

- Named functions and arrow functions in the same file
- Functions imported from other project files (resolve the import path, read the source)
- Class methods on project-defined classes
- Functions passed as callbacks, if their definition is in the project

**Stop tracing** (mark as external boundary) when you encounter:
- A call to a function from `node_modules/` (e.g., `mongoose.findOne()`, `bcrypt.hash()`, `jwt.sign()`)
- A built-in Node.js module call (`fs.readFile()`, `child_process.exec()`, `http.request()`) — these are leaf nodes; flag them as security-sensitive if relevant
- A function whose definition cannot be located in the project files

### Security-Sensitive Operations to Flag

At every node in the call tree, flag any of the following. These are NOT automatically vulnerabilities — they are points of interest where user input reaching the operation could be dangerous:

| Category | Operations to flag |
|---|---|
| **Database** | `db.query()`, `pool.query()`, raw SQL strings, `Model.find/findOne/create/update()` with any variable argument, `$where`, Sequelize `.query()`, Knex raw queries, Prisma `$queryRaw` / `$executeRaw` |
| **File System** | `fs.readFile/writeFile/readFileSync/writeFileSync/appendFile`, `path.join/resolve` with a variable, `fs.unlink/rmdir/mkdir`, `require()` with a variable path |
| **OS Command** | `child_process.exec/execSync/spawn/spawnSync/execFile`, `shelljs.exec()`, `execa()` |
| **HTTP Request** | `http.request()`, `https.request()`, `axios.get/post/...`, `fetch()`, `got()`, `node-fetch`, `request()`, `superagent` |
| **Template Render** | `ejs.render()`, `handlebars.compile()`, `pug.render()`, `nunjucks.render()`, `res.render()`, any template engine `render` call with a variable template string |
| **Eval / Code** | `eval()`, `new Function()`, `vm.runInNewContext/Context/ThisContext()`, `setTimeout/setInterval` with a string first arg |
| **Serialization** | `JSON.parse()`, `yaml.load()`, `serialize.unserialize()`, `Buffer.from()` with user data, `pickle`-equivalents |
| **Auth / Session** | `jwt.verify()`, `jwt.decode()`, `bcrypt.compare()`, `crypto.createHash/createHmac`, session lookups |
| **Response** | `res.send()`, `res.json()`, `res.render()`, `res.redirect()` with variable arguments |

---

## Execution

This skill runs entirely in your current context — do NOT spawn subagents. Read `sast/architecture.md` before starting and use it throughout.

---

### Phase 1: Route Enumeration

**Do the following directly** (no subagents — you are the sole agent):

> **Goal**: Enumerate every HTTP route defined anywhere in this Node.js codebase. For each route, record the method, path, handler function name, and source location. Write results to `sast/nodejs-routes-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the frameworks in use and locate route definition files.
>
> **What to search for**:
>
> Search ALL `.js`, `.ts`, `.mjs`, `.cjs` files in the project (excluding `node_modules/`). For each framework present, apply the following:
>
> **Express**:
> - Search for: `app.get(`, `app.post(`, `app.put(`, `app.delete(`, `app.patch(`, `app.all(`, `router.get(`, `router.post(`, `router.put(`, `router.delete(`, `router.patch(`, `router.use(`
> - For each hit, record: HTTP method, path string (first argument), and handler function reference (last argument — may be inline arrow function or named function reference)
> - If the handler is a named reference (e.g., `router.get('/users', getUser)`), note the function name and the file where it's defined
> - Trace router mounting: if `app.use('/api/v1', userRouter)` mounts a router, all routes on `userRouter` have the `/api/v1` prefix — compute full paths
> - **Router group middleware (CRITICAL)**: For each router file, search for `router.use(fn)` or `router.use(fn1, fn2)` calls that have NO path string as first argument (or a wildcard `'*'`). These apply to ALL routes defined after them in the same router. Read these calls and record which middleware functions they register. When recording a route in that router, list these group-level middlewares under "Group middleware" — do NOT mark the route as "none detected" just because the inline route call has no middleware argument.
> - Also check: `app.use('/prefix', middlewareFn, router)` — when a router is mounted with middleware arguments inline, those middlewares protect every route inside that router.
>
> **NestJS**:
> - Search for `@Controller(` to find all controller classes and their base paths
> - Within each controller, search for `@Get(`, `@Post(`, `@Put(`, `@Delete(`, `@Patch(`, `@All(` — note sub-path and the method name immediately below the decorator
> - Compute full path = controller base path + method sub-path
> - Note any `@UseGuards(`, `@Roles(`, `@Public(` decorators on **both the controller class AND the individual method** — a guard on the class applies to every method inside it
>
> **Fastify**:
> - Search for `fastify.get(`, `fastify.post(`, `fastify.route({`, `fastify.register(`
> - For `register()` calls, note the prefix option — all routes in the plugin inherit this prefix
> - For each route, note handler (inline or named)
>
> **Koa**:
> - Search for `router.get(`, `router.post(`, `router.put(`, `router.del(`, `router.patch(`
> - Note any prefix from `router.prefix(...)` or router nesting
>
> **Hapi**:
> - Search for `server.route({` — extract `method`, `path`, `handler` fields from the object literal
>
> **Restify**:
> - Search for `server.get(`, `server.post(`, `server.put(`, `server.del(`
>
> **Next.js App Router**:
>
> Next.js uses the file system itself as the router. Routes are defined by directory structure under `app/` (or `src/app/`). **Important**: folders named with parentheses — e.g., `(auth)`, `(dashboard)`, `(public)` — are "Route Groups" that do NOT appear in the URL path but DO determine which `layout.tsx` and which middleware `matcher` rules apply.
>
> Apply this enumeration process:
>
> 1. **Locate the app directory**: Look for `app/` or `src/app/` at the project root.
>
> 2. **Enumerate all `page.tsx` / `page.js` files** (UI routes):
>    - Walk every subdirectory under `app/`.
>    - Strip the `app/` prefix to compute the URL path.
>    - Strip any `(groupName)` path segments from the URL — they do not appear in the URL. For example, `app/(dashboard)/profile/page.tsx` → URL `/profile`.
>    - Strip dynamic segments for display: `[id]` → `:id`, `[...slug]` → `*slug`, `[[...slug]]` → `*slug?`.
>    - Record which Route Group folder (if any) it belongs to.
>
> 3. **Enumerate all `route.ts` / `route.js` files** (API Route Handlers):
>    - Same path computation as above.
>    - Read the file and identify which HTTP method exports exist: `export function GET`, `export function POST`, `export function PUT`, `export function DELETE`, `export function PATCH`.
>    - Record each exported method as a separate route entry.
>    - Note any `export const runtime = 'edge'` or `export const dynamic` directives.
>
> 4. **Analyze `middleware.ts` / `middleware.js`** (project root or `src/`):
>    - Read the file and extract the `matcher` config from `export const config = { matcher: [...] }`.
>    - The matcher is an array of path patterns (can be glob strings or regex-like patterns with negative lookaheads).
>    - For each enumerated route (pages + API routes), **determine if its URL path would be matched** by the middleware matcher:
>      - A route is **covered** if at least one matcher pattern positively matches its URL.
>      - A route is **NOT covered** if no pattern matches, or if the only matching patterns are negative lookaheads that exclude it.
>      - Common exclusion patterns: `'/((?!api|_next/static|_next/image|favicon.ico).*)' ` excludes `/api/*`, `/_next/*`, and `/favicon.ico` — everything else is matched. Verify carefully.
>    - Also note what the middleware function actually does: does it verify a session/token/cookie? Does it redirect unauthenticated users? Or does it only run analytics/logging?
>
> 5. **Analyze `layout.tsx` / `layout.js` for auth guards**:
>    - For each Route Group folder, check if the `layout.tsx` in that folder (or a parent folder) performs authentication:
>      - Does it call a `getSession()`, `auth()`, `getServerSession()`, `cookies()` for a session token, or similar server-side auth check?
>      - Does it redirect (`redirect(...)`) unauthenticated users?
>      - A layout that does NOT perform any auth check makes ALL routes under that Route Group potentially unprotected — even if the middleware matcher covers them, the layout provides a second layer (or single layer if middleware is absent).
>    - Record the auth posture of each Route Group based on its layout.
>
> 6. **Cross-reference: middleware coverage vs layout auth**:
>    - For each route, record:
>      - ✅ Middleware covers it AND layout has auth check → double-protected
>      - ⚠️ Middleware covers it BUT layout has NO auth check → middleware-only (verify middleware actually enforces auth)
>      - ⚠️ Middleware does NOT cover it BUT layout has auth check → layout-only (server component auth)
>      - 🔴 Middleware does NOT cover it AND layout has NO auth check → potentially unprotected
>    - API route handlers (`route.ts`) do NOT have layouts, so they rely entirely on middleware OR in-handler auth checks.
>
> **For each route, also record**:
> - Whether an auth middleware or guard is listed in the route definition (e.g., `router.get('/path', authMiddleware, handler)` — note `authMiddleware`)
> - Whether group-level middleware applies (from `router.use(fn)` calls earlier in the same router file, or from `app.use('/path', middleware, router)` at mount point)
> - The file and approximate line number of the route registration
> - The file and approximate line number of the handler function definition (if it can be located)
> - **For Next.js**: the Route Group it belongs to, whether middleware covers it, and whether the layout performs auth
>
> **Output format** — write to `sast/nodejs-routes-recon.md`:
>
> ```markdown
> # Node.js Route Enumeration: [Project Name]
>
> ## Summary
> Total routes found: [N]
> Frameworks detected: [list]
>
> ## [Next.js only] Middleware Analysis
> - Middleware file: `middleware.ts` / not found
> - Matcher patterns: [list the exact matcher strings]
> - Middleware function purpose: [auth enforcement / analytics / redirect / other]
> - Routes NOT covered by middleware: [count and list]
>
> ## [Next.js only] Route Group Auth Posture
>
> | Route Group | Layout file | Layout performs auth? | Auth method |
> |---|---|---|---|
> | `(auth)` | `app/(auth)/layout.tsx` | No | — |
> | `(dashboard)` | `app/(dashboard)/layout.tsx` | Yes | `getServerSession()` + redirect |
> | [root] | `app/layout.tsx` | No | — |
>
> ## Routes
>
> ### 1. [METHOD] [full-path]
> - **File**: `path/to/routes.ts` (line X — route registration)
> - **Handler**: `functionName()` in `path/to/handler.ts` (line Y)
> - **Auth middleware (inline)**: [middleware listed directly in the route call, or "none"]
> - **Auth middleware (group-level)**: [middleware applied via router.use() to the whole router or mount point, or "none"]
> - **Guard / decorator**: [e.g., `@UseGuards(JwtAuthGuard)` on method or controller class, or "none"]
> - **[Next.js] Route Group**: `(groupName)` or [root]
> - **[Next.js] Middleware coverage**: ✅ covered / 🔴 NOT covered
> - **[Next.js] Layout auth**: ✅ layout enforces auth / ⚠️ layout has no auth check / N/A
> - **[Next.js] Overall posture**: ✅ protected / ⚠️ partial / 🔴 unprotected
> - **Handler snippet**:
>   ```
>   [the first 5-10 lines of the handler function body]
>   ```
>
> [Repeat for each route]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/nodejs-routes-recon.md`. If the summary reports zero routes found, write the following to `sast/nodejs-routes.md`, delete `sast/nodejs-routes-recon.md`, and stop:

```markdown
# Node.js Route Call Graph

No routes found. This project may not use a supported Node.js framework (Express, NestJS, Fastify, Koa, Hapi, Restify), or route definitions could not be located.
```

Only proceed to Phase 2 if at least one route was found.

---

### Phase 2: Deep Call Tracing (Batched)

After Phase 1 completes, read `sast/nodejs-routes-recon.md` and split the routes into **batches of up to 3 routes each**. Process each batch **sequentially**.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/nodejs-routes-recon.md` and count the numbered route sections (`### 1.`, `### 2.`, ...).
2. Divide into batches of up to 3.
3. For each batch, extract the full text of those route sections from the recon file.
4. Process each batch sequentially, working through each its assigned routes.
5. Write results to `sast/nodejs-routes-batch-N.md`.

For each batch, apply the following analysis (substitute batch-specific values):

> **Goal**: For each assigned route, build a complete call tree by recursively tracing every project-defined function called from the handler. Flag security-sensitive operations at each node. Write results to `sast/nodejs-routes-batch-[N].md`.
>
> **Your assigned routes** (from the recon phase):
>
> [Paste the full text of the assigned route sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary.
>
> ---
>
> **How to build the call tree**:
>
> For each assigned route:
>
> 1. **Identify the entry point function** by framework type — then read its full source code:
>
>    - **Express / Koa / Hapi / Restify**: the handler function (last argument of the route registration call, or named reference)
>    - **NestJS**: the controller method decorated with `@Get / @Post / ...`
>    - **Fastify**: the handler function in the route options object
>    - **Next.js `route.ts` (API Route Handler)**: the named export matching the HTTP method — e.g., `export async function GET(request)`, `export async function POST(request)`. Read the file and start tracing from the matching export.
>    - **Next.js `page.tsx` (Server Component page)**: the `default export` function. This IS a valid attack entry point — `searchParams` and `params` are user-controlled. Read the file and start tracing from the default export.
>    - **Next.js `layout.tsx` (Server Component layout)**: the `default export` function. Layouts can also perform data fetching with user-influenced values (e.g., session-derived IDs). Trace from the default export.
>    - **Next.js Server Actions**: any function inside a `'use server'` file, or a function marked `'use server'` at its top. Form `action={serverAction}` makes these direct attack surfaces — the `formData` argument carries user input. Trace from the function body.
>
> 2. **List every function call** made in the entry point body. For each call:
>    - Is it a project-defined function? (i.e., imported from a project file, or defined in the same file — NOT from `node_modules/`)
>    - Is it a security-sensitive built-in or library call (see the flag list below)?
>
> 3. **For every project-defined call**: look up the function definition (follow the import), read its full source, and repeat step 2 recursively. There is no depth limit — keep going until every branch terminates.
>
> 4. **A branch terminates** when:
>    - The called function is from `node_modules/` — mark as `[external: package-name]`
>    - The called function is a Node.js built-in (`fs`, `path`, `http`, `crypto`, etc.) — mark as `[built-in]` and flag if security-sensitive
>    - The function definition cannot be found in the project — mark as `[unresolved]`
>    - The function has no further calls — mark as `[leaf]`
>
> 5. **Detect and handle cycles**: If a function appears twice on the same call path (recursive call), mark it as `[recursive — not re-expanded]` to avoid infinite loops.
>
> ---
>
> **User-controlled taint sources by framework**:
>
> When annotating tainted values, look for these user-controlled sources:
>
> - **Express / Koa / Hapi / Restify**: `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, `ctx.request.body`, `ctx.query`, `ctx.params`, `request.payload`, `request.query`, `request.params`
> - **NestJS**: `@Body()`, `@Query()`, `@Param()`, `@Headers()`, `@Req()` decorated parameters
> - **Fastify**: `request.body`, `request.query`, `request.params`, `request.headers`
> - **Next.js `route.ts`**: `request.json()`, `request.formData()`, `request.text()`, `request.arrayBuffer()`, URL search params via `new URL(request.url).searchParams`
> - **Next.js `page.tsx` / `layout.tsx`**: the `searchParams` prop (URL query string — ALWAYS user-controlled), the `params` prop (dynamic route segments — user-controlled), `cookies()` from `next/headers` (if used as an identifier without server-side verification), `headers()` from `next/headers`
> - **Next.js Server Actions**: `formData.get(key)`, `formData.getAll(key)`, any parameter passed from the client call site
>
> ---
>
> **Security-sensitive operations to flag at each node**:
>
> Flag any of the following with the `⚠️` marker and the category label. These are not automatic vulnerabilities — they are operations where user-controlled data flowing in could be dangerous:
>
> - `⚠️ [DB]` — any database query: raw SQL construction, `Model.find/findOne/update/create`, `db.query()`, `$where`, Knex raw, Prisma `$queryRaw`
> - `⚠️ [FILE]` — `fs.readFile/writeFile/readFileSync`, `path.join/resolve` with variable args, `require(variable)`
> - `⚠️ [CMD]` — `exec/execSync/spawn/spawnSync`, `shelljs.exec`, `execa`
> - `⚠️ [HTTP]` — `axios.*`, `fetch()`, `http.request()`, `got()`, `node-fetch`, `superagent`
> - `⚠️ [TEMPLATE]` — `ejs.render()`, `handlebars.compile()`, `res.render()`, any template `render()` with a variable template string
> - `⚠️ [EVAL]` — `eval()`, `new Function()`, `vm.runIn*`, `setTimeout/setInterval` with string arg
> - `⚠️ [SERIAL]` — `yaml.load()`, `serialize.unserialize()`, unsafe deserialization
> - `⚠️ [AUTH]` — `jwt.verify/decode()`, `bcrypt.compare()`, session read
> - `⚠️ [RESPONSE]` — `res.send/json/render/redirect()` — note when the argument contains data that came from the request (potential reflected output)
> - `⚠️ [XSS]` — `dangerouslySetInnerHTML={{ __html: value }}` in any React component (server or client) — flag if `value` is derived from user input
> - `⚠️ [REDIRECT]` — `redirect(url)` from `next/navigation` — flag if `url` is derived from user-controlled input (open redirect)
> - `⚠️ [ACTION-CSRF]` — Server Action that mutates state without verifying the caller's session/origin — flag if the action has no authentication check before the mutation
>
> For each flagged operation, also note whether you can see a variable that appears to carry user input (from the taint sources listed above for the relevant framework) flowing into it. If yes, mark it `🔴 user-tainted`; if it appears server-side only, mark `🟢 server-side only`; if uncertain, mark `🟡 unknown`.
>
> ---
>
> **Output format** — write to `sast/nodejs-routes-batch-[N].md`:
>
> ```markdown
> # Route Call Graph — Batch [N]
>
> ---
>
> ## Route [original number]: [METHOD] [path]
> **Handler**: `functionName()` — `path/to/file.ts:line`
> **Auth**: [middleware/guard names, or "none detected"]
>
> ### Call Tree
>
> ```
> functionName(req, res) [path/to/file.ts:45]
> ├── helperA(req.params.id) [src/helpers/a.ts:12]
> │   ├── ⚠️ [DB] 🔴 user-tainted — User.findOne({ _id: id }) [src/db/user.ts:8]
> │   │   └── [external: mongoose]
> │   └── validateId(id) [src/utils/validate.ts:3]
> │       └── [leaf]
> ├── serviceB.process(req.body) [src/services/b.ts:67]
> │   ├── ⚠️ [DB] 🟡 unknown — pool.query(sql) [src/db/pool.ts:22]
> │   │   └── [built-in: pg]
> │   └── ⚠️ [RESPONSE] 🔴 user-tainted — res.json(result) [src/services/b.ts:80]
> └── [external: express] res.status(200)
> ```
>
> ### Security-Sensitive Operations Summary
>
> | # | Category | Function | File | Line | Taint | Notes |
> |---|---|---|---|---|---|---|
> | 1 | DB | `User.findOne({ _id: id })` | `src/db/user.ts` | 8 | 🔴 user-tainted | id from req.params |
> | 2 | DB | `pool.query(sql)` | `src/db/pool.ts` | 22 | 🟡 unknown | sql built in serviceB |
> | 3 | RESPONSE | `res.json(result)` | `src/services/b.ts` | 80 | 🔴 user-tainted | result derived from req.body |
>
> ---
>
> [Repeat for each assigned route]
> ```
>
> **Important notes**:
> - You must actually READ each referenced file to trace the call chain — do not guess at function bodies.
> - When an import resolves to a file you've already read for a previous route in this batch, you may reuse your memory of it — you don't need to re-read it.
> - For functions that are very long or have many branches, trace all branches but you may summarize repeated patterns (e.g., "same DB call pattern as branch A").
> - If a function is called with multiple different arguments across the codebase, focus on this specific call site's argument values.
> - Use indentation to show nesting depth. `├──` for non-last children, `└──` for last child.

---

### Phase 3: Merge — Consolidate Batch Results

After completing all batches in Phase 2, read every `sast/nodejs-routes-batch-*.md` file and merge them into `sast/nodejs-routes.md`. Do this directly in your current context.

**Merge procedure**:

1. Read all `sast/nodejs-routes-batch-1.md`, `sast/nodejs-routes-batch-2.md`, ... files.
2. Collect all route sections, preserving their original route numbers and all detail.
3. Build an aggregate security-sensitive operations index across all routes.
4. Write the merged report to `sast/nodejs-routes.md` using this format:

```markdown
# Node.js Route Call Graph: [Project Name]

## Summary

- Total routes traced: [N]
- Routes with user-tainted DB operations: [N]
- Routes with user-tainted CMD operations: [N]
- Routes with user-tainted FILE operations: [N]
- Routes with user-tainted TEMPLATE operations: [N]
- Routes with user-tainted EVAL operations: [N]
- Routes with no auth middleware detected: [N]
- Routes with unknown-taint sensitive operations: [N]

## High-Priority Routes (routes with 🔴 user-tainted sensitive operations)

| Route | Operations | Taint |
|---|---|---|
| `POST /api/users` | DB, RESPONSE | 🔴 |
| ... | | |

## Full Route Call Graphs

[All route sections from all batches, in original route number order.
Preserve all call trees, summaries, and tables exactly as written.]

## Cross-Route Sensitive Operations Index

[For each category (DB, CMD, FILE, etc.), list all flagged operations across all routes,
grouped by file. This helps identify shared helper functions that are called from
multiple routes and may be high-value targets for vulnerability review.]

### DB Operations
| Function call | File | Line | Called from routes | Taint |
|---|---|---|---|---|
| ... | | | | |

### CMD Operations
[same table structure]

### FILE Operations
[same table structure]
```

5. After writing `sast/nodejs-routes.md`, **delete all intermediate files** (`sast/nodejs-routes-batch-*.md`) and **delete** `sast/nodejs-routes-recon.md`.

---

## Important Reminders

- Read `sast/architecture.md` and keep it in context throughout.
- Phase 2 must run AFTER Phase 1 completes.
- Phase 3 must run AFTER all Phase 2 batches complete.
- Process batches of **3 routes each** sequentially. For large projects with many routes, this produces many batches — that is expected.
- Process all batches sequentially — write results to batch files as you complete each one.
- **This skill traces FORWARD from routes**, unlike other SAST skills that search for sinks and trace backward. The call tree is the primary output; the security-sensitive operation flags are annotations on the tree, not the final verdict.
- **The taint annotation (🔴/🟡/🟢) is a best-effort assessment** made while reading the code. The other vulnerability skills (sast-sqli, sast-rce, sast-ssrf, etc.) should be run afterward to confirm exploitability — this skill identifies WHERE to look, not whether it's exploitable.
- For very large projects (100+ routes), consider scoping the search to a specific subdirectory or router file rather than the entire project.
- The Cross-Route Sensitive Operations Index in the output is especially useful: a DB helper called from 20 different routes is a higher-value target than one called from a single route.
- When you encounter a function definition you cannot find (import resolves to a path that doesn't exist or is ambiguous), mark it `[unresolved]` and continue — do not halt the trace.
- Clean up all intermediate files after writing the final `sast/nodejs-routes.md`.
