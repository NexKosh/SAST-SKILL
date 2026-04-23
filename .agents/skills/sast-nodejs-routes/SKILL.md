---
name: sast-nodejs-routes
description: >-
  Enumerate every API route in a Node.js codebase and perform unlimited-depth
  function call tracing from each route handler through all project-defined code.
  Produces a complete route-to-callgraph map with security-sensitive operations
  flagged at every layer. Uses a three-phase approach: recon (enumerate all
  routes and their handlers), batched trace (3 routes per subagent, recursive
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

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

---

### Phase 1: Route Enumeration

Launch a subagent with the following instructions:

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
>
> **NestJS**:
> - Search for `@Controller(` to find all controller classes and their base paths
> - Within each controller, search for `@Get(`, `@Post(`, `@Put(`, `@Delete(`, `@Patch(`, `@All(` — note sub-path and the method name immediately below the decorator
> - Compute full path = controller base path + method sub-path
> - Note any `@UseGuards(`, `@Roles(`, `@Public(` decorators on the method — these affect authentication
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
> **For each route, also record**:
> - Whether an auth middleware or guard is listed in the route definition (e.g., `router.get('/path', authMiddleware, handler)` — note `authMiddleware`)
> - The file and approximate line number of the route registration
> - The file and approximate line number of the handler function definition (if it can be located)
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
> ## Routes
>
> ### 1. [METHOD] [full-path]
> - **File**: `path/to/routes.ts` (line X — route registration)
> - **Handler**: `functionName()` in `path/to/handler.ts` (line Y)
> - **Auth middleware**: [list middleware names, or "none detected"]
> - **Guard / decorator**: [e.g., `@UseGuards(JwtAuthGuard)`, or "none"]
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

After Phase 1 completes, read `sast/nodejs-routes-recon.md` and split the routes into **batches of up to 3 routes each**. Launch **one subagent per batch in parallel**.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/nodejs-routes-recon.md` and count the numbered route sections (`### 1.`, `### 2.`, ...).
2. Divide into batches of up to 3.
3. For each batch, extract the full text of those route sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each its assigned routes.
5. Each subagent writes to `sast/nodejs-routes-batch-N.md`.

Give each batch subagent the following instructions (substitute batch-specific values):

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
> 1. **Start at the handler function**. Read its full source code.
>
> 2. **List every function call** made in the handler body. For each call:
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
>
> For each flagged operation, also note whether you can see a variable that appears to carry user input (from `req.body`, `req.query`, `req.params`, `req.headers`, etc.) flowing into it. If yes, mark it `🔴 user-tainted`; if it appears server-side only, mark `🟢 server-side only`; if uncertain, mark `🟡 unknown`.
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
> **Important notes for the subagent**:
> - You must actually READ each referenced file to trace the call chain — do not guess at function bodies.
> - When an import resolves to a file you've already read for a previous route in this batch, you may reuse your memory of it — you don't need to re-read it.
> - For functions that are very long or have many branches, trace all branches but you may summarize repeated patterns (e.g., "same DB call pattern as branch A").
> - If a function is called with multiple different arguments across the codebase, focus on this specific call site's argument values.
> - Use indentation to show nesting depth. `├──` for non-last children, `└──` for last child.

---

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/nodejs-routes-batch-*.md` file and merge them into `sast/nodejs-routes.md`. You (the orchestrator) do this directly — no subagent needed.

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

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes.
- Phase 3 must run AFTER all Phase 2 batches complete.
- Batch size is **3 routes per subagent**. For large projects with many routes, this produces many subagents — that is expected and correct.
- Launch all batch subagents **in parallel** — do not run them sequentially.
- **This skill traces FORWARD from routes**, unlike other SAST skills that search for sinks and trace backward. The call tree is the primary output; the security-sensitive operation flags are annotations on the tree, not the final verdict.
- **The taint annotation (🔴/🟡/🟢) is a best-effort assessment** made by the subagent reading the code. The other vulnerability skills (sast-sqli, sast-rce, sast-ssrf, etc.) should be run afterward to confirm exploitability — this skill identifies WHERE to look, not whether it's exploitable.
- For very large projects (100+ routes), consider running this skill on a specific subdirectory or router file rather than the entire project. Pass a note to the Phase 1 subagent scoping the search.
- The Cross-Route Sensitive Operations Index in the output is especially useful: a DB helper called from 20 different routes is a higher-value target than one called from a single route.
- When the Phase 2 subagent encounters a function definition it cannot find (import resolves to a path that doesn't exist or is ambiguous), it should mark it `[unresolved]` and continue — do not halt the trace.
- Clean up all intermediate files after writing the final `sast/nodejs-routes.md`.
