---
name: sast-missingauth
description: >-
  Detect missing authentication and broken function-level authorization
  vulnerabilities in a codebase using a three-phase approach: recon (map
  endpoints and the role/permission system), batched verify (check auth/authz
  in parallel subagents, 3 endpoints each), and merge (consolidate batch
  results). Covers unauthenticated access and vertical privilege escalation
  (e.g., regular user accessing admin-only functions). Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/missingauth-results.md. Use when asked to find missing auth, broken
  access control, or privilege escalation bugs.
---

# Missing Authentication & Broken Function-Level Authorization Detection

You are performing a focused security assessment to find missing authentication and broken function-level authorization vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (map endpoints and the permission system), **batched verify** (check authentication and authorization in parallel batches of 3 endpoints each), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What This Skill Covers

### Missing Authentication
An endpoint performs a sensitive action but requires **no login at all** — any anonymous HTTP request can trigger it.

### Broken Function-Level Authorization
An endpoint requires authentication (user must be logged in) but **does not check whether the authenticated user has the required role or permission** to invoke that function. The classic example: a regular user calling an admin-only API.

### What This Skill Is NOT

Do not conflate with:
- **IDOR / Horizontal privilege escalation**: Authenticated user A accessing user B's resource by changing an ID. This skill covers **vertical** privilege escalation and unauthenticated access.
- **JWT weaknesses**: Flawed token signing/verification (covered by sast-jwt).
- **Business logic flaws**: Price manipulation, workflow bypass — these are separate.

---

## Vulnerability Classes

### Class 1: Unauthenticated Sensitive Endpoint
The endpoint modifies data, returns private information, or performs an administrative action — with no authentication required.

```
GET /api/admin/users          → returns full user list, no token needed
DELETE /api/admin/users/5     → deletes a user, no token needed
POST /api/settings/smtp       → updates server config, no token needed
```

### Class 2: Authenticated but Missing Role Check
The endpoint requires a valid session/token but performs no role or permission check. Any authenticated user — regardless of role — can invoke admin or privileged functions.

```
Regular user sends:
DELETE /api/admin/users/5
Authorization: Bearer <regular_user_token>
→ Server deletes the user without checking if the caller is an admin
```

### Class 3: Incomplete or Bypassable Authorization
Authorization logic is present but can be bypassed:
- Role check exists in the GET handler but not in the corresponding DELETE/POST handler
- Role check is conditional on a request header or parameter the attacker controls
- Middleware is registered but the route is mounted before the middleware applies

### Class 4: Next.js Route Group Middleware Gap
Applies to Next.js App Router projects. A route inside a parenthesized route group folder (e.g., `app/(dashboard)/settings/page.tsx`) resolves to a URL that strips the group name (e.g., `/settings`). If the `middleware.ts` matcher does not include that URL pattern, the route bypasses middleware entirely — even when the developer intended the group to be protected.

Common ways this manifests:
- Matcher only covers `/dashboard/*` but the route group `(dashboard)` resolves routes to `/settings`, `/profile`, `/billing` — NOT under `/dashboard/`
- Matcher uses a positive allowlist that omits some route group paths
- New route groups are added without updating the `middleware.ts` matcher
- API route handlers (`route.ts`) inside ungrouped or mismatched directories bypass middleware

```
# Example: developer expects /settings to be protected because it's in (dashboard)
# But middleware.ts only matches /dashboard/*

app/
  (dashboard)/
    settings/page.tsx   → URL: /settings   ← NOT matched by /dashboard/*
    profile/page.tsx    → URL: /profile    ← NOT matched by /dashboard/*

middleware.ts:
  matcher: ['/dashboard/:path*']   ← misses all (dashboard) group routes!
```

---

## Authorization Patterns That PREVENT Vulnerabilities

When you see these patterns, the endpoint is likely **not vulnerable**:

**1. Authentication + role-check middleware on a route group**
```javascript
// Express: all /admin routes protected
router.use('/admin', auth, requireRole('admin'));
router.delete('/admin/users/:id', deleteUser);   // protected by above

// Flask-Login + custom decorator
@app.route('/admin/users')
@login_required
@admin_required
def list_users(): ...
```

**2. Declarative role annotations (Java / Spring)**
```java
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/api/admin/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) { ... }
```

**3. In-handler role check before sensitive action**
```python
# Django
@login_required
def delete_user(request, user_id):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    User.objects.filter(id=user_id).delete()
    return HttpResponse(status=204)
```

**4. Middleware gate applied to entire prefix**
```go
// Chi router — admin group protected
r.Group(func(r chi.Router) {
    r.Use(AdminOnly)
    r.Delete("/admin/users/{id}", deleteUser)
})
```

**5. Policy/Gate objects**
```php
// Laravel Gate
Gate::define('admin-action', fn($user) => $user->role === 'admin');
// In controller
$this->authorize('admin-action');
```

**6. Next.js App Router — double-layer protection**
```typescript
// middleware.ts — matcher covers all non-public routes
export const config = { matcher: ['/((?!login|register|_next/static|_next/image|favicon\.ico).*)'] }
export default withAuth(middleware, { pages: { signIn: '/login' } })

// app/(dashboard)/layout.tsx — server-side auth guard as second layer
export default async function DashboardLayout({ children }) {
  const session = await getServerSession(authOptions)
  if (!session) redirect('/login')
  return <>{children}</>
}
```

---

## Vulnerable vs. Secure Examples

### Python — Django

```python
# VULNERABLE: No authentication at all
def list_all_users(request):
    users = User.objects.values('id', 'email', 'is_staff')
    return JsonResponse(list(users), safe=False)

# VULNERABLE: Authenticated but no role check
@login_required
def delete_user(request, user_id):
    User.objects.filter(id=user_id).delete()
    return HttpResponse(status=204)

# SECURE
@login_required
def delete_user(request, user_id):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    User.objects.filter(id=user_id).delete()
    return HttpResponse(status=204)
```

### Python — Flask

```python
# VULNERABLE: No auth decorator
@app.route('/admin/users')
def list_users():
    return jsonify([u.to_dict() for u in User.query.all()])

# VULNERABLE: Login required but no role check
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return '', 204

# SECURE
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return '', 204
```

### Node.js — Express

```javascript
// VULNERABLE: No auth middleware
router.get('/api/admin/users', async (req, res) => {
    const users = await User.find({});
    res.json(users);
});

// VULNERABLE: Auth middleware present but no role check
router.delete('/api/admin/users/:id', auth, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.sendStatus(204);
});

// SECURE
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    next();
};
router.delete('/api/admin/users/:id', auth, requireAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.sendStatus(204);
});
```

### Ruby on Rails

```ruby
# VULNERABLE: No before_action
def destroy
    User.find(params[:id]).destroy
    head :no_content
end

# VULNERABLE: Authenticated but no admin check
before_action :authenticate_user!
def destroy
    User.find(params[:id]).destroy
    head :no_content
end

# SECURE
before_action :authenticate_user!
before_action :require_admin

def destroy
    User.find(params[:id]).destroy
    head :no_content
end

private

def require_admin
    head :forbidden unless current_user.admin?
end
```

### Java — Spring Boot

```java
// VULNERABLE: No security annotation
@DeleteMapping("/api/admin/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepo.deleteById(id);
    return ResponseEntity.noContent().build();
}

// VULNERABLE: Authenticated but wrong role
@DeleteMapping("/api/admin/users/{id}")
@Secured("ROLE_USER")  // any user can call this
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepo.deleteById(id);
    return ResponseEntity.noContent().build();
}

// SECURE
@DeleteMapping("/api/admin/users/{id}")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepo.deleteById(id);
    return ResponseEntity.noContent().build();
}
```

### Go

```go
// VULNERABLE: No auth middleware on route
r.Delete("/admin/users/{id}", deleteUser)

// VULNERABLE: Auth middleware but no role check in handler
r.With(AuthMiddleware).Delete("/admin/users/{id}", deleteUser)

func deleteUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    db.DeleteUser(id)  // no role check
    w.WriteHeader(http.StatusNoContent)
}

// SECURE
r.Group(func(r chi.Router) {
    r.Use(AuthMiddleware)
    r.Use(AdminOnlyMiddleware)
    r.Delete("/admin/users/{id}", deleteUser)
})
```

### PHP — Laravel

```php
// VULNERABLE: No auth middleware
Route::delete('/admin/users/{id}', [AdminController::class, 'destroy']);

// VULNERABLE: Auth but no role gate
Route::middleware('auth')->delete('/admin/users/{id}', [AdminController::class, 'destroy']);

// SECURE
Route::middleware(['auth', 'role:admin'])->delete('/admin/users/{id}', [AdminController::class, 'destroy']);

// SECURE (using Gate in controller)
public function destroy($id) {
    Gate::authorize('admin-action');
    User::findOrFail($id)->delete();
    return response()->noContent();
}
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: No authorization attribute
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}

// VULNERABLE: [Authorize] but no role
[Authorize]
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}

// SECURE
[Authorize(Roles = "Admin")]
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Map Endpoints and Permission System

Launch a subagent with the following instructions:

> **Goal**: Build a complete map of (1) all application endpoints/routes and their current authentication/authorization posture, and (2) the role/permission system. Write results to `sast/missingauth-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, route definitions, and the auth/authz strategy.
>
> **What to search for**:
>
> 1. **All route/endpoint definitions** — collect every HTTP handler, REST endpoint, GraphQL mutation/query, RPC method, or WebSocket handler:
>    - Express/Koa: `router.get/post/put/delete/patch/use`
>    - Django: `urlpatterns`, `path()`, `re_path()`
>    - Flask: `@app.route`, `@blueprint.route`
>    - Rails: `routes.rb` — `get`, `post`, `resources`, `namespace`
>    - Spring: `@GetMapping`, `@PostMapping`, `@RequestMapping`, `@DeleteMapping`, `@PutMapping`
>    - Go/Chi: `r.Get`, `r.Post`, `r.Delete`, `r.Handle`
>    - Laravel: `Route::get/post/put/delete`
>    - FastAPI: `@router.get/post/put/delete`
>    - ASP.NET: `[HttpGet]`, `[HttpPost]`, `[HttpDelete]`, `[HttpPut]`
>
> 2. **Authentication middleware and decorators** currently applied:
>    - Identify the pattern used: `@login_required`, `auth` middleware, `[Authorize]`, `authenticate_user!`, JWT verification middleware, session checks
>    - Note which routes or route groups they are applied to
>    - Note any routes explicitly excluded from auth (e.g., `except: [:index, :show]`)
>    - **For Next.js**: read `middleware.ts` / `middleware.js` (project root or `src/`) in full:
>      - Extract the `matcher` from `export const config = { matcher: [...] }`
>      - Determine what the middleware function actually enforces (auth check / redirect / analytics only)
>      - For each page route and API route handler, evaluate whether its URL matches the matcher patterns
>      - Route Group folders `(groupName)` do NOT appear in the URL — compute effective URLs first, then check matcher coverage
>      - An API route handler (`route.ts`) has no layout, so if middleware doesn't cover it, it has no automatic auth
>
> 3. **Role/permission system** — identify how roles are defined and checked:
>    - Role constants/enums: `ROLE_ADMIN`, `'admin'`, `UserRole.ADMIN`, `is_staff`, `is_superuser`
>    - Permission decorators: `@admin_required`, `@roles_required`, `@PreAuthorize`, `requireRole()`
>    - Middleware: `AdminOnly`, `requireAdmin`, `role:admin`
>    - Policy/Gate/Ability objects: `Gate::define`, `Policy`, `CanCanCan`, `Pundit`
>    - In-handler checks: `if user.role != 'admin'`, `if not current_user.is_admin`
>
> 4. **Sensitive/privileged endpoints** to flag — any endpoint that:
>    - Has an `/admin`, `/management`, `/internal`, `/api/admin`, `/superadmin`, `/system`, `/ops` path prefix
>    - Performs user management: create/update/delete users, change roles, reset passwords for others
>    - Manages application configuration: settings, feature flags, SMTP, secrets, environment variables
>    - Accesses financial/billing data: invoices, payments, subscriptions for all users
>    - Triggers system actions: sending emails to all users, running background jobs, clearing caches
>    - Returns aggregate or sensitive data: all users, all orders, audit logs, error logs
>
> 5. **For each endpoint, note**:
>    - Whether an auth middleware/decorator is present
>    - Whether a role/permission check is present
>    - The HTTP method(s) it handles
>    - Whether it reads, writes, or deletes data
>    - **For Next.js**: the Route Group it belongs to, effective URL (after stripping group names), middleware coverage status, and layout auth status
>
> 6. **For Next.js projects — Route Group Middleware Gap Analysis**:
>    - List all Route Group folders found under `app/`
>    - For each group: what is the middleware matcher, and does the matcher cover the effective URLs of routes in this group?
>    - Flag any group where: middleware does NOT cover its routes AND the layout.tsx does NOT perform an auth check
>    - Flag any `route.ts` API handlers that are neither covered by middleware NOR have in-handler auth checks
>
> **What to ignore**:
> - Publicly intended endpoints: login, register, password reset request, public content (blog posts, product listings)
> - Static asset serving, health-check endpoints (`/health`, `/ping`, `/status`)
>
> **Output format** — write to `sast/missingauth-recon.md`:
>
> ```markdown
> # Missing Auth Recon: [Project Name]
>
> ## Permission System Summary
> - Roles identified: [list roles, e.g. admin, moderator, user]
> - Auth mechanism: [JWT / session / API key / OAuth]
> - Auth decorators/middleware: [list names, e.g. @login_required, auth, requireAdmin]
>
> ## [Next.js only] Middleware Matcher Analysis
> - Middleware file: [path or "not found"]
> - Matcher patterns: [exact strings from config.matcher]
> - Middleware enforces: [auth redirect / session check / none / analytics only]
>
> | Route Group | Example URL | Matcher covers? | Layout auth? | Posture |
> |---|---|---|---|---|
> | `(dashboard)` | `/profile` | 🔴 NO | ✅ Yes | ⚠️ Partial |
> | `(admin)` | `/admin/users` | ✅ Yes | ✅ Yes | ✅ Protected |
> | [root] | `/api/data` | 🔴 NO | N/A | 🔴 Unprotected |
>
> ## Endpoint Inventory
>
> ### 1. [Endpoint name / description]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Operation**: [read / write / delete / admin-action]
> - **Auth present**: [yes / no]
> - **Role check present**: [yes / no / partial]
> - **[Next.js] Route Group**: `(groupName)` or [root] or N/A
> - **[Next.js] Middleware coverage**: ✅ covered / 🔴 NOT covered / N/A
> - **[Next.js] Layout auth**: ✅ yes / ⚠️ no / N/A
> - **Code snippet**:
>   ```
>   [route registration + handler signature]
>   ```
>
> [Repeat for each endpoint]
> ```

### Phase 2: Verify — Check Authentication and Authorization (Batched)

After Phase 1 completes, read `sast/missingauth-recon.md` and split the endpoint inventory into **batches of up to 3 endpoints each** (each numbered `### N.` under **Endpoint Inventory**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned endpoints and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/missingauth-recon.md` and count the numbered endpoint sections under **Endpoint Inventory** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 endpoints → 3 batches (1–3, 4–6, 7–8).
3. For each batch, extract the full text of those endpoint sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned endpoints.
5. Each subagent writes to `sast/missingauth-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Python/Django, include only the "Python — Django" (and if relevant, Flask) examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Verify the following endpoints for missing authentication and broken function-level authorization vulnerabilities. Write results to `sast/missingauth-batch-[N].md`.
>
> **Your assigned endpoints** (from the recon phase):
>
> [Paste the full text of the assigned endpoint sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the middleware ordering, role definitions, and auth patterns.
>
> **Missing auth / broken function-level auth — what to look for**:
>
> - **Missing authentication**: Sensitive action with no login/session/token required.
> - **Broken function-level authorization**: Authentication is required but no role/permission check on a privileged endpoint (vertical escalation).
>
> **What this skill is NOT** — do not flag these here:
> - **IDOR / horizontal escalation**: User A accessing user B's resource by changing an ID → covered by the IDOR skill.
> - **JWT crypto/verification bugs** → covered by sast-jwt.
>
> **Authorization patterns that PREVENT issues** — if you see these, the endpoint is likely safe:
> 1. **Authentication + role-check middleware on a route group** (e.g., `router.use('/admin', auth, requireRole('admin'))`)
> 2. **Declarative role annotations** (e.g., `@PreAuthorize("hasRole('ADMIN')")`)
> 3. **In-handler role check** before sensitive action
> 4. **Middleware gate on entire prefix** (e.g., Chi `r.Group` with `AdminOnly`)
> 5. **Policy/Gate** objects enforcing privileged actions
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned endpoint, evaluate**:
>
> 1. **Authentication check** — is a valid login/session/token required?
>    - Is there an auth middleware, decorator, or guard on this route or its parent group?
>    - Trace the middleware chain — confirm the auth middleware runs BEFORE the handler, not after
>    - Check if the route is accidentally mounted outside an auth-protected group
>    - **For Next.js**: check BOTH layers:
>      - **Layer 1 — middleware.ts**: does the matcher cover this route's effective URL? Read `middleware.ts` and evaluate whether the function actually enforces auth (not just sets headers or logs).
>      - **Layer 2 — layout.tsx**: does the nearest `layout.tsx` (in the same Route Group folder or a parent) perform `getServerSession()` / `auth()` / `cookies()` and redirect on failure?
>      - **API route handlers (`route.ts`)**: no layout applies — check middleware coverage AND in-handler auth checks (e.g., `const session = await getServerSession(); if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })`)
>      - A route is unprotected if BOTH layers are absent. A route is partially protected if only one layer is present.
>
> **Deep Internal Call Tracing — follow ALL project-defined middleware and guard functions**
>
> When a middleware, guard, or auth helper is referenced, read its full implementation:
> 1. Look up the function definition. Is it defined in this project (not in `node_modules/`)?
> 2. If YES: read that function's source code. Follow all internal calls recursively.
> 3. Continue until you reach one of three terminal conditions:
>    - (a) An authentication check (token verification, session lookup, `req.user` assignment)
>    - (b) A `node_modules` import boundary — authentication is delegated to a library
>    - (c) The function returns or calls `next()` without performing any authentication check
> 4. Document the chain, e.g.:
>    `authMiddleware() → verifyToken() → jwt.verify(token, secret)` — or note where the chain skips auth.
>
> Do NOT assume a function named `auth`, `authenticate`, or `requireLogin` actually verifies credentials. Read its source to confirm. A middleware may call `next()` unconditionally or only check for the header's presence without validating its value.
>
> 2. **Role/permission check** — if the endpoint is privileged, is a role or permission verified?
>    - Look for: `is_admin`, `is_staff`, `role == 'admin'`, `hasRole('ADMIN')`, `@PreAuthorize`, `requireRole`, `can?(:manage, ...)`, `Gate::allows`, `authorize('admin-action')`
>    - Verify the check runs on every HTTP method — a DELETE may be unguarded even if GET is protected
>    - Check that the role comparison is not inverted or trivially bypassable
>
> 3. **Edge cases**:
>    - Is the check conditional on a user-controlled header, parameter, or query string?
>    - Does the auth gate apply to the route group but the specific route is excluded via an `except` list?
>    - Is there a secondary unauthenticated path to the same function (e.g., an internal API alias)?
>    - Does the middleware apply only to some environments (e.g., skipped in test mode)?
>
> 4. **Privilege identification**:
>    - Does the endpoint path suggest it is admin/privileged (`/admin/`, `/manage/`, `/internal/`)?
>    - Does the operation affect other users' data, system configuration, or aggregate records?
>    - If yes to either, a role/permission check should be present
>
> **Classification**:
> - **Vulnerable**: No authentication required, or authenticated but role check is entirely absent on a privileged endpoint.
> - **Likely Vulnerable**: Auth and/or role check exists but appears incomplete, bypassable, or misapplied (e.g., wrong role, wrong HTTP method, conditional skip).
> - **Not Vulnerable**: Proper authentication and role/permission checks are in place.
> - **Needs Manual Review**: Cannot determine with confidence (e.g., complex middleware chain, dynamic role loading, authorization delegated to a service layer).
>
> **Output format** — write to `sast/missingauth-batch-[N].md`:
>
> ```markdown
> # Missing Auth Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Issue**: [Missing authentication / Missing role check for privileged action]
> - **Impact**: [What an unauthenticated or low-privilege attacker can do]
> - **Proof**: [Show the route definition and handler — highlight the missing check]
> - **Remediation**: [Specific fix — add auth middleware, add role decorator, etc.]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step to confirm on the live app.
>    For missing auth: show the request with NO token succeeding.
>    For missing role: show the request with a regular user token succeeding on an admin endpoint.
>    Use placeholders like <REGULAR_USER_TOKEN>, <ADMIN_ENDPOINT>.]
>   ```
>
> ### [LIKELY VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Issue**: [What's incomplete about the check]
> - **Concern**: [Why this might still be exploitable]
> - **Proof**: [Show the code path with the weak/partial check]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step instructions to confirm this finding on the live app.]
>   ```
>
> ### [NOT VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Protection**: [How it's protected — auth middleware + role decorator / @PreAuthorize / Gate, etc.]
>
> ### [NEEDS MANUAL REVIEW] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Uncertainty**: [Why automated analysis couldn't determine the status]
> - **Suggestion**: [What to look at manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/missingauth-batch-*.md` file and merge them into a single `sast/missingauth-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/missingauth-batch-1.md`, `sast/missingauth-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/missingauth-results.md` using this format:

```markdown
# Missing Auth/Authz Analysis Results: [Project Name]

## Executive Summary
- Endpoints analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/missingauth-results.md`, **delete all intermediate files**: `sast/missingauth-recon.md` and `sast/missingauth-batch-*.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 endpoints per subagent**. If there are 1–3 endpoints total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned endpoints' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- Focus on **vertical privilege escalation** (user → admin) and **unauthenticated access**. Horizontal escalation (user A → user B's resource) is covered by the IDOR skill.
- Authentication (you are who you say you are) and authorization (you are allowed to do this) are separate concerns — check both.
- Middleware order matters: a middleware registered after the route handler will NOT protect the route.
- A missing auth or role check on one HTTP method (e.g., DELETE) is a full vulnerability even if GET is protected.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Pay attention to route grouping: a `use('/admin', adminRouter)` pattern protects all routes in `adminRouter`, but routes mounted outside that group are not protected.
- **For Next.js App Router**: Route Group folder names in parentheses `(like-this)` do NOT appear in the URL. Always compute effective URLs before checking middleware matcher coverage. A developer may name a group `(protected)` and assume it's protected, but the matcher only cares about the URL pattern, not the folder name.
- **For Next.js App Router**: Always check both protection layers — middleware.ts AND layout.tsx. An unprotected API route handler (`route.ts`) is especially dangerous because it has no layout layer.
- **For Next.js App Router**: The middleware function must actually enforce auth (check session, verify token, redirect on failure). A middleware that only sets headers or calls `next()` unconditionally provides no protection even if the matcher covers the route.
- Clean up intermediate files: delete `sast/missingauth-recon.md` and all `sast/missingauth-batch-*.md` files after the final `sast/missingauth-results.md` is written.
