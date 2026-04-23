---
name: sast-nodejs
description: >-
  Detect Node.js-specific vulnerabilities in a codebase using a three-phase
  approach: recon (find NoSQL injection, prototype pollution, and mass assignment
  sinks), batched verify (trace user input to sinks in parallel subagents, 3
  sinks each), and merge (consolidate batch results). Covers MongoDB operator
  injection, lodash/deepmerge prototype pollution, and Mongoose/Sequelize/TypeORM
  mass assignment. Requires sast/architecture.md (run sast-analysis first).
  Outputs findings to sast/nodejs-results.md. Use when asked to find Node.js-
  specific bugs or when the project uses Express, NestJS, Fastify, Koa, or Hapi
  with MongoDB, Mongoose, Sequelize, or TypeORM.
---

# Node.js Specific Vulnerability Detection

You are performing a focused security assessment to find Node.js-specific vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find NoSQL injection, prototype pollution, and mass assignment sinks), **batched verify** (trace whether user-supplied input reaches each sink, in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## Vulnerability Classes Covered

---

### Class 1: NoSQL Injection (MongoDB)

NoSQL injection in MongoDB occurs when user-supplied data is used directly as a query filter object or embedded inside one, allowing attackers to inject MongoDB query operators (`$where`, `$gt`, `$ne`, `$regex`, etc.) that alter query logic.

#### What NoSQL Injection IS

- Passing `req.body` or `req.query` directly as a Mongoose/MongoDB filter:
  `User.findOne(req.body)` — attacker sends `{"username": "admin", "password": {"$gt": ""}}`
- Using `$where` with string concatenation: `db.collection.find({ $where: "this.username == '" + username + "'" })`
- Regex injection: `User.find({ name: req.query.name })` where attacker sends `{"$regex": ".*"}`
- Operator injection via nested query parameters: `Model.find({ price: req.query.price })` where Express parses `?price[$lt]=999999` as `{ price: { '$lt': '999999' } }`

#### What NoSQL Injection is NOT

- SQL injection (different database system — flag as SQLi, not NoSQL injection)
- Prototype pollution (separate class — covered below)

#### Patterns That Prevent NoSQL Injection

```javascript
// 1. Explicit field extraction — never spread entire req.body into a query
const { username, password } = req.body;
User.findOne({ username: String(username), password: String(password) });

// 2. Input validation with joi / zod / express-validator (strict shape + types)
const schema = Joi.object({ username: Joi.string().required(), password: Joi.string().required() });
const { value, error } = schema.validate(req.body);
if (error) return res.status(400).send(error.details);
User.findOne({ username: value.username, password: value.password });

// 3. express-mongo-sanitize middleware — strips keys beginning with $ or containing .
app.use(mongoSanitize());  // applied globally before routes

// 4. Type coercion — reduces risk for simple cases but is NOT equivalent to schema validation
User.find({ age: Number(req.query.age) });  // Likely Vulnerable if no further validation
```

#### Vulnerable vs. Secure Examples

```javascript
// VULNERABLE: entire req.body spread into findOne — operator injection
app.post('/login', async (req, res) => {
  const user = await User.findOne(req.body);
  // attacker: {"username": "admin", "password": {"$gt": ""}} → auth bypass
  if (user) res.json({ token: generateToken(user) });
  else res.status(401).send('Invalid credentials');
});

// VULNERABLE: $where with string concatenation
app.get('/search', (req, res) => {
  const name = req.query.name;
  db.collection('users').find({ $where: `this.name == '${name}'` }).toArray(...);
  // attacker: ?name=x' || '1'=='1  → returns all users
});

// VULNERABLE: query parameter used directly as filter value (object injection)
app.get('/products', async (req, res) => {
  const products = await Product.find({ price: req.query.price });
  // Express qs: ?price[$lt]=999999 → { price: { '$lt': '999999' } }
  res.json(products);
});

// SECURE: explicit field extraction + type coercion
app.post('/login', async (req, res) => {
  const username = String(req.body.username);
  const password = String(req.body.password);
  const user = await User.findOne({ username, password });
  ...
});

// SECURE: express-mongo-sanitize middleware
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());
```

---

### Class 2: Prototype Pollution

Prototype pollution occurs when user-supplied data is merged into a JavaScript object in a way that allows setting properties on `Object.prototype`, affecting all objects in the application and potentially enabling property injection, privilege escalation, or Remote Code Execution via gadget chains.

#### What Prototype Pollution IS

- Deep merge with user-controlled objects:
  `_.merge({}, req.body)` — attacker sends `{"__proto__": {"isAdmin": true}}`
- `_.set(obj, userKey, userValue)` where `userKey` is `__proto__.isAdmin`
- `deepmerge(target, req.body)` without prototype-pollution protection
- jQuery `$.extend(true, {}, userObject)` — deep extend is vulnerable
- Any custom recursive object merge function applied to user-controlled data

#### What Prototype Pollution is NOT

- `Object.assign({}, req.body)` — shallow assign does NOT recurse into `__proto__`; lower risk but still note it if used in patterns that others build on
- Reading individual properties from user input without merging
- XSS, SQLi, or other injection classes

#### Patterns That Prevent Prototype Pollution

```javascript
// 1. null-prototype target — no Object.prototype chain to pollute
const safe = Object.create(null);
_.merge(safe, req.body);

// 2. Key sanitization before deep merge
function sanitizeKeys(obj) {
  const dangerous = ['__proto__', 'constructor', 'prototype'];
  for (const key of Object.keys(obj)) {
    if (dangerous.includes(key)) { delete obj[key]; continue; }
    if (typeof obj[key] === 'object' && obj[key] !== null) sanitizeKeys(obj[key]);
  }
  return obj;
}
_.merge({}, sanitizeKeys(JSON.parse(JSON.stringify(req.body))));

// 3. Use patched library versions — lodash >= 4.17.21 patches _.merge for direct __proto__
//    but may not cover constructor.prototype; verify exact version and test both attack vectors

// 4. JSON schema validation rejecting unexpected keys / unknown nesting
```

#### Vulnerable vs. Secure Examples

```javascript
// VULNERABLE: lodash _.merge with req.body — __proto__ pollution
app.post('/settings', (req, res) => {
  const settings = {};
  _.merge(settings, req.body);
  // attacker: {"__proto__": {"isAdmin": true}} → Object.prototype.isAdmin = true
  res.json({ success: true });
});

// VULNERABLE: _.set with user-controlled key
app.patch('/config', (req, res) => {
  const { key, value } = req.body;
  _.set(appConfig, key, value);
  // attacker: key = "__proto__.debug", value = true
  res.json({ updated: true });
});

// VULNERABLE: deepmerge on req.body
const deepmerge = require('deepmerge');
app.put('/profile', (req, res) => {
  user.profile = deepmerge(user.profile, req.body);
  res.json(user.profile);
});

// SECURE: null-prototype target
app.post('/settings', (req, res) => {
  const settings = Object.create(null);
  _.merge(settings, req.body);
  res.json({ success: true });
});
```

---

### Class 3: Mass Assignment

Mass assignment occurs when user-supplied data (typically `req.body`) is passed directly to an ORM model constructor or update method without filtering which fields the user is permitted to set. Attackers can inject fields like `isAdmin`, `role`, `balance`, or `verified`.

#### What Mass Assignment IS

- `new Model(req.body)` or `Model.create(req.body)` — all fields in req.body set on the model
- Mongoose with `strict: false` schema option — allows arbitrary fields
- Sequelize `Model.create(req.body)` or `instance.update(req.body)` without `fields` whitelist
- TypeORM `repository.save(Object.assign(entity, req.body))` without field filtering
- `instance.set(req.body)` or `.assign(req.body)` on an ORM model without specifying allowed fields

#### What Mass Assignment is NOT

- Passing specific extracted fields: `new User({ username: req.body.username, email: req.body.email })`
- NestJS DTO with `ValidationPipe({ whitelist: true })` — only DTO-declared fields are accepted
- IDOR (accessing another user's object — different class)

#### Patterns That Prevent Mass Assignment

```javascript
// 1. Explicit field extraction via destructuring
app.post('/users', async (req, res) => {
  const { username, email, password } = req.body;
  const user = await User.create({ username, email, password });
  res.json(user);
});

// 2. Sequelize: fields whitelist option in create() / update()
await User.create(req.body, { fields: ['username', 'email', 'password'] });
await user.update(req.body, { fields: ['email', 'bio'] });

// 3. Lodash _.pick to whitelist fields
const allowedFields = ['username', 'email', 'bio'];
await User.create(_.pick(req.body, allowedFields));

// 4. NestJS: DTO class + ValidationPipe with whitelist: true
// @Body() userDto: CreateUserDto — only DTO properties pass through
// app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))

// 5. Mongoose strict: true (default) — prevents PERSISTENCE of unknown fields,
//    but does NOT prevent query operator injection (separate concern)
```

#### Vulnerable vs. Secure Examples

```javascript
// VULNERABLE: Mongoose create from full req.body
app.post('/register', async (req, res) => {
  const user = await User.create(req.body);
  // attacker: {"username":"x","password":"x","isAdmin":true,"role":"admin"}
  res.json(user);
});

// VULNERABLE: Mongoose strict: false
const UserSchema = new mongoose.Schema({ username: String }, { strict: false });
// Any field in a save() call is persisted — attacker can inject arbitrary fields

// VULNERABLE: Sequelize update without field whitelist
app.put('/profile/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  await user.update(req.body);  // attacker can set role, verified, balance
  res.json(user);
});

// VULNERABLE: TypeORM save with Object.assign from req.body
app.put('/users/:id', async (req, res) => {
  const user = await userRepo.findOne(req.params.id);
  await userRepo.save(Object.assign(user, req.body));
  res.json(user);
});

// SECURE: explicit field extraction
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const user = await User.create({ username, email, password });
  res.json(user);
});

// SECURE: Sequelize fields whitelist
app.put('/profile/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  await user.update(req.body, { fields: ['bio', 'avatarUrl', 'displayName'] });
  res.json(user);
});
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find NoSQL Injection, Prototype Pollution, and Mass Assignment Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a NoSQL injection, prototype pollution, or mass assignment vulnerability may exist. Flag ANY site where user-controlled data could reach a dangerous operation. Write results to `sast/nodejs-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, ORM/ODM in use, frameworks, and dependency versions.
>
> ---
>
> **Category 1 — NoSQL Injection sinks**:
>
> Search for MongoDB/Mongoose query calls where the filter argument may contain user-controlled data:
> - `Model.find(var)`, `Model.findOne(var)`, `Model.findById(var)` — flag if `var` is not a plain object literal with only hardcoded keys
> - `Model.find({ field: var })` where `var` is sourced from `req.query` or `req.body` without type coercion to a primitive (Express query strings without explicit typing can become objects)
> - `db.collection(name).find(var)`, `db.collection(name).findOne(var)` (native MongoDB driver)
> - `collection.aggregate([{ $match: var }])` — flag if `var` is not a literal
> - `{ $where: "..." + var + "..." }` — always flag (JavaScript execution in query context)
> - `{ field: { $regex: var } }` — flag if `var` is from user input (regex injection + potential ReDoS)
> - `Model.update(filter, var)` or `Model.updateMany(filter, var)` where `var` may contain user data
>
> **Category 2 — Prototype Pollution sinks**:
>
> Search for deep merge / recursive property assignment operations accepting user-controlled objects:
> - `_.merge(target, var)` — flag if `var` may be user data
> - `_.mergeWith(target, var, ...)` — flag if `var` may be user data
> - `_.set(obj, keyVar, valueVar)` — flag if `keyVar` is user-controlled
> - `$.extend(true, target, var)` (jQuery) — flag if `var` may be user data
> - `deepmerge(target, var)` — flag if `var` may be user data
> - Custom recursive merge functions called with `req.body` or derivatives
> - `Object.assign(target, var)` in patterns where callers perform recursive merges — note (lower risk for shallow assign but flag for review)
>
> **Category 3 — Mass Assignment sinks**:
>
> Search for ORM/ODM model creation/update calls where the entire request body or unfiltered superset is passed:
> - `new Model(req.body)` or `new Model(req.query)` — always flag
> - `Model.create(req.body)` — always flag
> - `Model.create(var)` — flag if `var` is traceable to `req.body` with no field filtering
> - `Model.insertMany(var)` — flag if `var` contains unsanitized user data
> - `instance.update(req.body)` or `instance.update(var)` without a `fields` array (Sequelize)
> - `instance.set(req.body)` (Mongoose)
> - `repository.save(Object.assign(entity, req.body))` or similar TypeORM patterns
> - `Model.findOrCreate({ where: ..., defaults: req.body })` — flag the defaults field
> - Mongoose schemas with `{ strict: false }` — note location; any `save()` on these models is a potential sink
>
> **What to skip**:
> - `Model.create({ username: req.body.username, email: req.body.email })` — explicit field extraction, not mass assignment
> - `_.merge({}, hardcodedObject)` — no user data involved
>
> **Output format** — write to `sast/nodejs-recon.md`:
>
> ```markdown
> # Node.js Recon: [Project Name]
>
> ## Summary
> Found [N] potential sinks: [X] NoSQL injection, [Y] prototype pollution, [Z] mass assignment.
>
> ## Sinks Found
>
> ### 1. [Descriptive name — e.g., "Mongoose findOne with full req.body in login handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Category**: [NoSQL Injection / Prototype Pollution / Mass Assignment]
> - **Sink**: [the dangerous call — e.g., `User.findOne(req.body)`]
> - **Dynamic argument(s)**: `var_name` — [brief note on what it appears to represent]
> - **Code snippet**:
>   ```
>   [relevant code around the sink]
>   ```
>
> [Repeat for each sink]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/nodejs-recon.md`. If the recon found **zero sinks** (the summary reports "Found 0" or the "Sinks Found" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following to `sast/nodejs-results.md`, **delete** `sast/nodejs-recon.md`, and stop:

```markdown
# Node.js Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one potential sink.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/nodejs-recon.md` and split the sinks into **batches of up to 3 sinks each**. Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sinks and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/nodejs-recon.md` and count the numbered sink sections (`### 1.`, `### 2.`, ...) under "Sinks Found".
2. Divide them into batches of up to 3. For example, 7 sinks → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those sink sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sinks.
5. Each subagent writes to `sast/nodejs-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: For each assigned Node.js vulnerability sink, determine whether a user-supplied value reaches the dangerous argument. Write results to `sast/nodejs-batch-[N].md`.
>
> **Your assigned sinks** (from the recon phase):
>
> [Paste the full text of the assigned sink sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, and how data flows through the application.
>
> **For each sink, trace the dynamic argument(s) backwards to their origin**:
>
> 1. **Direct user input** — the variable is assigned directly from a request source:
>    - Express: `req.body`, `req.body.field`, `req.query`, `req.query.field`, `req.params`, `req.params.id`, `req.headers['x']`, `req.cookies.x`
>    - NestJS: `@Body()`, `@Query()`, `@Param()`, `@Headers()` decorated parameters
>    - Fastify: `request.body`, `request.query`, `request.params`
>    - Koa: `ctx.request.body`, `ctx.query`, `ctx.params`
>    - Hapi: `request.payload`, `request.query`, `request.params`
>
> 2. **Indirect user input** — the variable is derived from user input through function calls, intermediate assignments, or helper utilities. Trace the full chain:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - Variable read from a class attribute or shared state set elsewhere → find the setter
>    - Variable conditionally assigned — check all branches
>
> **Deep Internal Call Tracing — follow ALL project-defined functions, no layer limit**
>
> When tracing a dynamic argument backward and it passes through an internal function call:
> 1. Look up the function definition. Is it defined in this project (not in `node_modules/`)?
> 2. If YES: read that function's source code. Follow the parameter that carries the tainted value. Repeat this process recursively.
> 3. Continue until you reach one of three terminal conditions:
>    - (a) A direct user input source (e.g., `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, `ctx.request.body`, `request.payload`)
>    - (b) A `node_modules` import boundary — the function is from an installed package, not project code
>    - (c) A hardcoded constant, environment variable, or value computed entirely from server-side state
> 4. Document each hop in the taint trace using arrow notation, e.g.:
>    `handler() → parseRequest() → buildFilter() → User.findOne(filter)`
>
> Do NOT stop at the first internal function call. Trace through helpers, services, repositories, utility modules, data-access layers, and transformation functions. Indirect flows through 5+ layers are common in layered Node.js applications and must be fully traced to avoid false negatives.
>
> 3. **Server-side / hardcoded value** — the variable comes from config, env var, hardcoded constant, or server-side logic with no user influence — NOT exploitable.
>
> **Mitigations to check**:
>
> For **NoSQL Injection**:
> - `express-mongo-sanitize` middleware applied globally before routes — effective if in place
> - Explicit field extraction + `String()`/`Number()` type coercion — reduces risk but may not cover all operator injection vectors; classify as Likely Vulnerable unless schema validation also present
> - Joi/Zod/express-validator schema validation with strict type and shape enforcement — effective if schema rejects object/operator inputs for value fields
>
> For **Prototype Pollution**:
> - Merge target is `Object.create(null)` — no prototype chain; effective mitigation
> - Key sanitization removing `__proto__`, `constructor`, `prototype` before merge — effective if applied recursively to all nesting levels
> - Lodash version >= 4.17.21 patches `_.merge` for `__proto__` but may not cover `constructor.prototype` — check exact version; classify as Likely Vulnerable if relying on library version alone
>
> For **Mass Assignment**:
> - Explicit field extraction via destructuring or `_.pick()` — effective if it covers all sensitive fields
> - Sequelize `fields` whitelist option in `create()`/`update()` — effective
> - Mongoose `strict: true` (default) — prevents persistence of extra schema fields but does NOT prevent query operator injection (these are separate concerns)
> - NestJS `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` with a DTO — effective if DTO covers all sensitive fields and pipe is applied globally or per endpoint
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the dangerous sink with no effective mitigation.
> - **Likely Vulnerable**: User input probably reaches the sink (indirect flow), or mitigation is partial (type coercion without schema validation, library version patch only, etc.).
> - **Not Vulnerable**: Argument is server-side only, OR effective mitigation is confirmed in place.
> - **Needs Manual Review**: Cannot determine argument origin with confidence.
>
> **Output format** — write to `sast/nodejs-batch-[N].md`:
>
> ```markdown
> # Node.js Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Category**: [NoSQL Injection / Prototype Pollution / Mass Assignment]
> - **Issue**: [e.g., "req.body spread directly into Mongoose findOne — operator injection possible"]
> - **Taint trace**: [Step-by-step from entry point to sink]
> - **Impact**: [What an attacker can do]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl or HTTP payload showing the attack — e.g.:
>    NoSQL: curl -X POST https://app.example.com/login -H "Content-Type: application/json" \
>           -d '{"username":"admin","password":{"$gt":""}}'
>    Proto: curl -X POST https://app.example.com/settings -H "Content-Type: application/json" \
>           -d '{"__proto__":{"isAdmin":true}}'
>    Mass:  curl -X POST https://app.example.com/register -H "Content-Type: application/json" \
>           -d '{"username":"x","password":"x","role":"admin","isAdmin":true}']
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Category**: [NoSQL Injection / Prototype Pollution / Mass Assignment]
> - **Issue**: [Indirect flow or partial mitigation]
> - **Taint trace**: [Best-effort trace with uncertain steps marked]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Fix]
> - **Dynamic Test**:
>   ```
>   [payload to attempt]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Explicit field extraction — only whitelisted properties used in query"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the variable's origin could not be determined]
> - **Suggestion**: [What to trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/nodejs-batch-*.md` file and merge them into a single `sast/nodejs-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/nodejs-batch-1.md`, `sast/nodejs-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/nodejs-results.md` using this format:

```markdown
# Node.js Analysis Results: [Project Name]

## Executive Summary
- Sinks analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/nodejs-results.md`, **delete all intermediate batch files** (`sast/nodejs-batch-*.md`) and **delete** `sast/nodejs-recon.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sinks per subagent**. If there are 1-3 sinks total, use a single subagent.
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sinks' text from the recon file.
- **Phase 1 is purely structural**: flag any sink where the argument is or may contain user data. Do not do taint analysis in Phase 1.
- **Phase 2 is purely taint analysis**: for each sink, trace the argument back to its origin. Use deep internal call tracing — follow all project-defined functions, no layer limit.
- For NoSQL injection: `Model.find({ field: req.query.field })` is flagged in Phase 1 because Express `qs` parses `?field[$gt]=` as an object. Phase 2 determines if type validation is present.
- For prototype pollution: the key risk is deep/recursive merge. Shallow `Object.assign({}, req.body)` is lower risk but note it in patterns that callers extend.
- For mass assignment: Mongoose `strict: true` prevents persistence of unknown fields but does NOT prevent query operator injection — these are distinct protections.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files after the final results file is written.
