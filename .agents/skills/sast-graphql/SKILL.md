---
name: sast-graphql
description: >-
  Detect GraphQL injection vulnerabilities in a codebase using a three-phase
  approach: recon (confirm GraphQL usage and find unsafe operation document
  assembly sites), batched verify (trace user input to those sites in parallel
  sequential batches of up to 3 candidate sites each), and merge (consolidate batch
  results). Requires sast/architecture.md (run sast-analysis first). Outputs
  findings to sast/graphql-results.md. If no GraphQL technology is found in
  Phase 1, later phases are skipped. Use when asked to find GraphQL injection,
  unsafe GraphQL document construction, or operation string injection bugs.
---

# GraphQL Injection Detection

You are performing a focused security assessment to find GraphQL injection vulnerabilities. This skill uses a three-phase approach: **recon** (confirm GraphQL usage and find every location where a GraphQL operation document is assembled unsafely), **batched verify** (trace whether user-supplied input reaches those assembly sites, in parallel batches of up to 3 sites each), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is GraphQL Injection

GraphQL injection occurs when user-controlled data is embedded into the **GraphQL document** (the query, mutation, or subscription string) rather than passed only through the **variables** map. The parser then interprets attacker-controlled syntax — new fields, aliases, directives, or fragments — which can bypass intent, reach unauthorized resolvers, or change server-side behavior when that document is executed or forwarded.

The core pattern: *unvalidated user input alters the structure or text of the GraphQL operation string passed to `execute`, `graphql`, a gateway client, or an HTTP body `query` field built from string operations.*

### What GraphQL Injection IS

- Concatenating or interpolating user input into an operation string: `` `query { user(id: "${id}") { name } }` ``, `"query { user(id: \"" + id + "\") { name } }"`
- Building the JSON `query` field for a downstream GraphQL HTTP request with string concat from request body or params
- Forwarding `req.body.query` (or similar) into another interpolated template that wraps or extends the operation
- Dynamic `gql` / `graphql-tag` template literals where a non-static expression changes document structure (not just a bound variable value inside a static document)
- Server-side code that selects or assembles operation text from user input (including "persisted query" ID → document maps without allowlisting)
- Wrappers around `graphql.execute()`, `graphqlHTTP`, Yoga/Apollo request pipeline where the first argument (document/source) is built from variables that could be user-influenced

### What GraphQL Injection is NOT

Do not flag these as GraphQL injection:

- **SQL injection in resolvers**: Resolver code that builds SQL from `args` — that is **SQL injection** (`sast-sqli`), not this skill
- **NoSQL / command injection in resolvers**: Same — use the appropriate SAST skill
- **IDOR via GraphQL arguments**: Passing another user's ID in a **variables** JSON with a **static** document — authorization flaw, not document injection
- **Normal variable binding**: Static document with `{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": userInput}}` — values are bound as variables; the document structure is fixed (still verify authorization in resolvers)
- **Introspection / field suggestion enabled**: Information disclosure and hardening topic; only flag as GraphQL injection if the finding is specifically about **injecting into the operation string**
- **Query depth / complexity DoS**: Rate limiting and cost analysis — different class

### Patterns That Prevent GraphQL Injection

**1. Static operation documents with variables**

```javascript
const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) { name }
  }
`;
// execute(schema, GET_USER, null, context, { id: userId });
```

**2. Server uses standard HTTP handler; client sends document; server parses once**

The risk is not the mere presence of `req.body.query` on the server if the server only parses and executes it as the client's operation — injection in *that* path is client-side. Flag **server-side** construction of a **new** document that incorporates user strings before `execute` or before forwarding.

**3. Persisted queries / allowlisted operation IDs**

Document looked up by ID from a server-side registry; client cannot inject arbitrary document text.

**4. graphql-js `Source` with static string; dynamic values only in variableValues**

```javascript
graphql({ schema, source: staticQueryString, variableValues: { id: userId } });
```

---

## Vulnerable vs. Secure Examples

### Node.js — dynamic document for downstream API

```javascript
// VULNERABLE: user input in operation text
app.post('/proxy', async (req, res) => {
  const fragment = req.body.fragment;
  const query = `query { me { ${fragment} } }`;
  const data = await fetch('https://api.internal/graphql', {
    method: 'POST',
    body: JSON.stringify({ query }),
  });
});

// SECURE: static operation, user data only in variables
const PROXY_QUERY = `query ProxyMe { me { id name email } }`;
app.post('/proxy', async (req, res) => {
  const data = await fetch('https://api.internal/graphql', {
    method: 'POST',
    body: JSON.stringify({ query: PROXY_QUERY }),
  });
});
```

### Python — string format into execute

```python
# VULNERABLE
def run_custom_query(user_gql: str):
    document = f"query {{ user {{ {user_gql} }} }}"
    return graphql_sync(schema, document)

# SECURE: validate against allowlist of named operations or use static documents only
ALLOWED = {"id", "name", "email"}
fields = [f for f in requested_fields if f in ALLOWED]
document = "query { user { " + " ".join(ALLOWED.intersection(set(requested_fields))) + " } }"
# Better: fixed FieldNodes, not string building from user input
```

---

## Execution

This skill runs entirely in your current context — do NOT spawn subagents. Read `sast/architecture.md` before starting and use it throughout.

### Phase 1: GraphQL Technology Recon and Injection Candidate Sites

**Do the following directly** (no subagents — you are the sole agent):

> **Goal**: (1) Determine whether this codebase uses GraphQL at all. (2) If it does, find every location where a GraphQL **operation document** (query/mutation/subscription source string) is built using string concatenation, interpolation, formatting, or dynamic assembly such that a variable could change the **document text** (not merely `variables` JSON). Write results to `sast/graphql-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it for stack, API layout, and BFF/gateway patterns.
>
> **Part A — Is GraphQL used?**
>
> Search for:
> - Dependencies: `graphql`, `@apollo/server`, `apollo-server-express`, `@nestjs/graphql`, `graphql-yoga`, `@graphql-yoga/node`, `mercurius`, `strawberry-graphql`, `graphene`, `sangria`, `gqlgen`, `async-graphql`, `juniper`, `graphql-ruby`, Hot Chocolate / `GraphQL.Server`, etc.
> - Schema artifacts: `*.graphql`, `*.graphqls`, codegen config (e.g. GraphQL Code Generator)
> - Server routes or plugins mounting `/graphql` or similar
>
> Set the summary to exactly one of:
> - `GraphQL is used in this codebase.` (list libraries and main entry points)
> - `GraphQL is not used in this codebase.`
>
> **Part B — Injection candidate sites (only if GraphQL is used)**
>
> If GraphQL is **not** used, omit the "Injection Candidate Sites" section or state there are none. Do not invent candidates.
>
> If GraphQL **is** used, search for **unsafe document construction**:
>
> 1. **String concatenation / interpolation into operation text**:
>    - `` `query { ... ${x} ...}` ``, `"mutation { " + userFragment + " }"`
>    - `sprintf`, `format`, `%` formatting, `.format()` building `query` or `source` arguments
>
> 2. **Calls where the document argument is not a compile-time constant**:
>    - `graphql(schema, dynamicString, ...)`, `execute({ schema, document: parsedDynamic, ...})` where the string feeding `parse` or `execute` is built from non-static parts
>    - `graphqlHTTP({ schema, rootValue, context: (req) => ({ query: req.body.query + something }) })` patterns that **mutate** or **wrap** the query string with user data
>
> 3. **HTTP clients forwarding a constructed GraphQL body**:
>    - `JSON.stringify({ query: `...${userPart}...` })`, `axios.post(url, { query: builtFromInput })`
>
> 4. **Unsafe persisted / stored query lookup**:
>    - Operation text loaded by key from user input without allowlist → file path or DB value becomes document source
>
> **What to skip** (do not flag as Phase 1 candidates):
> - Fully static `source` / `query` strings; only `variableValues` / `variables` come from the request
> - Schema definition with `buildSchema` / SDL files with no user interpolation
> - Resolver implementations that only use args with parameterized DB APIs (optional: note "resolver uses ORM" but not a GraphQL injection candidate unless the **document** is built unsafely)
>
> **Output format** — write to `sast/graphql-recon.md`:
>
> ```markdown
> # GraphQL Recon: [Project Name]
>
> ## Summary
> GraphQL is [used / not used] in this codebase.
> [If used: libraries, main server files, typical endpoint paths]
> Found [N] injection candidate site(s) where operation documents may be built unsafely. [If not used, say N/A or 0 and skip candidate list]
>
> ## GraphQL Surface (only if used)
> - **Libraries / frameworks**: ...
> - **Entry points**: ...
> - **Notable files**: ...
>
> ## Injection Candidate Sites
>
> ### 1. [Descriptive name]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: ...
> - **Execution / call pattern**: [graphql.execute / fetch with body / gql template / etc.]
> - **Construction pattern**: [concat / template literal / format / forwarded body mutation]
> - **Interpolated variable(s)**: ...
> - **Code snippet**:
>   ```
>   ...
>   ```
>
> [Repeat for each site; if none, write "No injection candidate sites found." under the heading]
> ```

### After Phase 1: Gates Before Phase 2

After Phase 1 completes, read `sast/graphql-recon.md`.

**Gate 1 — No GraphQL technology**

If the summary states GraphQL is **not used** (or equivalent: no GraphQL libraries, no schema, no server — clear absence), **skip Phases 2 and 3**. Write the following to `sast/graphql-results.md` and stop:

```markdown
# GraphQL Injection Analysis Results

No GraphQL technology detected in this codebase.
```

**Gate 2 — GraphQL used but no injection candidates**

If GraphQL **is** used but there are **zero** injection candidate sites (summary reports 0 candidates, or the "Injection Candidate Sites" section states none found / is empty), **skip Phases 2 and 3**. Write the following to `sast/graphql-results.md` and stop:

```markdown
# GraphQL Injection Analysis Results

No vulnerabilities found.
```

**Otherwise** proceed to Phase 2.

### Phase 2: Trace User Input to Injection Candidate Sites (Batched)

After Phase 1 completes and both gates pass (GraphQL used and at least one candidate site), read `sast/graphql-recon.md` and split the **Injection Candidate Sites** into **batches of up to 3 sites each** (each `### N.` section is one site). Process each batch **sequentially**. For each batch, trace taint only for the assigned sites and write results to the batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/graphql-recon.md` and count the numbered candidate sections under "Injection Candidate Sites" (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Process each batch sequentially, working through each one only its assigned candidate sections (plus architecture context).
5. Write results to `sast/graphql-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Node.js, include the "Node.js — dynamic document for downstream API" example; if Python, include "Python — string format into execute". Include these selected examples for the current batch where indicated by `[TECH-STACK EXAMPLES]` below.

For each batch, apply the following analysis directly (substitute the batch-specific values):

> **Goal**: For each assigned injection candidate site, determine whether user-supplied data can reach the dynamic part of the operation document. Our goal is to find GraphQL injection vulnerabilities. Write results to `sast/graphql-batch-[N].md`.
>
> **Step 0 — Cross-reference with route call graph (Node.js / Next.js projects)**:
> If `sast/nodejs-routes.md` exists, do the following BEFORE any backward tracing:
> 1. Search the file for each assigned candidate's file path or resolver function name.
> 2. If found with 🔴 user-tainted → confirmed user-controlled input reaches this resolver. Use the call chain as the taint trace; classify directly.
> 3. If found but marked 🟡 unknown → use the call tree as your starting map, then continue backward tracing to resolve.
> 4. If NOT found → perform the full backward tracing described below.
> **Next.js**: GraphQL endpoints in Next.js are typically `route.ts` handlers at `/api/graphql` — `request.json()` carries the operation and variables, both fully user-controlled. Route group folders do NOT appear in URLs.
>
> **Minimum trace depth**: Never conclude a value is server-side only after fewer than 5 function hops. Document every hop with arrow notation.
>
> **Your assigned candidate sites** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it for API layout, request handling, and BFF/gateway patterns.
>
> **GraphQL injection reference — What to look for**:
>
> User-controlled data must not alter the **GraphQL document text** (query/mutation/subscription source) except through bound **variables** on a static document. Flag when taint reaches string assembly of the operation.
>
> **What GraphQL injection is NOT** — do not flag these here:
> - **SQL/NoSQL injection in resolvers** — other SAST skills
> - **IDOR with static document + variables** — authorization, not document injection
> - **Normal variable binding** on a fixed document string
> - **Introspection enabled** — unless the finding is specifically operation-string injection
> - **Query depth/complexity DoS** — different class
>
> **Mitigations that reduce risk**:
> - Allowlist of fields or operation IDs before any string assembly
> - Parser validation that rejects unexpected definitions (still prefer no user-controlled document structure)
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned site, trace dynamic values backward**:
>
> 1. **Direct user input** — query params, path params, JSON body fields (including nested `query` if re-wrapped), headers, cookies
> 2. **Indirect user input** — helpers, middleware, context builders
> 3. **Second-order** — stored preferences or DB fields later used to build a document; trace write path
> 4. **Server-only** — config, env, hardcoded fragments — not exploitable from the client
>
> **Classification**:
> - **Vulnerable**: User-controlled data reaches document construction with no effective mitigation
> - **Likely Vulnerable**: Probable taint or weak sanitization
> - **Not Vulnerable**: Server-side-only or effective allowlist / static document path
> - **Needs Manual Review**: Opaque flow
>
> **Output format** — write to `sast/graphql-batch-[N].md`:
>
> ```markdown
> # GraphQL Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: ...
> - **Issue**: ...
> - **Taint trace**: ...
> - **Impact**: [e.g., unauthorized fields, gateway bypass, SSRF-style behavior to internal GraphQL]
> - **Remediation**: [static operations; variables only; persisted query allowlist]
> - **Dynamic Test**:
>   ```
>   [curl or in-browser GraphQL request showing injected fragment/directive/field]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: ...
> - **Endpoint / function**: ...
> - **Issue**: ...
> - **Taint trace**: ...
> - **Concern**: ...
> - **Remediation**: ...
> - **Dynamic Test**:
>   ```
>   ...
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: ...
> - **Endpoint / function**: ...
> - **Reason**: ...
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: ...
> - **Endpoint / function**: ...
> - **Uncertainty**: ...
> - **Suggestion**: ...
> ```

### Phase 3: Merge — Consolidate Batch Results

After completing all batches in Phase 2, read every `sast/graphql-batch-*.md` file and merge them into a single `sast/graphql-results.md`. Do this directly in your current context.

**Merge procedure**:

1. Read all `sast/graphql-batch-1.md`, `sast/graphql-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/graphql-results.md` using this format:

```markdown
# GraphQL Injection Analysis Results: [Project Name]

## Executive Summary
- Candidate sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/graphql-results.md`, **delete all intermediate batch files** (`sast/graphql-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and keep it in context throughout.
- **If Phase 1 finds no GraphQL technology, skip Phases 2 and 3** — write the "No GraphQL technology detected" results file.
- **If GraphQL is used but Phase 1 finds no injection candidates, skip Phases 2 and 3** — write "No vulnerabilities found."
- Phase 2 must run **after** Phase 1 completes — it depends on the recon output.
- Phase 3 must run **after** all Phase 2 batches complete — it depends on all batch outputs.
- Process batches of up to **3 candidate sites each** sequentially. If there are 1-3 sites total, treat it as a single batch.
- Process all batches sequentially — write results to batch files as you complete each one.
- For each batch, work only from the assigned candidates' text from the recon file, not the entire file. This keeps each batch focused.
- Phase 1 does **not** trace taint; Phase 2 does.
- Resolver-layer SQL/NoSQL issues belong to other skills; this skill targets **operation document** construction.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable".
- Clean up intermediate files: delete `sast/graphql-recon.md` and all `sast/graphql-batch-*.md` files after the final `sast/graphql-results.md` is written.
