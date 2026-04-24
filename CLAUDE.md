# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current directory.

---

## Step 1: Codebase Analysis & Architecture Mapping

Before running, check if `sast/architecture.md` already exists. If it does, skip this step.

Run the `sast-analysis` skill directly (this one stays in-session since later steps depend on reading its output).

**Wait for this step to finish before proceeding.**

---

## Step 1b: Node.js Route Call Graph (Node.js projects only)

Check if the project uses Node.js (look at `sast/architecture.md` — if the Languages or Frameworks row mentions Node.js, Express, NestJS, Fastify, Koa, Hapi, Next.js, Nuxt, Remix, or any JavaScript/TypeScript backend or full-stack framework).

- **If Node.js is detected** and `sast/nodejs-routes.md` does not already exist: run `sast-nodejs-routes` in-session now. This enumerates every API route and builds a full recursive call graph for each handler. Later skills will use this as additional context.
- **If not a Node.js project**, or if `sast/nodejs-routes.md` already exists: skip this step.

**Wait for this step to finish before proceeding to Step 2.**

---

## Step 2: Vulnerability Detection (Sequential)

Run each skill one at a time in your current context — do NOT spawn subagents. Skip any skill where the output file already exists.

- Skip IDOR if `sast/idor-results.md` already exists.
- Skip SQLi if `sast/sqli-results.md` already exists.
- Skip SSRF if `sast/ssrf-results.md` already exists.
- Skip XSS if `sast/xss-results.md` already exists.
- Skip RCE if `sast/rce-results.md` already exists.
- Skip XXE if `sast/xxe-results.md` already exists.
- Skip File Upload if `sast/fileupload-results.md` already exists.
- Skip Path Traversal if `sast/pathtraversal-results.md` already exists.
- Skip SSTI if `sast/ssti-results.md` already exists.
- Skip JWT if `sast/jwt-results.md` already exists.
- Skip Missing Auth if `sast/missingauth-results.md` already exists.
- Skip Business Logic if `sast/businesslogic-results.md` already exists.
- Skip GraphQL injection if `sast/graphql-results.md` already exists.
- Skip Hardcoded Secrets if `sast/hardcodedsecrets-results.md` already exists.
- Skip Node.js if `sast/nodejs-results.md` already exists.

Before running each skill: read `sast/architecture.md`. If `sast/nodejs-routes.md` exists, also read it — then follow this process during each skill's Phase 2: (1) Search `sast/nodejs-routes.md` for each sink's file path or function name. (2) If the sink appears in a route's call tree marked 🔴 user-tainted, use that call chain as taint evidence directly without re-tracing. (3) If marked 🟡 unknown, use the call tree as a starting map. (4) Only re-trace from scratch for sinks not found in the call graph. This is mandatory for Next.js projects — route group folders like `(dashboard)` do NOT appear in URLs, and the call graph already resolves these mappings.

Run each skill in sequence using the table below. Write all findings to the results file. Clean up any intermediate files when done.

| Skill | Results file | Intermediate files to clean |
|-------|----------------|--------------------------------------|
| sast-idor | `sast/idor-results.md` | `sast/idor-recon.md` |
| sast-sqli | `sast/sqli-results.md` | `sast/sqli-recon.md`, `sast/sqli-batch-*.md` |
| sast-ssrf | `sast/ssrf-results.md` | `sast/ssrf-recon.md` |
| sast-xss | `sast/xss-results.md` | `sast/xss-recon.md` |
| sast-rce | `sast/rce-results.md` | `sast/rce-recon.md`, `sast/rce-batch-*.md` |
| sast-xxe | `sast/xxe-results.md` | `sast/xxe-recon.md` |
| sast-fileupload | `sast/fileupload-results.md` | `sast/fileupload-recon.md`, `sast/fileupload-batch-*.md` |
| sast-pathtraversal | `sast/pathtraversal-results.md` | `sast/pathtraversal-recon.md`, `sast/pathtraversal-batch-*.md` |
| sast-ssti | `sast/ssti-results.md` | `sast/ssti-recon.md` |
| sast-jwt | `sast/jwt-results.md` | `sast/jwt-recon.md` |
| sast-missingauth | `sast/missingauth-results.md` | `sast/missingauth-recon.md`, `sast/missingauth-batch-*.md` |
| sast-businesslogic | `sast/businesslogic-results.md` | `sast/businesslogic-threats.md`, `sast/businesslogic-batch-*.md` |
| sast-graphql | `sast/graphql-results.md` | `sast/graphql-recon.md` |
| sast-hardcodedsecrets | `sast/hardcodedsecrets-results.md` | `sast/hardcodedsecrets-recon.md`, `sast/hardcodedsecrets-batch-*.md` |
| sast-nodejs | `sast/nodejs-results.md` | `sast/nodejs-recon.md`, `sast/nodejs-batch-*.md` |

Complete all skills before proceeding to Step 3.

---

## Step 3: Report Generation

After all skills in Step 2 complete, generate the final consolidated report.

Skip this step if `sast/final-report.md` already exists.

Read all available `sast/*-results.md` files, `sast/architecture.md`, and (if it exists) `sast/nodejs-routes.md` for context, then run the `sast-report` skill directly in your current context to generate `sast/final-report.md` with all findings ranked by severity and confidentiality impact.
