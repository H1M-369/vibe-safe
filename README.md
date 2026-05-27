# 🛡 vibe-safe

**Security audit & active probe tool for AI-generated ("vibe-coded") web applications.**

AI coding tools ship working apps in minutes — but they consistently skip the same security fundamentals: no authentication on routes, hardcoded secrets, SQL injection, no rate limiting, missing legal pages, weak password hashing. vibe-safe catches all of it automatically, explains every issue in plain English, and can fix the safe ones for you.

---

## The Problem It Solves

When developers use AI to generate web apps quickly ("vibe coding"), the generated code almost always has the same class of vulnerabilities:

- Secrets and API keys hardcoded directly in source files
- Database queries built from raw user input (SQL injection)
- No rate limiting — bots can hammer your API and drain paid quotas
- No security headers — browsers have zero protection against XSS or clickjacking
- JWT tokens with weak secrets or no expiry
- Routes that let User A read, update, or delete User B's data (IDOR)
- Missing legal pages (privacy policy, terms of service) that are legally required
- Passwords hashed with MD5 instead of bcrypt
- Admin endpoints with no role checks

vibe-safe scans any project directory in seconds and produces a prioritised, actionable report of every issue it finds — without ever needing a running server.

---

## What It Does

vibe-safe operates in two modes that work independently or together:

### Mode 1 — Static Scan (default, offline)
Analyses your source code without running anything. Reads every file in the project directory, applies 60+ detection rules across 7 security modules, and produces a severity-ranked list of findings with file locations, code snippets, and remediation steps.

### Mode 2 — Active Probe (`--probe <url>`)
Sends real attack payloads to a running application to confirm whether vulnerabilities are actually exploitable — not just flagged in code. Tests SQL injection, XSS reflection, missing security headers, rate limiting, authentication bypass, and exposed sensitive endpoints.

> **Active probing requires written authorization.** The tool presents a legal warning and requires you to type `I AGREE` before sending any request. Unauthorized probing is illegal under CFAA, Computer Misuse Act, and equivalent laws.

---

## Installation

```bash
git clone <repo>
cd tool
npm install
npm run build
```

Run directly:
```bash
node dist/cli.js [path]
```

Or link globally:
```bash
npm link
vibe-safe [path]
```

---

## Usage

### Scan a project
```bash
# Scan the current directory
vibe-safe .

# Scan a specific project
vibe-safe /path/to/your/project

# Scan and export a PDF report
vibe-safe . --pdf

# Scan and auto-fix detected issues
vibe-safe . --fix

# Scan and output raw JSON (for CI pipelines)
vibe-safe . --json
```

### Active probing
```bash
# Scan code + send real attack payloads to a running app
vibe-safe . --probe http://localhost:3000

# Probe a deployed app (requires written authorization)
vibe-safe . --probe https://staging.myapp.com
```

### Web dashboard
```bash
# Launch the interactive web UI at http://localhost:4000
vibe-safe --ui
```

### Filter and output options
```bash
# Only run specific modules
vibe-safe . --only security,secrets,auth

# Only show CRITICAL and HIGH findings (suppress MEDIUM/LOW)
vibe-safe . --severity HIGH

# Write report to a custom path
vibe-safe . --output /reports/audit.md

# Export PDF to a custom path
vibe-safe . --pdf /reports/audit.pdf
```

---

## All Flags

| Flag | Description | Default |
|---|---|---|
| `[path]` | Project directory to scan | Current directory |
| `--fix` | Apply safe auto-fixes for detected issues | off |
| `--probe <url>` | Send real attack payloads to a running app | off |
| `--only <modules>` | Comma-separated list of modules to run | all |
| `--severity <level>` | Minimum severity to display: `CRITICAL\|HIGH\|MEDIUM\|LOW` | `LOW` |
| `--output <file>` | Markdown report output path | `vibe-safe-report.md` |
| `--pdf [file]` | Export a PDF report | `vibe-safe-report.pdf` |
| `--json` | Print raw JSON scan result to stdout | off |
| `--ui` | Launch the web dashboard at http://localhost:4000 | off |

---

## Security Modules

vibe-safe runs 7 static analysis modules in parallel. Every finding includes an ID, severity, file location, code snippet, and remediation steps.

---

### 🔐 Authentication & Authorization (`auth`)

The most critical module — catches the vulnerabilities that let attackers impersonate users, escalate privileges, or access other users' data.

| ID | Severity | What It Catches |
|---|---|---|
| AUTH-001 | CRITICAL/HIGH | Weak password hashing — MD5, SHA-1 used on passwords, or no hashing library present |
| AUTH-002 | CRITICAL | Hardcoded credentials — `password: "admin"`, `ADMIN_PASSWORD = "secret"` in source |
| AUTH-003 | CRITICAL | JWT signed with weak/guessable secret (`"secret"`, `"changeme"`, `"mysecret"`) |
| AUTH-004 | HIGH | JWT tokens with no `expiresIn` — valid forever if stolen |
| AUTH-005 | HIGH | Admin routes (`/admin`, `/dashboard`, `/manage`) with no role or permission check |
| AUTH-006 | HIGH | Mass assignment — `...req.body` or `Object.assign(user, req.body)` passed to DB |
| AUTH-007 | HIGH | Session cookies missing `httpOnly`, `secure`, or `sameSite` flags |
| AUTH-008 | MEDIUM | Registration route with no password minimum length or complexity check |
| AUTH-009 | MEDIUM | Account enumeration — distinct "User not found" vs "Wrong password" error messages |
| AUTH-010 | MEDIUM | JWT logout route with no token blacklist or revocation mechanism |
| AUTH-011 | HIGH | Password reset token generated with `Math.random()` instead of `crypto.randomBytes()` |
| AUTH-012 | MEDIUM | Open redirect after login — `res.redirect(req.query.returnUrl)` unvalidated |
| AUTH-013 | HIGH | **IDOR** — `findById(req.params.id)` or DB mutations with user-supplied IDs and no ownership check |
| AUTH-014 | HIGH | DELETE, PUT, or PATCH routes with no authentication middleware |
| AUTH-015 | HIGH | Unguarded data listing — `User.find({})`, `findAll()`, `findMany()` without user filter |
| AUTH-016 | HIGH | GET routes with user-specific path params (`:userId`, `:profileId`) and no auth middleware |

---

### 🔒 Security Basics (`security`)

Core OWASP Top 10 issues that appear in almost every AI-generated backend.

| ID | Severity | What It Catches |
|---|---|---|
| SEC-001–003 | CRITICAL | SQL injection via template literals — `` `SELECT * FROM users WHERE id = ${req.body.id}` `` |
| SEC-004 | CRITICAL | `dangerouslySetInnerHTML` usage in React — XSS risk |
| SEC-005 | HIGH | `eval()` calls in production code |
| SEC-006 | HIGH | POST routes with no CSRF protection library |
| SEC-007 | MEDIUM | No HTTP security headers (helmet for Express, headers() in Next.js config) |

---

### 🗝 Secrets & Keys (`secrets`)

Catches credentials and tokens that should never be in source code.

| ID | Severity | What It Catches |
|---|---|---|
| SCR-001–009 | CRITICAL | Hardcoded API keys — Stripe `sk-`, GitHub `ghp_`, Google `AIza`, OpenAI, etc. |
| SCR-010 | HIGH | `.env` file not in `.gitignore` |
| SCR-011 | CRITICAL | `.env` committed to git history — secrets permanently exposed |
| SCR-012 | CRITICAL | Secrets in `public/`, `static/`, or `dist/` — served to all users |
| SCR-013 | HIGH | API response returning `password`, `token`, `hash`, or `secret` fields |

---

### 🚫 Abuse Prevention (`abuse`)

Protections against bots, scrapers, and cost-abuse of third-party APIs.

| ID | Severity | What It Catches |
|---|---|---|
| ABUSE-001 | HIGH | No rate limiting library (`express-rate-limit`, `slowapi`, `flask-limiter`) |
| ABUSE-002 | HIGH | No input validation library (`zod`, `yup`, `joi`, `pydantic`) |
| ABUSE-003 | LOW | Auth routes (login, register, password reset) with no CAPTCHA |
| ABUSE-004 | MEDIUM | OpenAI API calls without `max_tokens` — unbounded cost exposure |

---

### 📋 Legal & Privacy (`legal`)

Compliance checks required for any app that collects user data.

| ID | Severity | What It Catches |
|---|---|---|
| LEGAL-001 | MEDIUM | No privacy policy page or route |
| LEGAL-002 | MEDIUM | No terms of service page or route |
| LEGAL-003 | HIGH | PII collected (email, phone, address) with no privacy policy |
| LEGAL-004 | LOW | Cookies set with no consent mechanism |

---

### ⚙️ Environment & Config (`environment`)

Prevents debug settings and secrets leaking into production.

| ID | Severity | What It Catches |
|---|---|---|
| ENV-001 | MEDIUM | `.env` exists but no `.env.example` for other developers |
| ENV-002 | MEDIUM | Production scripts without `NODE_ENV` set |
| ENV-003 | LOW | `DEBUG=true` left in config files |
| ENV-004 | MEDIUM | `console.log` statements printing passwords, tokens, or secrets |

---

### 📄 Error Pages (`error-pages`)

Missing error handlers expose stack traces and framework internals to attackers.

| ID | Severity | What It Catches |
|---|---|---|
| ERR-001 | MEDIUM | No 404 handler (Next.js `not-found.tsx`, Express catch-all, Flask `@errorhandler(404)`) |
| ERR-002 | MEDIUM | No 500 error handler — unhandled exceptions crash with a stack trace |
| ERR-003 | LOW | Auth middleware present but no custom 403 response |
| ERR-004 | LOW | Rate limiting present but no custom 429 response |
| ERR-005/006 | MEDIUM | No `process.on('uncaughtException')` or `process.on('unhandledRejection')` handler |

---

## Active Probe Modules

When `--probe <url>` is used (with authorization), vibe-safe sends real payloads to a running application and reports only confirmed, exploitable vulnerabilities.

| Module | What It Does |
|---|---|
| **SQL Injection** | Sends `' OR 1=1 --` and similar payloads; confirms by detecting DB error strings in response |
| **XSS** | Sends `<script>alert(1)</script>` payloads; confirms if reflected verbatim (not HTML-encoded) |
| **Security Headers** | Makes a single GET request; checks which security headers are absent from the response |
| **Rate Limiting** | Sends 50 rapid requests to the same endpoint; confirms no limiting if all return 200 |
| **Auth Bypass** | Tests protected endpoints with no token, expired JWT, and `alg: none` JWT |
| **Sensitive Endpoints** | Probes `/.env`, `/.git/config`, `/api/users`, `/admin`, `/swagger`, and 20+ common paths |
| **Error Pages** | Requests a non-existent path; checks response for stack traces, framework fingerprints, and `X-Powered-By` headers |

---

## Auto-Fix System

Run with `--fix` (CLI) or click **⚡ Apply all auto-fixes** (dashboard) to automatically remediate safe, low-risk findings.

Every fix is **idempotent** (safe to run multiple times) and creates a `.vibe-safe.bak` backup of any modified file before changing it.

| Fix | What It Does | Files Touched |
|---|---|---|
| `add-env-gitignore` | Appends `.env`, `.env.local`, `.env.*.local` to `.gitignore` | `.gitignore` |
| `create-env-example` | Copies `.env`, strips values, writes `.env.example` | `.env.example` (new) |
| `add-helmet-express` | Adds `import helmet` + `app.use(helmet())` after Express init | `app.ts` / `server.ts` |
| `add-nextjs-headers` | Appends a security headers block to `next.config.js` | `next.config.js` |
| `add-rate-limit-boilerplate` | Creates a documented rate-limit setup file | `vibe-safe-suggestions/` |
| `add-validation-boilerplate` | Creates a Zod schema example file | `vibe-safe-suggestions/` |
| `create-privacy-policy` | Creates a `privacy-policy.md` template | project root |
| `create-terms-of-service` | Creates a `terms-of-service.md` template | project root |
| `fix-debug-true` | Replaces `DEBUG=true` with `DEBUG=false` in config files | relevant config file |
| `remove-sensitive-logs` | Comments out `console.log` lines leaking secrets | relevant source file |
| `create-404-page` | Creates framework-appropriate 404 handler (Next.js/Express/static) | framework-specific |
| `create-500-handler` | Creates framework-appropriate 500 error handler | framework-specific |

**Safety rules the fixer always follows:**
1. Never deletes code — only adds or comments out
2. Always backs up before modifying (`file.vibe-safe.bak`)
3. Never touches Python files, test files, `node_modules`, `dist`, or `.git`
4. One change per file per run maximum

---

## Report Outputs

### Terminal
Color-coded severity badges, per-finding details with file location and code snippet, summary table per module, and a final pass/fail banner.

```
╔══════════════════════════════════════╗
║          vibe-safe  v1.0.0           ║
║   Security audit for vibe-coded apps ║
╚══════════════════════════════════════╝

  Audit Summary
  Module               CRIT  HIGH   MED   LOW
  ────────────────────────────────────────────
  Auth & Authorization    2     4     1     0
  Security Basics         1     1     0     1
  Secrets & Keys          3     1     0     0
  ...

  ── Authentication & Authorization ──
  [ CRITICAL ] AUTH-002 — Hardcoded admin password in source
               File: src/routes/admin.ts:14
               > adminPassword: "admin123"
               Fix: Move to environment variables...
```

### Markdown Report
Written to `vibe-safe-report.md` (or `--output <path>`). Contains the full audit in a structured markdown format — summary table, per-module findings with code blocks, and probe results — suitable for committing to a repo or sharing with a team.

### PDF Report
Generated with `--pdf` (CLI) or the **⬇ Download PDF Report** button in the dashboard. A professionally formatted document with:

- Dark header with project metadata
- Four summary cards (CRITICAL / HIGH / MEDIUM / LOW counts)
- Per-module findings table
- Colour-coded severity badges per finding
- Code snippet blocks with file locations
- Active probe results (confirmed exploits only)
- Page footer with timestamp and page numbers

---

## Web Dashboard

```bash
vibe-safe --ui
# → http://localhost:4000
```

The dashboard provides a point-and-click interface for the full toolset:

- Enter any project path on your machine to scan it
- Optionally enter an active probe URL (with authorization checkbox)
- Real-time loading indicator during scanning
- Results grouped by module with expandable sections
- Colour-coded severity badges
- Per-finding **⚡ Fix** buttons for auto-fixable issues
- **⬇ Download PDF Report** button always visible after a scan
- **⚡ Apply all auto-fixes** bulk action

---

## CI/CD Integration

vibe-safe uses process exit codes so it integrates cleanly with any CI pipeline:

| Exit Code | Meaning |
|---|---|
| `0` | Clean — no CRITICAL or HIGH findings |
| `1` | CRITICAL or HIGH findings found — **block the deploy** |
| `2` | Tool error (bad path, permissions problem) |
| `3` | Active probe authorization declined — no requests were sent |

Example GitHub Actions step:
```yaml
- name: Security audit
  run: |
    npm run build
    node dist/cli.js . --severity HIGH --output security-report.md
  # Exits 1 and fails the build if any CRITICAL or HIGH issues found
```

---

## Supported Project Types

vibe-safe detects your project type automatically and adjusts its checks accordingly.

| Language / Framework | Detection Method |
|---|---|
| **Node.js / Express** | `package.json` + `express` dependency |
| **Next.js** | `next` dependency + `pages/` or `app/` directory structure |
| **NestJS** | `@nestjs/core` dependency |
| **Python / FastAPI** | `import fastapi` in source files |
| **Python / Flask** | `import flask` in source files |
| **React (frontend)** | `react` or `react-dom` dependency |
| **Mixed (Node + Python)** | Both `package.json` and `requirements.txt` present |

Framework detection influences which auto-fixes are applied (e.g. Next.js gets `next.config.js` headers, Express gets helmet).

---

## Project Structure

```
src/
  cli.ts                  Entry point — argument parsing, authorization gate
  scanner.ts              Orchestrates all static auditors
  prober.ts               Active probe orchestrator
  report.ts               Terminal output + markdown writer
  pdfReport.ts            PDF generation (pdfkit)
  fixer.ts                Auto-fix logic
  ui.ts                   Express web dashboard (port 4000)
  types.ts                Shared TypeScript interfaces
  auditors/
    auth.ts               Authentication & Authorization (16 checks)
    security.ts           Security Basics — SQLi, XSS, CSRF, headers
    secrets.ts            Secrets & Keys — API keys, .env, git history
    abuse.ts              Abuse Prevention — rate limiting, validation, CAPTCHA
    legal.ts              Legal & Privacy — ToS, privacy policy, GDPR
    environment.ts        Environment & Config — debug flags, NODE_ENV
    errorPages.ts         Error Pages — 404, 500, 403, 429 handlers
  probes/
    sqlInjection.ts       Live SQL injection testing
    xss.ts                Live XSS reflection testing
    headers.ts            Real HTTP security header check
    rateLimit.ts          Rate limit flood test
    authBypass.ts         JWT alg:none, expired token, missing token
    sensitiveEndpoints.ts /.env, /.git/config, /admin exposure
    errorPages.ts         Stack trace leakage via 404/500 responses
  utils/
    fileWalker.ts         Recursive file discovery with .gitignore support
    gitUtils.ts           Git history checks (simple-git)
    patternMatcher.ts     Shared regex patterns + scanContentForPatterns()
```

---

## Philosophy

- **No false negatives over false positives** — it's better to flag something safe than miss a real vulnerability
- **Every finding has a remediation** — not just "this is bad" but exactly how to fix it
- **Offline by default** — the static scan sends zero network requests
- **Authorization first** — active probing cannot proceed without explicit user confirmation
- **Non-destructive fixes** — the auto-fixer never deletes code, always backs up

---

*Built for the era of AI-generated code. Made to be run on every project before it ships.*
