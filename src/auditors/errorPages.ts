import {
  ScanContext, AuditResult, Finding,
} from '../types';
import { getFileContent } from '../utils/fileWalker';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py']);

// ── Helpers ──────────────────────────────────────────────────────────────────

function hasFile(ctx: ScanContext, patterns: RegExp[]): string | null {
  for (const entry of ctx.files) {
    const norm = entry.relativePath.replace(/\\/g, '/');
    if (patterns.some(p => p.test(norm))) return entry.relativePath;
  }
  return null;
}

// ── Check: custom 404 page / handler ─────────────────────────────────────────

async function check404(ctx: ScanContext): Promise<Finding[]> {
  // ① Static HTML / public files
  const static404 = hasFile(ctx, [
    /(?:^|\/)404\.(html?|tsx?|jsx?)$/i,
    /(?:^|\/)not[-_]found\.(html?|tsx?|jsx?)$/i,
  ]);
  if (static404) return [];

  // ② Next.js App Router convention
  const nextNotFound = hasFile(ctx, [
    /(?:^|\/)app\/not-found\.[tj]sx?$/,
    /(?:^|\/)pages\/404\.[tj]sx?$/,
  ]);
  if (nextNotFound) return [];

  // ③ React Router catch-all  <Route path="*"  or  path="/*"
  for (const entry of ctx.files) {
    if (!['.tsx', '.jsx', '.ts', '.js'].includes(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (/path\s*=\s*["'`]\*["'`]/.test(content) ||
        /path\s*=\s*["'`]\/\*["'`]/.test(content) ||
        /<Route[^>]*path\s*=\s*["'`]\*/.test(content)) {
      return [];
    }
  }

  // ④ Express catch-all / 404 middleware
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    // app.use((req, res) => res.status(404)...) or res.sendStatus(404)
    if (/(?:res\.status|res\.sendStatus)\s*\(\s*404\s*\)/.test(content)) return [];
    // app.use('*', ...) catch-all at end of routes
    if (/(?:app|router)\.use\s*\(\s*['"`]\*['"`]/.test(content)) return [];
    // app.all('*', ...) wildcard
    if (/(?:app|router)\.all\s*\(\s*['"`]\*['"`]/.test(content)) return [];
  }

  // ⑤ Flask / FastAPI error handlers
  for (const entry of ctx.files) {
    if (entry.extension !== '.py') continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (/@app\.errorhandler\s*\(\s*404\s*\)/.test(content)) return [];
    if (/@app\.errorhandler\s*\(\s*HTTPException\s*\)/.test(content)) return [];
    if (/exception_handler\s*\(.*404/.test(content)) return [];
    if (/add_exception_handler\s*\(/.test(content)) return [];
  }

  return [{
    id: 'ERR-001',
    severity: 'MEDIUM',
    module: 'error-pages',
    title: 'No custom 404 (Not Found) page or handler detected',
    description: 'When users visit a broken link or mistype a URL, they see a raw framework error page that reveals your tech stack (e.g. "Cannot GET /path — Express", Django yellow debug page, or a blank browser 404). This looks unprofessional, leaks implementation details, and gives attackers free reconnaissance about your server.',
    remediation:
      'Express: add app.use((req,res) => res.status(404).send("Page not found")) after all routes.\n' +
      'Next.js: create pages/404.tsx or app/not-found.tsx.\n' +
      'React Router: add <Route path="*" element={<NotFound />} />.\n' +
      'Flask: add @app.errorhandler(404) def not_found(e): return render_template("404.html"), 404\n' +
      'Static sites: add a 404.html to your public root.',
    autoFixable: true,
    fixId: 'create-404-page',
  }];
}

// ── Check: custom 500 / error handler ────────────────────────────────────────

async function check500(ctx: ScanContext): Promise<Finding[]> {
  // ① Static 500 page
  const static500 = hasFile(ctx, [
    /(?:^|\/)500\.(html?|tsx?|jsx?)$/i,
    /(?:^|\/)error\.(html?|tsx?|jsx?)$/i,
  ]);
  if (static500) return [];

  // ② Next.js conventions
  const next500 = hasFile(ctx, [
    /(?:^|\/)pages\/500\.[tj]sx?$/,
    /(?:^|\/)app\/error\.[tj]sx?$/,
    /(?:^|\/)app\/global-error\.[tj]sx?$/,
  ]);
  if (next500) return [];

  // ③ Express 4-argument error middleware: (err, req, res, next)
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    // Must have 4 parameters — that's what makes it an error handler in Express
    if (/(?:app|router)\.use\s*\(\s*(?:['"`][^'"]*['"`]\s*,\s*)?\s*(?:async\s*)?\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/.test(content)) return [];
    // Also check for standalone error handler function pattern
    if (/function\s+\w+\s*\(\s*err\b[^)]*,\s*req\b[^)]*,\s*res\b[^)]*,\s*next\b/.test(content)) return [];
    if (/\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)\s*(?:=>|\{)/.test(content)) return [];
  }

  // ④ Flask / FastAPI
  for (const entry of ctx.files) {
    if (entry.extension !== '.py') continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (/@app\.errorhandler\s*\(\s*500\s*\)/.test(content)) return [];
    if (/@app\.errorhandler\s*\(\s*Exception\s*\)/.test(content)) return [];
    if (/exception_handler\s*\(.*(?:500|Exception|ServerError)/.test(content)) return [];
  }

  return [{
    id: 'ERR-002',
    severity: 'MEDIUM',
    module: 'error-pages',
    title: 'No custom 500 (Server Error) handler detected',
    description: 'When your server crashes, unhandled exceptions produce raw stack traces visible to users. This exposes file paths, dependency names, line numbers, and internal logic — a roadmap for attackers. It also produces a terrible user experience with no recovery path.',
    remediation:
      'Express: add app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "Something went wrong" }); }) as your last middleware.\n' +
      'Next.js: create pages/500.tsx or app/error.tsx (and app/global-error.tsx for the root layout).\n' +
      'Flask: @app.errorhandler(500) def server_error(e): return render_template("500.html"), 500\n' +
      'FastAPI: @app.exception_handler(Exception) async def unhandled(req, exc): return JSONResponse(status_code=500, content={"error": "Internal server error"})',
    autoFixable: true,
    fixId: 'create-500-handler',
  }];
}

// ── Check: missing 403 handler ────────────────────────────────────────────────

async function check403(ctx: ScanContext): Promise<Finding[]> {
  // Only flag if the project has auth middleware (403 is only relevant when
  // you actively restrict access to routes).
  let hasAuthMiddleware = false;
  let has403Handler = false;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    if (/(?:authenticate|authorize|requireAuth|isAuthenticated|isAdmin|verifyToken|authMiddleware|permission_required)/i.test(content)) {
      hasAuthMiddleware = true;
    }
    if (/(?:res\.status|res\.sendStatus)\s*\(\s*403\s*\)/.test(content) ||
        /@app\.errorhandler\s*\(\s*403\s*\)/.test(content) ||
        /exception_handler\s*\(.*403/.test(content) ||
        /403\.(html?|tsx?|jsx?)/.test(entry.relativePath)) {
      has403Handler = true;
    }
  }

  if (!hasAuthMiddleware || has403Handler) return [];

  return [{
    id: 'ERR-003',
    severity: 'LOW',
    module: 'error-pages',
    title: 'No custom 403 (Forbidden) response — auth middleware found but no 403 handler',
    description: 'Auth middleware is present but no custom 403 handler was detected. When authorisation fails, users see a generic "Forbidden" response with no explanation or navigation path back, making the app feel broken.',
    remediation:
      'Express: in your auth middleware, send res.status(403).json({ error: "You do not have permission to access this resource" }).\n' +
      'Flask: @app.errorhandler(403) def forbidden(e): return render_template("403.html"), 403\n' +
      'FastAPI: @app.exception_handler(403) or raise HTTPException(status_code=403, detail="Forbidden")',
    autoFixable: false,
  }];
}

// ── Check: missing 429 page ────────────────────────────────────────────────────

async function check429(ctx: ScanContext): Promise<Finding[]> {
  let hasRateLimit = false;
  let has429Response = false;

  const RATE_LIMIT_LIBS = [
    'express-rate-limit', 'slowapi', 'flask-limiter', 'fastapi-limiter',
    'django-ratelimit', '@nestjs/throttler',
  ];

  for (const entry of ctx.files) {
    const content = await getFileContent(entry, ctx.contentCache);

    if (RATE_LIMIT_LIBS.some(lib => content.includes(lib))) hasRateLimit = true;
    if (/(?:res\.status|res\.sendStatus)\s*\(\s*429\s*\)/.test(content) ||
        /status_code\s*=\s*429/.test(content) ||
        /429\.html/.test(entry.relativePath) ||
        /RateLimitExceeded/.test(content)) {
      has429Response = true;
    }
  }

  if (!hasRateLimit || has429Response) return [];

  return [{
    id: 'ERR-004',
    severity: 'LOW',
    module: 'error-pages',
    title: 'Rate limiting present but no custom 429 (Too Many Requests) message',
    description: 'Rate limiting middleware is configured but no custom 429 response message was found. The default response is often a plain "Too Many Requests" string with no context about when the user can retry, which is confusing and unhelpful.',
    remediation:
      'Express rate-limit: set the message option — { message: { error: "Too many requests. Please wait 15 minutes before trying again." } }.\n' +
      'Slowapi/Flask-Limiter: add a custom error handler for RateLimitExceeded.\n' +
      'Always include a Retry-After header with the seconds until the limit resets.',
    autoFixable: false,
  }];
}

// ── Check: unhandled promise rejections / uncaught exceptions ─────────────────

async function checkUncaughtHandlers(ctx: ScanContext): Promise<Finding[]> {
  if (ctx.projectType === 'python') return [];

  // Look for the process-level safety nets in Node entry files
  const entryPatterns = [
    /^(?:src\/)?(?:index|server|app|main)\.[tj]s$/,
  ];
  let hasEntryFile = false;
  let hasUncaughtHandler = false;
  let hasUnhandledHandler = false;

  for (const entry of ctx.files) {
    const isEntry = entryPatterns.some(p => p.test(entry.relativePath));
    if (!isEntry && !entry.relativePath.includes('server') && !entry.relativePath.includes('index')) continue;
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    if (/\bexpress\b/.test(content) || /\bcreateServer\b/.test(content)) {
      hasEntryFile = true;
    }
    if (/process\.on\s*\(\s*['"`]uncaughtException['"`]/.test(content)) hasUncaughtHandler = true;
    if (/process\.on\s*\(\s*['"`]unhandledRejection['"`]/.test(content)) hasUnhandledHandler = true;
  }

  if (!hasEntryFile) return [];

  const findings: Finding[] = [];

  if (!hasUncaughtHandler) {
    findings.push({
      id: 'ERR-005',
      severity: 'MEDIUM',
      module: 'error-pages',
      title: 'No process.on("uncaughtException") handler in Node server',
      description: 'Without a global uncaughtException handler, any unhandled synchronous exception will crash the entire Node process — taking down all active connections with a raw stack trace potentially logged to stdout where users or logs may capture it.',
      remediation:
        'Add to your entry file:\n' +
        'process.on("uncaughtException", (err) => {\n' +
        '  console.error("Uncaught Exception:", err);\n' +
        '  // Gracefully shut down, then exit\n' +
        '  server.close(() => process.exit(1));\n' +
        '});',
      autoFixable: false,
    });
  }

  if (!hasUnhandledHandler) {
    findings.push({
      id: 'ERR-006',
      severity: 'MEDIUM',
      module: 'error-pages',
      title: 'No process.on("unhandledRejection") handler in Node server',
      description: 'Unhandled promise rejections will crash Node.js (v15+) or silently swallow errors (v14 and below). Either way you lose error visibility and risk bringing down the server.',
      remediation:
        'Add to your entry file:\n' +
        'process.on("unhandledRejection", (reason) => {\n' +
        '  console.error("Unhandled Rejection:", reason);\n' +
        '  server.close(() => process.exit(1));\n' +
        '});',
      autoFixable: false,
    });
  }

  return findings;
}

// ── Orchestrate ───────────────────────────────────────────────────────────────

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();
  const [f404, f500, f403, f429, uncaught] = await Promise.all([
    check404(ctx),
    check500(ctx),
    check403(ctx),
    check429(ctx),
    checkUncaughtHandlers(ctx),
  ]);

  return {
    module: 'error-pages',
    findings: [...f404, ...f500, ...f403, ...f429, ...uncaught],
    duration: Date.now() - start,
  };
}
