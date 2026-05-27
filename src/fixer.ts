import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, ScanContext, FixResult, Finding } from './types';

type FixFn = (ctx: ScanContext, finding: Finding) => Promise<FixResult>;

function backup(filePath: string): void {
  if (fs.existsSync(filePath)) {
    fs.copyFileSync(filePath, `${filePath}.vibe-safe.bak`);
  }
}

function isIdempotent(content: string, marker: string): boolean {
  return content.includes(marker);
}

/** Ensures a resolved file path stays inside rootPath — prevents path traversal in fixes. */
function isWithinRoot(rootPath: string, filePath: string): boolean {
  const rel = path.relative(rootPath, filePath);
  return !rel.startsWith('..') && !path.isAbsolute(rel);
}

async function addEnvToGitignore(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const gitignorePath = path.join(ctx.rootPath, '.gitignore');
  const toAdd = '\n# Added by vibe-safe\n.env\n.env.local\n.env.*.local\n';

  try {
    let current = '';
    if (fs.existsSync(gitignorePath)) {
      current = fs.readFileSync(gitignorePath, 'utf-8');
    }
    if (isIdempotent(current, '.env')) {
      return { fixId: 'add-env-gitignore', applied: false, description: '.env already in .gitignore — skipped' };
    }
    backup(gitignorePath);
    fs.writeFileSync(gitignorePath, current + toAdd, 'utf-8');
    return { fixId: 'add-env-gitignore', applied: true, description: 'Added .env, .env.local, .env.*.local to .gitignore' };
  } catch (err) {
    return { fixId: 'add-env-gitignore', applied: false, description: 'Failed', error: String(err) };
  }
}

async function createEnvExample(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const envPath = path.join(ctx.rootPath, '.env');
  const examplePath = path.join(ctx.rootPath, '.env.example');

  if (fs.existsSync(examplePath)) {
    return { fixId: 'create-env-example', applied: false, description: '.env.example already exists — skipped' };
  }
  if (!fs.existsSync(envPath)) {
    return { fixId: 'create-env-example', applied: false, description: 'No .env file found to generate example from' };
  }

  try {
    const envContent = fs.readFileSync(envPath, 'utf-8');
    const exampleLines = envContent.split('\n').map(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith('#') || trimmed === '') return line;
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex === -1) return line;
      return trimmed.slice(0, eqIndex + 1);
    });
    fs.writeFileSync(examplePath, exampleLines.join('\n'), 'utf-8');
    return { fixId: 'create-env-example', applied: true, description: 'Created .env.example with keys but no values' };
  } catch (err) {
    return { fixId: 'create-env-example', applied: false, description: 'Failed', error: String(err) };
  }
}

async function addHelmetToExpress(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const candidates = ['app.ts', 'app.js', 'server.ts', 'server.js', 'index.ts', 'index.js'];
  let targetFile: string | null = null;

  for (const candidate of candidates) {
    const fullPath = path.join(ctx.rootPath, 'src', candidate);
    const rootPath = path.join(ctx.rootPath, candidate);
    if (fs.existsSync(fullPath)) { targetFile = fullPath; break; }
    if (fs.existsSync(rootPath)) { targetFile = rootPath; break; }
  }

  if (!targetFile) {
    return { fixId: 'add-helmet-express', applied: false, description: 'Could not locate Express app entry file (app.ts/server.ts)' };
  }

  try {
    const content = fs.readFileSync(targetFile, 'utf-8');
    if (isIdempotent(content, 'helmet')) {
      return { fixId: 'add-helmet-express', applied: false, description: 'helmet already present — skipped' };
    }

    backup(targetFile);
    const lines = content.split('\n');

    // Find last import line
    let lastImportIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      if (/^import /.test(lines[i] ?? '')) lastImportIdx = i;
    }

    const helmetImport = `import helmet from 'helmet';`;
    const helmetUse = `app.use(helmet());`;

    let modified = [...lines];

    // Insert import after last import block
    if (lastImportIdx >= 0) {
      modified.splice(lastImportIdx + 1, 0, helmetImport);
    } else {
      modified.unshift(helmetImport);
    }

    // Insert app.use(helmet()) after express() initialization
    const appInitIdx = modified.findIndex(l => /(?:const|let|var)\s+app\s*=\s*express\s*\(/.test(l));
    if (appInitIdx >= 0) {
      modified.splice(appInitIdx + 1, 0, helmetUse);
    }

    fs.writeFileSync(targetFile, modified.join('\n'), 'utf-8');
    return {
      fixId: 'add-helmet-express',
      applied: true,
      description: `Added helmet import and app.use(helmet()) to ${path.relative(ctx.rootPath, targetFile)}. Run: npm install helmet`,
    };
  } catch (err) {
    return { fixId: 'add-helmet-express', applied: false, description: 'Failed', error: String(err) };
  }
}

async function addNextjsSecurityHeaders(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const candidates = ['next.config.js', 'next.config.ts', 'next.config.mjs'];
  let targetFile: string | null = null;

  for (const candidate of candidates) {
    const fullPath = path.join(ctx.rootPath, candidate);
    if (fs.existsSync(fullPath)) { targetFile = fullPath; break; }
  }

  if (!targetFile) {
    return { fixId: 'add-nextjs-headers', applied: false, description: 'next.config.js not found' };
  }

  try {
    const content = fs.readFileSync(targetFile, 'utf-8');
    if (isIdempotent(content, 'Content-Security-Policy')) {
      return { fixId: 'add-nextjs-headers', applied: false, description: 'Security headers already present in next.config — skipped' };
    }
    if (content.includes('headers()') || content.includes('headers:')) {
      return {
        fixId: 'add-nextjs-headers',
        applied: false,
        description: 'next.config already has a headers() function — manual edit needed to add security headers inside it',
      };
    }

    backup(targetFile);

    const headersBlock = `
// Security headers added by vibe-safe
const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" },
];
`;

    const appendedContent = content.trimEnd() + headersBlock;
    fs.writeFileSync(targetFile, appendedContent, 'utf-8');
    return { fixId: 'add-nextjs-headers', applied: true, description: 'Added securityHeaders constant to next.config.js — wire it into your config\'s headers() export manually.' };
  } catch (err) {
    return { fixId: 'add-nextjs-headers', applied: false, description: 'Failed', error: String(err) };
  }
}

async function addRateLimitBoilerplate(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const suggestionsDir = path.join(ctx.rootPath, 'vibe-safe-suggestions');
  if (!fs.existsSync(suggestionsDir)) {
    fs.mkdirSync(suggestionsDir, { recursive: true });
  }

  const filePath = path.join(suggestionsDir, 'rate-limit.ts');
  if (fs.existsSync(filePath)) {
    return { fixId: 'add-rate-limit-boilerplate', applied: false, description: 'Rate limit boilerplate already exists' };
  }

  const boilerplate = `/**
 * Rate Limiting Boilerplate — generated by vibe-safe
 *
 * INSTRUCTIONS: Copy the relevant section into your Express app entry file.
 * Run: npm install express-rate-limit
 */

import rateLimit from 'express-rate-limit';

// General API rate limit — 100 requests per 15 minutes per IP
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});

// Strict limit for auth endpoints — 10 requests per 15 minutes per IP
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' },
});

// AI/expensive endpoint limit — 20 requests per hour per IP
export const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'AI rate limit reached. Please try again later.' },
});

// Usage in your app:
// app.use('/api/', generalLimiter);
// app.use('/api/auth/', authLimiter);
// app.post('/api/chat', aiLimiter, yourChatHandler);

/* --- Python/FastAPI version (pip install slowapi) ---

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/api/data")
@limiter.limit("100/minute")
async def data_endpoint(request: Request):
    ...
*/
`;

  fs.writeFileSync(filePath, boilerplate, 'utf-8');
  return {
    fixId: 'add-rate-limit-boilerplate',
    applied: true,
    description: `Created vibe-safe-suggestions/rate-limit.ts with copy-paste rate limiting boilerplate`,
  };
}

async function createPrivacyPolicy(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const outPath = path.join(ctx.rootPath, 'PRIVACY.md');
  if (fs.existsSync(outPath)) {
    return { fixId: 'create-privacy-policy', applied: false, description: 'PRIVACY.md already exists — skipped' };
  }
  const content = `# Privacy Policy

_Last updated: ${new Date().toISOString().slice(0, 10)}_

## 1. What We Collect
We collect information you provide directly (e.g. name, email address) and usage data (e.g. pages visited, actions taken).

## 2. How We Use It
- To provide and improve the service
- To communicate with you about your account
- To comply with legal obligations

We do **not** sell your personal data to third parties.

## 3. Data Storage
Your data is stored securely. Passwords are hashed and never stored in plain text.

## 4. Your Rights
Depending on your jurisdiction you may have the right to access, correct, or delete your data. Contact us to exercise these rights.

## 5. Cookies
We use essential session cookies to keep you logged in. No advertising or tracking cookies are used.

## 6. Contact
For privacy questions: [your-email@example.com]

---
_This template was generated by [vibe-safe](https://github.com/your-org/vibe-safe). Replace placeholder text before publishing._
`;
  try {
    fs.writeFileSync(outPath, content, 'utf-8');
    return { fixId: 'create-privacy-policy', applied: true, description: 'Created PRIVACY.md — update placeholders before publishing' };
  } catch (err) {
    return { fixId: 'create-privacy-policy', applied: false, description: 'Failed', error: String(err) };
  }
}

async function createTermsOfService(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const outPath = path.join(ctx.rootPath, 'TERMS.md');
  if (fs.existsSync(outPath)) {
    return { fixId: 'create-terms-of-service', applied: false, description: 'TERMS.md already exists — skipped' };
  }
  const content = `# Terms of Service

_Last updated: ${new Date().toISOString().slice(0, 10)}_

## 1. Acceptance
By using this service you agree to these Terms. If you do not agree, do not use the service.

## 2. Use of Service
You agree not to:
- Use the service for any unlawful purpose
- Attempt to gain unauthorised access to any part of the service
- Submit false or misleading information

## 3. Intellectual Property
All content and code is owned by [Your Company]. You may not reproduce or distribute it without permission.

## 4. Limitation of Liability
The service is provided "as is". We are not liable for any indirect, incidental, or consequential damages arising from your use of the service.

## 5. Termination
We may suspend or terminate your access if you violate these Terms.

## 6. Changes
We may update these Terms at any time. Continued use constitutes acceptance of the revised Terms.

## 7. Governing Law
These Terms are governed by the laws of [Your Jurisdiction].

## 8. Contact
Questions: [your-email@example.com]

---
_This template was generated by [vibe-safe](https://github.com/your-org/vibe-safe). Replace placeholder text before publishing._
`;
  try {
    fs.writeFileSync(outPath, content, 'utf-8');
    return { fixId: 'create-terms-of-service', applied: true, description: 'Created TERMS.md — update placeholders before publishing' };
  } catch (err) {
    return { fixId: 'create-terms-of-service', applied: false, description: 'Failed', error: String(err) };
  }
}

async function fixDebugTrue(ctx: ScanContext, finding: Finding): Promise<FixResult> {
  if (!finding.file) {
    return { fixId: 'fix-debug-true', applied: false, description: 'No file path in finding' };
  }
  const filePath = path.isAbsolute(finding.file)
    ? finding.file
    : path.join(ctx.rootPath, finding.file);

  if (!isWithinRoot(ctx.rootPath, filePath)) {
    return { fixId: 'fix-debug-true', applied: false, description: 'File path outside project root — skipped for safety' };
  }
  if (!fs.existsSync(filePath)) {
    return { fixId: 'fix-debug-true', applied: false, description: `File not found: ${finding.file}` };
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const updated = content
      .replace(/\bDEBUG\s*=\s*true\b/gi, m => m.replace(/true/i, 'false'))
      .replace(/\bVERBOSE\s*=\s*true\b/gi, m => m.replace(/true/i, 'false'));

    if (updated === content) {
      return { fixId: 'fix-debug-true', applied: false, description: 'DEBUG=true not found in file (may already be fixed)' };
    }
    backup(filePath);
    fs.writeFileSync(filePath, updated, 'utf-8');
    return { fixId: 'fix-debug-true', applied: true, description: `Set DEBUG=false in ${finding.file}` };
  } catch (err) {
    return { fixId: 'fix-debug-true', applied: false, description: 'Failed', error: String(err) };
  }
}

async function removeSensitiveLogs(ctx: ScanContext, finding: Finding): Promise<FixResult> {
  if (!finding.file || !finding.line) {
    return { fixId: 'remove-sensitive-logs', applied: false, description: 'No file/line in finding' };
  }
  const filePath = path.isAbsolute(finding.file)
    ? finding.file
    : path.join(ctx.rootPath, finding.file);

  if (!isWithinRoot(ctx.rootPath, filePath)) {
    return { fixId: 'remove-sensitive-logs', applied: false, description: 'File path outside project root — skipped for safety' };
  }
  if (!fs.existsSync(filePath)) {
    return { fixId: 'remove-sensitive-logs', applied: false, description: `File not found: ${finding.file}` };
  }

  try {
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    const lineIdx = finding.line - 1;
    if (lineIdx < 0 || lineIdx >= lines.length) {
      return { fixId: 'remove-sensitive-logs', applied: false, description: 'Line number out of range' };
    }
    const line = lines[lineIdx] ?? '';
    if (line.trim().startsWith('//')) {
      return { fixId: 'remove-sensitive-logs', applied: false, description: `Line already commented out in ${finding.file}` };
    }
    backup(filePath);
    lines[lineIdx] = line.replace(/^(\s*)/, '$1// [vibe-safe] ');
    fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
    return { fixId: 'remove-sensitive-logs', applied: true, description: `Commented out sensitive log on line ${finding.line} of ${finding.file}` };
  } catch (err) {
    return { fixId: 'remove-sensitive-logs', applied: false, description: 'Failed', error: String(err) };
  }
}

async function addValidationBoilerplate(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const suggestionsDir = path.join(ctx.rootPath, 'vibe-safe-suggestions');
  if (!fs.existsSync(suggestionsDir)) fs.mkdirSync(suggestionsDir, { recursive: true });

  const filePath = path.join(suggestionsDir, 'validation.ts');
  if (fs.existsSync(filePath)) {
    return { fixId: 'add-validation-boilerplate', applied: false, description: 'Validation boilerplate already exists' };
  }

  const boilerplate = `/**
 * Input Validation Boilerplate — generated by vibe-safe
 *
 * INSTRUCTIONS: Copy relevant schemas into your route handlers.
 * Run: npm install zod
 */

import { z } from 'zod';

// ── Common reusable schemas ──────────────────────────────────────────────────

export const emailSchema = z.string().email().max(254).toLowerCase().trim();
export const passwordSchema = z.string().min(8).max(128);
export const uuidSchema = z.string().uuid();
export const pageSchema = z.coerce.number().int().min(1).max(1000).default(1);

// ── Request body schemas ─────────────────────────────────────────────────────

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().min(1).max(100).trim(),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(128),
});

// ── Usage in an Express route ────────────────────────────────────────────────

// import { registerSchema } from './vibe-safe-suggestions/validation';
//
// app.post('/auth/register', (req, res) => {
//   const result = registerSchema.safeParse(req.body);
//   if (!result.success) {
//     return res.status(400).json({ error: result.error.flatten() });
//   }
//   const { email, password, name } = result.data;
//   // ... proceed with validated data
// });

/* --- Python/FastAPI version (pydantic built-in) ---

from pydantic import BaseModel, EmailStr, constr

class RegisterRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)
    name: constr(min_length=1, max_length=100)

@app.post("/auth/register")
async def register(body: RegisterRequest):
    ...  # body is already validated
*/
`;

  fs.writeFileSync(filePath, boilerplate, 'utf-8');
  return {
    fixId: 'add-validation-boilerplate',
    applied: true,
    description: 'Created vibe-safe-suggestions/validation.ts with zod schemas — run: npm install zod',
  };
}

async function create404Page(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  // Try to detect framework to pick the right template
  const isNextJs = ctx.frameworks.includes('nextjs');
  const isExpress = ctx.frameworks.includes('express');

  if (isNextJs) {
    // Next.js App Router: app/not-found.tsx
    const appDir = path.join(ctx.rootPath, 'app');
    const pagesDir = path.join(ctx.rootPath, 'pages');
    if (fs.existsSync(appDir)) {
      const outPath = path.join(appDir, 'not-found.tsx');
      if (fs.existsSync(outPath)) return { fixId: 'create-404-page', applied: false, description: 'app/not-found.tsx already exists' };
      fs.writeFileSync(outPath, `export default function NotFound() {
  return (
    <main style={{ textAlign: 'center', padding: '4rem' }}>
      <h1>404 — Page Not Found</h1>
      <p>The page you are looking for does not exist.</p>
      <a href="/">Go home</a>
    </main>
  );
}
`, 'utf-8');
      return { fixId: 'create-404-page', applied: true, description: 'Created app/not-found.tsx (Next.js App Router 404 page)' };
    } else if (fs.existsSync(pagesDir)) {
      const outPath = path.join(pagesDir, '404.tsx');
      if (fs.existsSync(outPath)) return { fixId: 'create-404-page', applied: false, description: 'pages/404.tsx already exists' };
      fs.writeFileSync(outPath, `export default function Custom404() {
  return (
    <main style={{ textAlign: 'center', padding: '4rem' }}>
      <h1>404 — Page Not Found</h1>
      <p>The page you are looking for does not exist.</p>
      <a href="/">Go home</a>
    </main>
  );
}
`, 'utf-8');
      return { fixId: 'create-404-page', applied: true, description: 'Created pages/404.tsx (Next.js Pages Router 404 page)' };
    }
  }

  // Express: create a vibe-safe-suggestions snippet
  if (isExpress) {
    const suggestionsDir = path.join(ctx.rootPath, 'vibe-safe-suggestions');
    if (!fs.existsSync(suggestionsDir)) fs.mkdirSync(suggestionsDir, { recursive: true });
    const outPath = path.join(suggestionsDir, 'error-handlers.ts');
    if (fs.existsSync(outPath)) return { fixId: 'create-404-page', applied: false, description: 'vibe-safe-suggestions/error-handlers.ts already exists' };
    fs.writeFileSync(outPath, `/**
 * Error Handlers — generated by vibe-safe
 * Add these AFTER all your routes, just before app.listen()
 */
import { Request, Response, NextFunction } from 'express';

// 404 — must be the last route
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({ error: 'Not found', path: req.path });
}

// 500 — must have exactly 4 parameters to be treated as error middleware by Express
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
}

// Wire up in your app entry file:
// app.use(notFoundHandler);
// app.use(errorHandler);
`, 'utf-8');
    return { fixId: 'create-404-page', applied: true, description: 'Created vibe-safe-suggestions/error-handlers.ts with 404 + 500 handler templates' };
  }

  // Fallback: generic HTML 404 in public/
  const publicDir = path.join(ctx.rootPath, 'public');
  const targetDir = fs.existsSync(publicDir) ? publicDir : ctx.rootPath;
  const outPath = path.join(targetDir, '404.html');
  if (fs.existsSync(outPath)) return { fixId: 'create-404-page', applied: false, description: '404.html already exists' };
  fs.writeFileSync(outPath, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>404 — Page Not Found</title>
  <style>
    body { font-family: system-ui, sans-serif; display: flex; align-items: center;
           justify-content: center; min-height: 100vh; margin: 0; background: #f9f9f9; }
    .box { text-align: center; padding: 2rem; }
    h1 { font-size: 4rem; margin: 0; color: #111; }
    p  { color: #555; margin: 1rem 0; }
    a  { color: #7c3aed; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <div class="box">
    <h1>404</h1>
    <p>The page you're looking for doesn't exist.</p>
    <a href="/">Go back home</a>
  </div>
</body>
</html>
`, 'utf-8');
  return { fixId: 'create-404-page', applied: true, description: `Created ${path.relative(ctx.rootPath, outPath)} — a custom 404 page` };
}

async function create500Handler(ctx: ScanContext, _finding: Finding): Promise<FixResult> {
  const isNextJs = ctx.frameworks.includes('nextjs');

  if (isNextJs) {
    const appDir = path.join(ctx.rootPath, 'app');
    const pagesDir = path.join(ctx.rootPath, 'pages');
    if (fs.existsSync(appDir)) {
      const outPath = path.join(appDir, 'error.tsx');
      if (fs.existsSync(outPath)) return { fixId: 'create-500-handler', applied: false, description: 'app/error.tsx already exists' };
      fs.writeFileSync(outPath, `'use client';
// This file is required to be a Client Component
export default function Error({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <main style={{ textAlign: 'center', padding: '4rem' }}>
      <h1>Something went wrong</h1>
      <p>An unexpected error occurred. Please try again.</p>
      <button onClick={reset}>Try again</button>
    </main>
  );
}
`, 'utf-8');
      return { fixId: 'create-500-handler', applied: true, description: 'Created app/error.tsx (Next.js App Router error boundary)' };
    } else if (fs.existsSync(pagesDir)) {
      const outPath = path.join(pagesDir, '500.tsx');
      if (fs.existsSync(outPath)) return { fixId: 'create-500-handler', applied: false, description: 'pages/500.tsx already exists' };
      fs.writeFileSync(outPath, `export default function Custom500() {
  return (
    <main style={{ textAlign: 'center', padding: '4rem' }}>
      <h1>500 — Server Error</h1>
      <p>Something went wrong on our end. Please try again later.</p>
    </main>
  );
}
`, 'utf-8');
      return { fixId: 'create-500-handler', applied: true, description: 'Created pages/500.tsx (Next.js Pages Router 500 page)' };
    }
  }

  // Express: add to suggestions file (which may already exist from create-404-page)
  const suggestionsDir = path.join(ctx.rootPath, 'vibe-safe-suggestions');
  if (!fs.existsSync(suggestionsDir)) fs.mkdirSync(suggestionsDir, { recursive: true });
  const outPath = path.join(suggestionsDir, 'error-handlers.ts');
  if (fs.existsSync(outPath)) {
    return { fixId: 'create-500-handler', applied: false, description: 'vibe-safe-suggestions/error-handlers.ts already exists (check it for the errorHandler export)' };
  }
  fs.writeFileSync(outPath, `/**
 * Error Handlers — generated by vibe-safe
 * Add these AFTER all your routes, just before app.listen()
 */
import { Request, Response, NextFunction } from 'express';

// 404 — must be the last route
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({ error: 'Not found', path: req.path });
}

// 500 — must have exactly 4 parameters to be treated as error middleware by Express
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  console.error('[ERROR]', err.message); // log message only — NOT the full stack
  res.status(500).json({ error: 'Internal server error' });
}

// Wire up in your app entry file:
// app.use(notFoundHandler);
// app.use(errorHandler);
`, 'utf-8');
  return { fixId: 'create-500-handler', applied: true, description: 'Created vibe-safe-suggestions/error-handlers.ts with Express error handler template' };
}

const FIX_REGISTRY: Record<string, FixFn> = {
  'add-env-gitignore': addEnvToGitignore,
  'create-env-example': createEnvExample,
  'add-helmet-express': addHelmetToExpress,
  'add-nextjs-headers': addNextjsSecurityHeaders,
  'add-rate-limit-boilerplate': addRateLimitBoilerplate,
  'create-privacy-policy': createPrivacyPolicy,
  'create-terms-of-service': createTermsOfService,
  'fix-debug-true': fixDebugTrue,
  'remove-sensitive-logs': removeSensitiveLogs,
  'add-validation-boilerplate': addValidationBoilerplate,
  'create-404-page': create404Page,
  'create-500-handler': create500Handler,
};

export async function applyFixes(result: ScanResult, ctx: ScanContext): Promise<FixResult[]> {
  const fixableFindings = result.auditResults
    .flatMap(ar => ar.findings)
    .filter(f => f.autoFixable && f.fixId && f.fixId in FIX_REGISTRY);

  const fixResults: FixResult[] = [];
  const applied = new Set<string>();

  // Run fixes sequentially — order matters (.gitignore before adding .env, etc.)
  for (const finding of fixableFindings) {
    if (!finding.fixId || applied.has(finding.fixId)) continue;
    applied.add(finding.fixId);

    const fixFn = FIX_REGISTRY[finding.fixId];
    if (!fixFn) continue;

    const result = await fixFn(ctx, finding);
    fixResults.push(result);

    const status = result.applied ? '✓' : '–';
    console.log(`  ${status} ${result.description}`);
  }

  return fixResults;
}
