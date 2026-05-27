import {
  ScanContext, AuditResult, Finding,
} from '../types';
import {
  RATE_LIMIT_IMPORTS, VALIDATION_IMPORTS, CAPTCHA_IMPORTS,
} from '../utils/patternMatcher';
import { getFileContent } from '../utils/fileWalker';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py']);
const AUTH_PATH_PATTERN = /(?:auth|login|register|signup|sign-up|password|forgot|reset)/i;

async function checkRateLimiting(ctx: ScanContext): Promise<Finding[]> {
  for (const entry of ctx.files) {
    if (!['.ts', '.js', '.py', '.txt', '.toml'].includes(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (RATE_LIMIT_IMPORTS.some(imp => content.includes(imp))) return [];
  }

  return [{
    id: 'ABUSE-001',
    severity: 'HIGH',
    module: 'abuse',
    title: 'No rate limiting library detected',
    description: 'No rate limiting middleware found. Without rate limits, a single user or bot can call your API thousands of times per minute — burning through paid API quotas (OpenAI, Stripe) and degrading service for everyone.',
    remediation: 'Node/Express: npm install express-rate-limit, then:\n  const rateLimit = require("express-rate-limit");\n  app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));\nPython/FastAPI: pip install slowapi',
    autoFixable: true,
    fixId: 'add-rate-limit-boilerplate',
  }];
}

async function checkInputValidation(ctx: ScanContext): Promise<Finding[]> {
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (VALIDATION_IMPORTS.some(imp => content.includes(imp))) return [];
  }

  return [{
    id: 'ABUSE-002',
    severity: 'HIGH',
    module: 'abuse',
    title: 'No input validation library detected',
    description: 'No input validation library found (zod, yup, joi for Node; pydantic for Python). Without validation, malformed data reaches your database and business logic — causing crashes, data corruption, and potential injection attacks.',
    remediation: 'Node: npm install zod, then define schemas and parse req.body.\nPython/FastAPI: use Pydantic models — they are built-in to FastAPI.',
    autoFixable: true,
    fixId: 'add-validation-boilerplate',
  }];
}

async function checkBotProtection(ctx: ScanContext): Promise<Finding[]> {
  let hasAuthRoutes = false;
  let hasCaptcha = false;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    if (AUTH_PATH_PATTERN.test(entry.relativePath)) {
      hasAuthRoutes = true;
    }
    if (/(?:router|app)\.post.*(?:login|register|signup)/i.test(content) ||
        /@app\.route.*(?:login|register|signup)/i.test(content)) {
      hasAuthRoutes = true;
    }
    if (CAPTCHA_IMPORTS.some(imp => content.toLowerCase().includes(imp.toLowerCase()))) {
      hasCaptcha = true;
    }
  }

  if (hasAuthRoutes && !hasCaptcha) {
    return [{
      id: 'ABUSE-003',
      severity: 'LOW',
      module: 'abuse',
      title: 'No CAPTCHA/bot protection on authentication routes',
      description: 'Auth routes detected but no CAPTCHA or bot protection found. Without it, automated tools can attempt unlimited password guesses or create thousands of accounts.',
      remediation: 'Add Cloudflare Turnstile (free) or hCaptcha to your login/register forms. Server-side: verify the captcha token before processing.',
      autoFixable: false,
    }];
  }
  return [];
}

async function checkSpendCaps(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const openAIImportPattern = /(?:from ['"]openai['"]|require\(['"]openai['"]\)|import openai)/;
  const chatCompletePattern = /\.chat\.completions\.create\s*\(|\.complete\s*\(|openai\.ChatCompletion/;
  const maxTokensPattern = /max_tokens\s*[:=]/;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    if (!openAIImportPattern.test(content)) continue;
    if (!chatCompletePattern.test(content)) continue;
    if (!maxTokensPattern.test(content)) {
      findings.push({
        id: 'ABUSE-004',
        severity: 'MEDIUM',
        module: 'abuse',
        title: 'OpenAI API calls without max_tokens limit',
        description: `OpenAI completions in ${entry.relativePath} have no max_tokens set. A single malicious or looping request can run up a massive bill.`,
        file: entry.relativePath,
        remediation: 'Always set max_tokens in every OpenAI API call. Also set a hard spend cap in your OpenAI dashboard under Usage Limits.',
        autoFixable: false,
      });
    }
  }
  return findings;
}

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();
  const [rateLimiting, validation, botProtection, spendCaps] = await Promise.all([
    checkRateLimiting(ctx),
    checkInputValidation(ctx),
    checkBotProtection(ctx),
    checkSpendCaps(ctx),
  ]);

  return {
    module: 'abuse',
    findings: [...rateLimiting, ...validation, ...botProtection, ...spendCaps],
    duration: Date.now() - start,
  };
}
