import { Finding, Severity, AuditModule } from '../types';

export interface PatternDef {
  id: string;
  pattern: RegExp;
  description: string;
  severity: Severity;
  remediation: string;
  autoFixable?: boolean;
  fixId?: string;
}

export const SQL_INJECTION_PATTERNS: PatternDef[] = [
  {
    id: 'SEC-001',
    pattern: /query\s*\(\s*`[^`]*\$\{/,
    description: 'Template literal used directly in SQL query() — user input can break out of the query string.',
    severity: 'CRITICAL',
    remediation: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId])',
  },
  {
    id: 'SEC-002',
    pattern: /execute\s*\(\s*`[^`]*\$\{/,
    description: 'Template literal used directly in SQL execute() call.',
    severity: 'CRITICAL',
    remediation: 'Replace with parameterized execute() — pass values as a separate array argument.',
  },
  {
    id: 'SEC-003',
    pattern: /\.raw\s*\(\s*`[^`]*\$\{/,
    description: 'Template literal in ORM raw() query — bypasses ORM safety.',
    severity: 'CRITICAL',
    remediation: "Use parameterized raw queries: knex.raw('SELECT * FROM users WHERE id = ?', [id])",
  },
  {
    id: 'SEC-003b',
    pattern: /["'`]\s*SELECT\s+.+\s+WHERE\s+.+\s*\+\s*[a-zA-Z_$]/i,
    description: 'String concatenation inside a SQL SELECT WHERE clause.',
    severity: 'CRITICAL',
    remediation: 'Never concatenate user-controlled variables into SQL strings. Use prepared statements.',
  },
];

export const XSS_PATTERNS: PatternDef[] = [
  {
    id: 'SEC-004',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/,
    description: 'dangerouslySetInnerHTML used — if user-controlled data flows here, XSS is possible.',
    severity: 'CRITICAL',
    remediation: 'Sanitize input with DOMPurify before passing to dangerouslySetInnerHTML, or avoid it entirely.',
  },
  {
    id: 'SEC-004b',
    pattern: /innerHTML\s*=\s*[^'"]/,
    description: 'Direct innerHTML assignment without a string literal — potential XSS if value is user-controlled.',
    severity: 'HIGH',
    remediation: 'Use textContent for plain text, or sanitize HTML with DOMPurify before assigning innerHTML.',
  },
];

export const EVAL_PATTERNS: PatternDef[] = [
  {
    id: 'SEC-005',
    pattern: /\beval\s*\(/,
    description: 'eval() executes arbitrary code — never pass user input to eval().',
    severity: 'HIGH',
    remediation: 'Remove eval(). Use JSON.parse() for JSON data, or refactor to eliminate dynamic code execution.',
  },
  {
    id: 'SEC-005b',
    pattern: /new\s+Function\s*\(/,
    description: 'new Function() is equivalent to eval() — arbitrary code execution risk.',
    severity: 'HIGH',
    remediation: 'Replace new Function() with a safer alternative.',
  },
];

export const SECRET_PATTERNS: PatternDef[] = [
  {
    id: 'SCR-001',
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    description: 'OpenAI secret key found in source code.',
    severity: 'CRITICAL',
    remediation: 'Move to .env file and access via process.env. Rotate the key immediately.',
  },
  {
    id: 'SCR-002',
    pattern: /sk-ant-[a-zA-Z0-9\-]{20,}/,
    description: 'Anthropic API key found in source code.',
    severity: 'CRITICAL',
    remediation: 'Move to .env file and access via process.env. Rotate the key immediately.',
  },
  {
    id: 'SCR-003',
    pattern: /ghp_[a-zA-Z0-9]{36}/,
    description: 'GitHub Personal Access Token found in source code.',
    severity: 'CRITICAL',
    remediation: 'Revoke this token on GitHub immediately, then move secrets to environment variables.',
  },
  {
    id: 'SCR-004',
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    description: 'Google API key found in source code.',
    severity: 'CRITICAL',
    remediation: 'Move to .env file. Restrict the key\'s permissions in Google Console.',
  },
  {
    id: 'SCR-005',
    pattern: /(?:API_KEY|APIKEY|api_key)\s*=\s*['"][^'"$][^'"]{7,}['"]/i,
    description: 'Hardcoded API key literal found in source.',
    severity: 'CRITICAL',
    remediation: 'Move to .env and reference via process.env.API_KEY.',
  },
  {
    id: 'SCR-006',
    pattern: /(?:SECRET|secret_key|SECRET_KEY)\s*=\s*['"][^'"$][^'"]{7,}['"]/,
    description: 'Hardcoded secret value found in source.',
    severity: 'CRITICAL',
    remediation: 'Move to .env and reference via environment variable.',
  },
  {
    id: 'SCR-007',
    pattern: /(?:password|PASSWORD|passwd)\s*=\s*['"][^'"$][^'"]{3,}['"]/,
    description: 'Hardcoded password found in source code.',
    severity: 'CRITICAL',
    remediation: 'Never hardcode passwords. Use environment variables and a secrets manager.',
  },
  {
    id: 'SCR-008',
    pattern: /STRIPE_(?:SECRET|LIVE)_KEY\s*=\s*['"]sk_[a-zA-Z0-9_]{20,}['"]/,
    description: 'Stripe secret key hardcoded in source.',
    severity: 'CRITICAL',
    remediation: 'Move to .env immediately. This key can be used to charge customers.',
  },
  {
    id: 'SCR-009',
    pattern: /(?:TOKEN|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*['"][^'"$][^'"]{15,}['"]/i,
    description: 'Hardcoded authentication token found.',
    severity: 'CRITICAL',
    remediation: 'Move token to .env file and rotate it.',
  },
];

export const DEBUG_PATTERNS: PatternDef[] = [
  {
    id: 'ENV-003',
    pattern: /DEBUG\s*=\s*true/i,
    description: 'DEBUG=true left enabled — may expose stack traces and internal details to users.',
    severity: 'LOW',
    remediation: 'Set DEBUG=false in production. Use environment-conditional debug flags.',
    autoFixable: true,
    fixId: 'fix-debug-true',
  },
  {
    id: 'ENV-003b',
    pattern: /VERBOSE\s*=\s*true/i,
    description: 'VERBOSE=true found — verbose logging can leak sensitive data in production.',
    severity: 'LOW',
    remediation: 'Disable verbose logging in production environments.',
    autoFixable: true,
    fixId: 'fix-debug-true',
  },
];

export const SENSITIVE_LOG_PATTERNS: PatternDef[] = [
  {
    id: 'ENV-004',
    pattern: /console\.log\s*\([^)]*(?:password|token|secret|apiKey|api_key|AUTH)[^)]*\)/i,
    description: 'console.log may be logging sensitive data (password/token/secret).',
    severity: 'MEDIUM',
    remediation: 'Remove or redact sensitive fields from log statements.',
    autoFixable: true,
    fixId: 'remove-sensitive-logs',
  },
];

export const RATE_LIMIT_IMPORTS: string[] = [
  'express-rate-limit',
  'rate-limit-redis',
  'express-slow-down',
  '@nestjs/throttler',
  'fastify-rate-limit',
  'slowapi',
  'fastapi-limiter',
  'flask-limiter',
  'ratelimit',
  'django-ratelimit',
];

export const VALIDATION_IMPORTS: string[] = [
  'zod',
  'yup',
  'joi',
  'class-validator',
  'express-validator',
  'pydantic',
  'BaseModel',
  'cerberus',
  'marshmallow',
  'voluptuous',
];

export const CAPTCHA_IMPORTS: string[] = [
  'hcaptcha',
  'recaptcha',
  'turnstile',
  'react-google-recaptcha',
  '@hcaptcha/react-hcaptcha',
  'cf-turnstile',
  'captcha',
];

export const CSRF_IMPORTS: string[] = [
  'csurf',
  'csrf-csrf',
  'csrf',
  '@fastify/csrf-protection',
  'django.middleware.csrf',
  'CsrfProtect',
  'csrfToken',
];

export const SECURITY_HEADER_INDICATORS: string[] = [
  'helmet',
  'Content-Security-Policy',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Strict-Transport-Security',
  'SecurityMiddleware',
  'SECURE_CONTENT_TYPE_NOSNIFF',
  'SECURE_HSTS_SECONDS',
  'SECURE_BROWSER_XSS_FILTER',
];

export function getLineNumber(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

export function getSnippet(content: string, index: number): string {
  const lines = content.split('\n');
  const lineNum = content.slice(0, index).split('\n').length - 1;
  return (lines[lineNum] ?? '').trim().slice(0, 120);
}

export function isCommentedOut(content: string, index: number): boolean {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  const linePrefix = content.slice(lineStart, index).trim();
  return linePrefix.startsWith('//') || linePrefix.startsWith('#') || linePrefix.startsWith('*');
}

export function scanContentForPatterns(
  content: string,
  patterns: PatternDef[],
  filePath: string,
  module: AuditModule
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const def of patterns) {
    const regex = new RegExp(def.pattern.source, def.pattern.flags.includes('g') ? def.pattern.flags : def.pattern.flags + 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      if (isCommentedOut(content, match.index)) continue;

      const line = getLineNumber(content, match.index);
      const key = `${def.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        id: def.id,
        severity: def.severity,
        module,
        title: def.description,
        description: def.description,
        file: filePath,
        line,
        snippet: getSnippet(content, match.index),
        remediation: def.remediation,
        autoFixable: def.autoFixable ?? false,
        fixId: def.fixId,
      });
    }
  }

  return findings;
}
