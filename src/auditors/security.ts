import {
  ScanContext, AuditResult, Finding,
} from '../types';
import {
  SQL_INJECTION_PATTERNS, XSS_PATTERNS, EVAL_PATTERNS,
  CSRF_IMPORTS, SECURITY_HEADER_INDICATORS, scanContentForPatterns,
} from '../utils/patternMatcher';
import { getFileContent, isTestFile } from '../utils/fileWalker';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py']);
const FRONTEND_EXTENSIONS = new Set(['.tsx', '.jsx', '.js', '.ts']);

async function checkSQLInjection(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    findings.push(...scanContentForPatterns(content, SQL_INJECTION_PATTERNS, entry.relativePath, 'security'));
  }
  return findings;
}

async function checkXSS(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const entry of ctx.files) {
    if (!FRONTEND_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    findings.push(...scanContentForPatterns(content, XSS_PATTERNS, entry.relativePath, 'security'));
  }
  return findings;
}

async function checkEval(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    // Skip likely minified files
    const lines = content.split('\n');
    if (lines.some(l => l.length > 500)) continue;

    findings.push(...scanContentForPatterns(content, EVAL_PATTERNS, entry.relativePath, 'security'));
  }
  return findings;
}

async function checkCSRF(ctx: ScanContext): Promise<Finding[]> {
  // Check if the project has POST routes
  let hasPostRoutes = false;
  let hasCSRFProtection = false;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    if (/(?:router|app)\.post\s*\(|@app\.route.*methods.*POST|@router\.post/i.test(content)) {
      hasPostRoutes = true;
    }
    if (CSRF_IMPORTS.some(imp => content.includes(imp))) {
      hasCSRFProtection = true;
    }
  }

  if (hasPostRoutes && !hasCSRFProtection) {
    return [{
      id: 'SEC-006',
      severity: 'HIGH',
      module: 'security',
      title: 'No CSRF protection detected on POST routes',
      description: 'POST routes found but no CSRF middleware detected (csurf, csrf-csrf, CsrfProtect). Without CSRF tokens, attackers can forge requests on behalf of authenticated users.',
      remediation: 'Install csrf-csrf (Node) or use built-in CSRF protection in your framework. For REST APIs that use tokens in headers (not cookies), document that explicitly.',
      autoFixable: false,
    }];
  }
  return [];
}

async function checkSecurityHeaders(ctx: ScanContext): Promise<Finding[]> {
  let found = false;

  for (const entry of ctx.files) {
    if (!['.ts', '.js', '.py', '.toml'].includes(entry.extension)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    if (SECURITY_HEADER_INDICATORS.some(indicator => content.includes(indicator))) {
      found = true;
      break;
    }
  }

  if (!found) {
    return [{
      id: 'SEC-007',
      severity: 'MEDIUM',
      module: 'security',
      title: 'No HTTP security headers detected',
      description: 'No security headers middleware found (helmet for Express, headers() in next.config.js, SecurityMiddleware for Django/FastAPI). Without these headers, browsers have no protection against clickjacking, MIME sniffing, and XSS via injected scripts.',
      remediation: 'Express: npm install helmet then app.use(helmet()). Next.js: add a headers() function to next.config.js. FastAPI: use starlette\'s middleware or install secure-headers.',
      autoFixable: true,
      fixId: ctx.frameworks.includes('nextjs') ? 'add-nextjs-headers' : 'add-helmet-express',
    }];
  }
  return [];
}

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();
  const [sql, xss, evalFindings, csrf, headers] = await Promise.all([
    checkSQLInjection(ctx),
    checkXSS(ctx),
    checkEval(ctx),
    checkCSRF(ctx),
    checkSecurityHeaders(ctx),
  ]);

  return {
    module: 'security',
    findings: [...sql, ...xss, ...evalFindings, ...csrf, ...headers],
    duration: Date.now() - start,
  };
}
