import axios from 'axios';
import { ProbeResult } from '../types';

// A path that should never exist — triggers a 404 response from the app
const NOT_FOUND_PATH = '/vibe-safe-probe-404-check-xk39z';

// Patterns that indicate the server is leaking internal details in error pages
const STACK_TRACE_PATTERNS = [
  /at\s+\w+\s*\([^)]+:\d+:\d+\)/,          // JS/Node stack frame: at fn (file:line:col)
  /Traceback\s+\(most recent call last\)/i,   // Python traceback
  /File\s+"[^"]+",\s+line\s+\d+/,            // Python file reference
  /^\s+at\s+.+\.js:\d+/m,                    // Node.js stack frame
  /Error:\s+.+\n\s+at\s/,                    // JS Error + stack
  /\[object Object\]/,                        // Unserialised JS error object
];

const FRAMEWORK_LEAK_PATTERNS: Array<{ pattern: RegExp; framework: string }> = [
  { pattern: /Cannot\s+(?:GET|POST|PUT|DELETE|PATCH)\s+\//i, framework: 'Express default error page' },
  { pattern: /Express\b.*\d+\.\d+/i,                          framework: 'Express version leak' },
  { pattern: /powered\s+by\s+express/i,                       framework: 'X-Powered-By: Express header' },
  { pattern: /Django\s+tried\s+these\s+URL/i,                 framework: 'Django debug 404 page' },
  { pattern: /Django\s+Version:/i,                             framework: 'Django version leak' },
  { pattern: /Werkzeug\s+Debugger/i,                           framework: 'Flask/Werkzeug debugger exposed' },
  { pattern: /werkzeug\//i,                                    framework: 'Werkzeug version in header' },
  { pattern: /FastAPI\s+\d+\.\d+/i,                            framework: 'FastAPI version leak' },
  { pattern: /Rails\.version/i,                                framework: 'Rails version leak' },
  { pattern: /Laravel\s+v\d+/i,                                framework: 'Laravel version leak' },
  { pattern: /PHP\s+Parse\s+error/i,                           framework: 'PHP error exposed' },
  { pattern: /Microsoft\s+ASP\.NET/i,                          framework: 'ASP.NET version leak' },
];

const SERVER_HEADER_LEAKS = [
  'x-powered-by',
  'server',
  'x-aspnet-version',
  'x-aspnetmvc-version',
];

async function probe404(baseUrl: string): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const url = baseUrl.replace(/\/$/, '') + NOT_FOUND_PATH;

  let body = '';
  let statusCode = 0;
  const leakedHeaders: string[] = [];

  try {
    const resp = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 5,
    });

    statusCode = resp.status;
    body = typeof resp.data === 'string'
      ? resp.data
      : JSON.stringify(resp.data);

    // Check response headers for server fingerprinting
    for (const h of SERVER_HEADER_LEAKS) {
      const val = resp.headers[h];
      if (val) leakedHeaders.push(`${h}: ${val}`);
    }
  } catch (err) {
    return [{
      id: 'PROBE-ERR-000',
      module: 'error-pages',
      severity: 'LOW',
      title: 'Could not reach target to check error pages',
      confirmed: false,
      endpoint: url,
      payload: `GET ${NOT_FOUND_PATH}`,
      response: err instanceof Error ? err.message : String(err),
      remediation: 'Ensure the app is running and reachable at the probe URL.',
    }];
  }

  // ── Stack trace in response body ──────────────────────────────────────────
  const stackMatch = STACK_TRACE_PATTERNS.find(p => p.test(body));
  if (stackMatch) {
    results.push({
      id: 'PROBE-ERR-001',
      module: 'error-pages',
      severity: 'HIGH',
      title: 'Stack trace exposed in 404 error response',
      confirmed: true,
      endpoint: url,
      payload: `GET ${NOT_FOUND_PATH}`,
      response: body.slice(0, 400),
      remediation:
        'Add a global error handler that catches unhandled exceptions and returns a generic message. ' +
        'Never pass the raw Error object to res.json() or render it in templates. ' +
        'Set NODE_ENV=production — Express automatically hides stack traces in production mode.',
    });
  }

  // ── Framework / tech stack leak in response body ──────────────────────────
  const frameworkLeak = FRAMEWORK_LEAK_PATTERNS.find(({ pattern }) => pattern.test(body));
  if (frameworkLeak) {
    results.push({
      id: 'PROBE-ERR-002',
      module: 'error-pages',
      severity: 'MEDIUM',
      title: `Framework fingerprint in error page: ${frameworkLeak.framework}`,
      confirmed: true,
      endpoint: url,
      payload: `GET ${NOT_FOUND_PATH}`,
      response: body.slice(0, 400),
      remediation:
        'Replace the default framework error page with a custom one that gives no hints about the technology stack. ' +
        'Express: add a catch-all 404 handler before app.listen(). ' +
        'Django: set DEBUG=False and define TEMPLATES with a custom 404.html. ' +
        'Flask: use @app.errorhandler(404) with a custom template.',
    });
  }

  // ── Server-fingerprinting headers ─────────────────────────────────────────
  if (leakedHeaders.length > 0) {
    results.push({
      id: 'PROBE-ERR-003',
      module: 'error-pages',
      severity: 'LOW',
      title: `Server fingerprinting headers present: ${leakedHeaders.join(', ')}`,
      confirmed: true,
      endpoint: url,
      payload: `GET ${NOT_FOUND_PATH}`,
      response: `Headers returned: ${leakedHeaders.join(' | ')}`,
      remediation:
        'Remove or obfuscate server identification headers. ' +
        'Express: app.disable("x-powered-by") or use helmet() which removes it automatically. ' +
        'Nginx: set server_tokens off; in nginx.conf. ' +
        'Apache: add ServerTokens Prod and ServerSignature Off.',
    });
  }

  // ── No custom 404 (default response) ─────────────────────────────────────
  if (results.length === 0 && statusCode === 404) {
    // Try to detect a branded/custom 404 vs a raw one
    const hasCustomContent =
      body.length > 200 &&                       // more than a one-liner
      !/^Cannot (GET|POST)/.test(body.trim()) &&  // not Express default
      !/<title>404<\/title>/i.test(body);         // not a bare browser 404

    if (!hasCustomContent) {
      results.push({
        id: 'PROBE-ERR-004',
        module: 'error-pages',
        severity: 'LOW',
        title: 'Generic / unbranded 404 page served',
        confirmed: true,
        endpoint: url,
        payload: `GET ${NOT_FOUND_PATH}`,
        response: body.slice(0, 300) || '(empty body)',
        remediation:
          'Add a custom 404 page with your app branding, a helpful message, and a link back to the homepage. ' +
          'It should not reveal which framework or server you are running.',
      });
    }
  }

  return results;
}

async function probe500(baseUrl: string): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];

  // Try to trigger a 500 by sending deliberately malformed JSON to common API endpoints
  const targets = ['/api', '/api/data', '/api/users', '/graphql'];
  const base = baseUrl.replace(/\/$/, '');

  for (const target of targets) {
    const url = base + target;
    try {
      const resp = await axios.post(url, 'THIS_IS_NOT_JSON{{{', {
        headers: { 'Content-Type': 'application/json' },
        timeout: 8000,
        validateStatus: () => true,
      });

      if (resp.status !== 500 && resp.status !== 400) continue;
      if (resp.status === 400) continue; // 400 = app handled it correctly

      const body = typeof resp.data === 'string'
        ? resp.data
        : JSON.stringify(resp.data);

      const stackMatch = STACK_TRACE_PATTERNS.find(p => p.test(body));
      if (stackMatch) {
        results.push({
          id: 'PROBE-ERR-005',
          module: 'error-pages',
          severity: 'HIGH',
          title: `Stack trace exposed in 500 response at ${target}`,
          confirmed: true,
          endpoint: url,
          payload: 'POST with malformed JSON body',
          response: body.slice(0, 400),
          remediation:
            'Add a global Express error handler: app.use((err, req, res, next) => { ' +
            'console.error(err); res.status(500).json({ error: "Internal server error" }); }). ' +
            'Never send the raw Error object or stack trace to clients.',
        });
        break; // one confirmed 500 leak is enough
      }
    } catch { /* connection refused = skip */ }
  }

  return results;
}

export async function probe(baseUrl: string): Promise<ProbeResult[]> {
  const [results404, results500] = await Promise.all([
    probe404(baseUrl),
    probe500(baseUrl),
  ]);
  return [...results404, ...results500];
}
