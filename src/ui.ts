import * as http from 'http';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as child_process from 'child_process';
import express from 'express';
import { runScan, runAudits } from './scanner';
import { runProbes, mergeProbeResults } from './prober';
import { applyFixes } from './fixer';
import { writePdfReport } from './pdfReport';
import { ScanResult, ScanContext } from './types';

let lastCtx: ScanContext | null = null;
let lastResult: ScanResult | null = null;

function openBrowser(url: string): void {
  const cmd = process.platform === 'win32' ? `start ${url}`
    : process.platform === 'darwin' ? `open ${url}`
    : `xdg-open ${url}`;
  child_process.exec(cmd);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Validates that a URL is a safe http/https target (not internal/loopback for probing). */
function validateProbeUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: 'Invalid URL format' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'Probe URL must use http or https' };
  }
  return { ok: true, url: parsed.toString() };
}

/** Sanitised error — never expose internal stack traces to API consumers. */
function safeError(err: unknown): string {
  if (err instanceof Error) return err.message.split('\n')[0] ?? 'Unknown error';
  return 'An unexpected error occurred';
}

export async function startUI(port = 4000): Promise<void> {
  const app = express();

  // Remove the "X-Powered-By: Express" fingerprint header
  app.disable('x-powered-by');

  // Security headers on every response
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  app.get('/', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    // Strict CSP for the dashboard itself
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    );
    res.send(DASHBOARD_HTML);
  });

  app.post('/api/scan', async (req, res) => {
    const { path: targetPath, probeUrl } = req.body as { path: string; probeUrl?: string };

    if (!targetPath || typeof targetPath !== 'string') {
      res.status(400).json({ error: 'path is required' });
      return;
    }

    // Validate the target is an existing directory (mirrors CLI behaviour)
    const resolvedPath = path.resolve(targetPath);
    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
      res.status(400).json({ error: `"${resolvedPath}" is not a valid directory` });
      return;
    }

    // Validate probe URL if provided
    let safeProbeUrl: string | undefined;
    if (probeUrl && typeof probeUrl === 'string' && probeUrl.trim()) {
      const check = validateProbeUrl(probeUrl.trim());
      if (!check.ok) {
        res.status(400).json({ error: `Invalid probe URL: ${check.error}` });
        return;
      }
      safeProbeUrl = check.url;
    }

    try {
      const ctx = await runScan(resolvedPath, {});
      let result = await runAudits(ctx, {});

      if (safeProbeUrl) {
        const probes = await runProbes(safeProbeUrl, ctx);
        result = mergeProbeResults(result, probes);
      }

      lastCtx = ctx;
      lastResult = result;
      res.json(result);
    } catch (err) {
      console.error('[scan error]', err);
      res.status(500).json({ error: safeError(err) });
    }
  });

  app.get('/api/pdf', async (_req, res) => {
    if (!lastResult) {
      res.status(400).json({ error: 'Run a scan first' });
      return;
    }
    try {
      const tmpPath = path.join(os.tmpdir(), `vibe-safe-report-${Date.now()}.pdf`);
      await writePdfReport(lastResult, tmpPath);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename="vibe-safe-report.pdf"');
      fs.createReadStream(tmpPath).pipe(res);
    } catch (err) {
      console.error('[pdf error]', err);
      res.status(500).json({ error: safeError(err) });
    }
  });

  // ── SEO / crawler files ───────────────────────────────────────────────────
  const projectRoot = path.resolve(__dirname, '..');

  app.get('/robots.txt', (_req, res) => {
    const file = path.join(projectRoot, 'robots.txt');
    if (fs.existsSync(file)) {
      res.setHeader('Content-Type', 'text/plain');
      res.send(fs.readFileSync(file, 'utf-8'));
    } else {
      res.status(404).send('Not found');
    }
  });

  app.get('/sitemap.xml', (_req, res) => {
    const file = path.join(projectRoot, 'sitemap.xml');
    if (fs.existsSync(file)) {
      res.setHeader('Content-Type', 'application/xml');
      res.send(fs.readFileSync(file, 'utf-8'));
    } else {
      res.status(404).send('Not found');
    }
  });

  app.get('/llms.txt', (_req, res) => {
    const file = path.join(projectRoot, 'llms.txt');
    if (fs.existsSync(file)) {
      res.setHeader('Content-Type', 'text/plain');
      res.send(fs.readFileSync(file, 'utf-8'));
    } else {
      res.status(404).send('Not found');
    }
  });

  app.post('/api/fix', async (_req, res) => {
    if (!lastCtx || !lastResult) {
      res.status(400).json({ error: 'Run a scan first' });
      return;
    }
    try {
      const fixes = await applyFixes(lastResult, lastCtx);
      res.json(fixes);
    } catch (err) {
      console.error('[fix error]', err);
      res.status(500).json({ error: safeError(err) });
    }
  });

  const server = http.createServer(app);

  // Bind to 127.0.0.1 only — never expose the dashboard to the local network
  server.listen(port, '127.0.0.1', () => {
    const url = `http://localhost:${port}`;
    console.log(`\n  vibe-safe dashboard → ${url}\n`);
    openBrowser(url);
  });
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vibe-safe — Security Dashboard</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #0e0e14;
    --surface: #16161f;
    --surface2: #1e1e2c;
    --border: #2a2a3d;
    --text: #e2e8f0;
    --muted: #64748b;
    --critical: #ef4444;
    --critical-dim: rgba(239,68,68,0.15);
    --high: #f59e0b;
    --high-dim: rgba(245,158,11,0.15);
    --medium: #06b6d4;
    --medium-dim: rgba(6,182,212,0.15);
    --low: #6b7280;
    --low-dim: rgba(107,114,128,0.12);
    --accent: #111111;
    --accent2: #F5EDD8;
    --green: #22c55e;
    --green-dim: rgba(34,197,94,0.12);
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.5;
  }

  /* ── Header ── */
  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    height: 56px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text);
  }
  .logo-icon {
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 8px;
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 15px;
  }
  .version { color: var(--muted); font-size: 0.8rem; font-weight: 400; }

  /* ── Main layout ── */
  main { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }

  /* ── Scan form ── */
  .scan-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }
  .scan-card h2 {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin-bottom: 1rem;
  }
  .input-row {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .input-row input {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    padding: 0.65rem 1rem;
    font-size: 0.875rem;
    font-family: 'Consolas', 'Monaco', monospace;
    outline: none;
    transition: border-color 0.15s;
  }
  .input-row input:focus { border-color: var(--accent2); }
  .input-row input::placeholder { color: var(--muted); }
  .btn-scan {
    background: linear-gradient(135deg, #F5EDD8, #C8B090);
    color: #111111;
    border: none;
    border-radius: 8px;
    padding: 0.65rem 1.4rem;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity 0.15s, transform 0.1s;
  }
  .btn-scan:hover { opacity: 0.9; }
  .btn-scan:active { transform: scale(0.98); }
  .btn-scan:disabled { opacity: 0.5; cursor: not-allowed; }

  .probe-row { margin-bottom: 0.75rem; }
  .probe-row label {
    display: block;
    font-size: 0.75rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
  }
  .probe-row .input-row { margin-bottom: 0; }

  .probe-warning {
    background: rgba(245,158,11,0.1);
    border: 1px solid rgba(245,158,11,0.3);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    font-size: 0.8rem;
    color: var(--high);
    margin-top: 0.5rem;
    display: none;
    gap: 0.5rem;
    align-items: flex-start;
  }
  .probe-warning.visible { display: flex; }
  .probe-warning label { display: flex; align-items: center; gap: 0.4rem; color: var(--text); cursor: pointer; }
  .options-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-top: 0.5rem;
  }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--muted);
    cursor: pointer;
    user-select: none;
  }
  .checkbox-label input { accent-color: var(--accent2); }

  /* ── Loading ── */
  #loading {
    display: none;
    flex-direction: column;
    align-items: center;
    padding: 3rem;
    gap: 1rem;
    color: var(--muted);
  }
  #loading.visible { display: flex; }
  .spinner {
    width: 36px;
    height: 36px;
    border: 3px solid var(--border);
    border-top-color: var(--accent2);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  #loading-msg { font-size: 0.875rem; }

  /* ── Error ── */
  #error-box {
    display: none;
    background: var(--critical-dim);
    border: 1px solid var(--critical);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    color: var(--critical);
    margin-bottom: 1.5rem;
    font-size: 0.875rem;
  }
  #error-box.visible { display: block; }

  /* ── Results ── */
  #results { display: none; }
  #results.visible { display: block; }

  .scan-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 1.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .scan-meta strong { color: var(--text); }

  /* Summary cards */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .summary-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
    text-align: center;
    transition: border-color 0.15s;
  }
  .summary-card.has-critical { border-color: var(--critical); background: var(--critical-dim); }
  .summary-card.has-high { border-color: var(--high); background: var(--high-dim); }
  .summary-card.has-medium { border-color: var(--medium); background: var(--medium-dim); }
  .summary-card .count {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 0.25rem;
  }
  .summary-card .label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
  }
  .count-critical { color: var(--critical); }
  .count-high { color: var(--high); }
  .count-medium { color: var(--medium); }
  .count-low { color: var(--low); }

  /* Alert banner */
  .alert-banner {
    display: none;
    align-items: center;
    gap: 0.75rem;
    background: var(--critical-dim);
    border: 1px solid var(--critical);
    border-radius: 8px;
    padding: 0.875rem 1.25rem;
    margin-bottom: 1.5rem;
    font-size: 0.875rem;
    color: var(--critical);
    font-weight: 500;
  }
  .alert-banner.visible { display: flex; }

  /* Fix all button */
  .actions-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.25rem;
  }
  .actions-row h2 {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
  }
  .btn-fix-all {
    background: var(--green-dim);
    border: 1px solid var(--green);
    color: var(--green);
    border-radius: 7px;
    padding: 0.4rem 0.9rem;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn-fix-all:hover { background: rgba(34,197,94,0.2); }
  .btn-fix-all:disabled { opacity: 0.5; cursor: not-allowed; }

  /* Export bar */
  .export-bar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.875rem 1.25rem;
    margin-bottom: 1.25rem;
    justify-content: space-between;
  }
  .export-bar-label {
    font-size: 0.8rem;
    color: var(--muted);
    font-weight: 500;
  }
  .btn-pdf {
    background: linear-gradient(135deg, #F5EDD8, #C8B090);
    color: #111111;
    border: none;
    border-radius: 8px;
    padding: 0.55rem 1.2rem;
    font-size: 0.875rem;
    font-weight: 700;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    transition: opacity 0.15s, transform 0.1s;
    letter-spacing: 0.01em;
  }
  .btn-pdf:hover { opacity: 0.9; }
  .btn-pdf:active { transform: scale(0.97); }

  /* Module sections */
  .module-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 0.75rem;
    overflow: hidden;
  }
  .module-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.875rem 1.25rem;
    cursor: pointer;
    user-select: none;
    transition: background 0.1s;
  }
  .module-header:hover { background: var(--surface2); }
  .module-chevron {
    color: var(--muted);
    font-size: 0.75rem;
    transition: transform 0.2s;
    flex-shrink: 0;
  }
  .module-section.open .module-chevron { transform: rotate(90deg); }
  .module-name { font-weight: 600; font-size: 0.9rem; flex: 1; }
  .module-badges { display: flex; gap: 0.4rem; }
  .badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.2rem 0.5rem;
    border-radius: 999px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .badge-critical { background: var(--critical-dim); color: var(--critical); border: 1px solid var(--critical); }
  .badge-high { background: var(--high-dim); color: var(--high); border: 1px solid var(--high); }
  .badge-medium { background: var(--medium-dim); color: var(--medium); border: 1px solid var(--medium); }
  .badge-low { background: var(--low-dim); color: var(--low); border: 1px solid var(--low); }
  .badge-ok { background: var(--green-dim); color: var(--green); border: 1px solid var(--green); }

  .module-body { display: none; border-top: 1px solid var(--border); }
  .module-section.open .module-body { display: block; }

  /* Finding items */
  .finding-item {
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
    display: grid;
    gap: 0.4rem;
  }
  .finding-item:last-child { border-bottom: none; }
  .finding-header {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
  }
  .finding-id { color: var(--muted); font-size: 0.75rem; font-family: monospace; flex-shrink: 0; padding-top: 2px; }
  .finding-title { font-size: 0.875rem; font-weight: 500; flex: 1; }
  .finding-file {
    font-size: 0.75rem;
    color: var(--muted);
    font-family: monospace;
    padding-left: calc(0.6rem + 3.5rem);
  }
  .finding-snippet {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.78rem;
    color: var(--high);
    overflow-x: auto;
    white-space: pre;
    margin-left: calc(0.6rem + 3.5rem);
  }
  .finding-remediation {
    font-size: 0.8rem;
    color: var(--green);
    padding-left: calc(0.6rem + 3.5rem);
  }
  .finding-remediation::before { content: '↳ '; }
  .finding-fixbtn {
    background: var(--green-dim);
    border: 1px solid var(--green);
    color: var(--green);
    border-radius: 5px;
    padding: 0.25rem 0.6rem;
    font-size: 0.73rem;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
    align-self: flex-start;
    transition: background 0.15s;
  }
  .finding-fixbtn:hover { background: rgba(34,197,94,0.2); }

  /* Probe results */
  .probe-section {
    margin-top: 0.75rem;
  }
  .probe-item {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.5rem;
    display: grid;
    gap: 0.4rem;
  }
  .probe-header { display: flex; align-items: center; gap: 0.6rem; }
  .probe-confirmed { font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-weight: 700; }
  .probe-confirmed.yes { background: var(--critical-dim); color: var(--critical); border: 1px solid var(--critical); }
  .probe-confirmed.no { background: var(--low-dim); color: var(--low); }
  .probe-detail { font-size: 0.78rem; color: var(--muted); font-family: monospace; }
  .probe-response {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    font-family: monospace;
    font-size: 0.75rem;
    color: var(--muted);
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 80px;
    overflow-y: auto;
  }
  .probe-fix { font-size: 0.8rem; color: var(--green); }
  .probe-fix::before { content: '↳ '; }

  /* Fix toast */
  #fix-toast {
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    background: var(--surface);
    border: 1px solid var(--green);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    max-width: 360px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    display: none;
    z-index: 100;
  }
  #fix-toast.visible { display: block; }
  #fix-toast h3 { font-size: 0.85rem; color: var(--green); margin-bottom: 0.5rem; }
  #fix-toast ul { list-style: none; }
  #fix-toast li { font-size: 0.78rem; color: var(--muted); padding: 0.15rem 0; }
  #fix-toast li::before { content: '✓ '; color: var(--green); }
  #fix-toast li.failed::before { content: '✗ '; color: var(--critical); }
  .toast-close {
    position: absolute;
    top: 0.5rem;
    right: 0.75rem;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 1rem;
  }

  /* Section label */
  .section-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin: 1.5rem 0 0.75rem;
  }

  @media (max-width: 600px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .input-row { flex-direction: column; }
    .btn-scan { width: 100%; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    vibe-safe
    <span class="version">v1.0.0</span>
  </div>
  <span style="font-size:0.78rem;color:var(--muted)">Security audit for vibe-coded apps</span>
</header>

<main>

  <!-- Scan form -->
  <div class="scan-card">
    <h2>Scan a project</h2>

    <div class="input-row">
      <input type="text" id="path-input" placeholder="C:\\path\\to\\your\\project or /home/user/project" />
      <button class="btn-scan" id="scan-btn" onclick="runScan()">Run Scan</button>
    </div>

    <div class="probe-row">
      <label for="probe-input">Active probe URL <span style="color:var(--muted)">(optional — sends real attack payloads)</span></label>
      <div class="input-row">
        <input type="text" id="probe-input" placeholder="https://myapp.vercel.app" oninput="onProbeInput(this.value)" />
      </div>
    </div>

    <div class="probe-warning" id="probe-warning">
      <span>⚠</span>
      <div>
        <div style="margin-bottom:0.4rem"><strong>Active probe mode</strong> — real attack payloads will be sent to the URL above (SQL injection, XSS, auth bypass, rate limit flood).</div>
        <label><input type="checkbox" id="probe-agree"> I own this site or have written authorization to test it</label>
      </div>
    </div>

    <div class="options-row">
      <label class="checkbox-label">
        <input type="checkbox" id="fix-after"> Apply auto-fixes after scan
      </label>
    </div>
  </div>

  <!-- Loading -->
  <div id="loading">
    <div class="spinner"></div>
    <div id="loading-msg">Scanning...</div>
  </div>

  <!-- Error -->
  <div id="error-box"></div>

  <!-- Results -->
  <div id="results">

    <div class="scan-meta" id="scan-meta"></div>

    <div class="summary-grid" id="summary-grid"></div>

    <div class="alert-banner" id="alert-banner">
      ⚠ Critical or high-severity findings detected — fix before deploying.
    </div>

    <!-- Export bar -->
    <div class="export-bar">
      <span class="export-bar-label">📄 Export your full vulnerability report</span>
      <div style="display:flex;gap:0.75rem;align-items:center">
        <a class="btn-pdf" id="pdf-btn" href="/api/pdf" download="vibe-safe-report.pdf">⬇ Download PDF Report</a>
        <button class="btn-fix-all" id="fix-all-btn" onclick="applyAllFixes()">⚡ Apply all auto-fixes</button>
      </div>
    </div>

    <div class="actions-row">
      <h2>Findings</h2>
    </div>

    <div id="modules-container"></div>

    <div id="probes-section" class="probe-section" style="display:none">
      <div class="section-label">Active Probe Results</div>
      <div id="probes-container"></div>
    </div>

  </div>

</main>

<!-- Fix toast -->
<div id="fix-toast">
  <button class="toast-close" onclick="document.getElementById('fix-toast').classList.remove('visible')">×</button>
  <h3>Fixes applied</h3>
  <ul id="fix-list"></ul>
</div>

<script>
const MODULE_LABELS = {
  legal: 'Legal & Privacy',
  security: 'Security Basics',
  secrets: 'Secrets & API Keys',
  abuse: 'Abuse Prevention',
  environment: 'Environment & Config',
  'error-pages': 'Error Pages',
  auth: 'Authentication & Authorization',
};

const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW'];

function sevColor(s) {
  return { CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low' }[s] || 'low';
}

function escHtml(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function onProbeInput(val) {
  const w = document.getElementById('probe-warning');
  w.classList.toggle('visible', val.trim().length > 0);
}

async function runScan() {
  const pathVal = document.getElementById('path-input').value.trim();
  if (!pathVal) { showError('Please enter a project path.'); return; }

  const probeUrl = document.getElementById('probe-input').value.trim();
  const probeAgree = document.getElementById('probe-agree').checked;
  if (probeUrl && !probeAgree) {
    showError('You must confirm authorization before active probing.');
    return;
  }

  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  document.getElementById('loading').classList.add('visible');
  document.getElementById('error-box').classList.remove('visible');
  document.getElementById('results').classList.remove('visible');
  document.getElementById('loading-msg').textContent = probeUrl
    ? 'Running static scan + active probes…'
    : 'Scanning project files…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: pathVal, probeUrl: probeUrl || null }),
    });
    if (!res.ok) {
      const e = await res.json();
      throw new Error(e.error || 'Scan failed');
    }
    const result = await res.json();

    // Auto-fix if requested
    if (document.getElementById('fix-after').checked) {
      document.getElementById('loading-msg').textContent = 'Applying auto-fixes…';
      await applyAllFixes(true);
    }

    renderResults(result);
  } catch (err) {
    showError(err.message || String(err));
  } finally {
    document.getElementById('loading').classList.remove('visible');
    btn.disabled = false;
    btn.textContent = 'Run Scan';
  }
}

function renderResults(result) {
  // Meta
  const fws = result.frameworks && result.frameworks.length ? result.frameworks.join(', ') : '—';
  document.getElementById('scan-meta').innerHTML =
    '<span><strong>Path</strong>: ' + escHtml(result.rootPath) + '</span>' +
    '<span><strong>Type</strong>: ' + escHtml(result.projectType) + '</span>' +
    '<span><strong>Frameworks</strong>: ' + escHtml(fws) + '</span>' +
    '<span><strong>Duration</strong>: ' + result.scanDuration + 'ms</span>' +
    '<span><strong>Scanned</strong>: ' + new Date(result.timestamp).toLocaleTimeString() + '</span>';

  // Summary cards
  const hasCrit = result.criticalCount > 0;
  const hasHigh = result.highCount > 0;
  document.getElementById('summary-grid').innerHTML =
    summaryCard(result.criticalCount, 'CRITICAL', hasCrit ? 'has-critical' : '') +
    summaryCard(result.highCount,     'HIGH',     hasHigh ? 'has-high' : '') +
    summaryCard(result.mediumCount,   'MEDIUM',   '') +
    summaryCard(result.lowCount,      'LOW',      '');

  // Alert banner
  document.getElementById('alert-banner').classList.toggle('visible', hasCrit || hasHigh);

  // Fix-all button: only show if there are fixable findings
  const allFindings = result.auditResults.flatMap(r => r.findings);
  const hasFixable = allFindings.some(f => f.autoFixable);
  document.getElementById('fix-all-btn').style.display = hasFixable ? 'block' : 'none';

  // Modules
  const container = document.getElementById('modules-container');
  container.innerHTML = '';
  for (const ar of result.auditResults) {
    container.appendChild(renderModule(ar));
  }

  // Probes
  const probesSection = document.getElementById('probes-section');
  const probesContainer = document.getElementById('probes-container');
  probesContainer.innerHTML = '';
  if (result.probeResults && result.probeResults.length > 0) {
    probesSection.style.display = 'block';
    for (const p of result.probeResults) {
      probesContainer.appendChild(renderProbe(p));
    }
  } else {
    probesSection.style.display = 'none';
  }

  document.getElementById('results').classList.add('visible');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function summaryCard(count, label, extraClass) {
  const colorClass = 'count-' + label.toLowerCase();
  return '<div class="summary-card ' + extraClass + '">' +
    '<div class="count ' + colorClass + '">' + count + '</div>' +
    '<div class="label">' + label + '</div>' +
    '</div>';
}

function renderModule(ar) {
  const section = document.createElement('div');
  section.className = 'module-section';

  const sorted = [...ar.findings].sort((a,b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  for (const f of sorted) counts[f.severity]++;

  const badgesHtml = Object.entries(counts)
    .filter(([,n]) => n > 0)
    .map(([s, n]) => '<span class="badge badge-' + sevColor(s) + '">' + n + ' ' + s + '</span>')
    .join('');

  const okBadge = sorted.length === 0
    ? '<span class="badge badge-ok">✓ Clean</span>'
    : '';

  section.innerHTML =
    '<div class="module-header" onclick="toggleModule(this.parentElement)">' +
      '<span class="module-chevron">▶</span>' +
      '<span class="module-name">' + escHtml(MODULE_LABELS[ar.module] || ar.module) + '</span>' +
      '<div class="module-badges">' + (badgesHtml || okBadge) + '</div>' +
    '</div>' +
    '<div class="module-body" id="module-' + ar.module + '"></div>';

  // Auto-open if has critical/high
  if (counts.CRITICAL > 0 || counts.HIGH > 0) {
    section.classList.add('open');
  }

  const body = section.querySelector('#module-' + ar.module);
  if (sorted.length === 0) {
    body.innerHTML = '<div style="padding:1rem 1.25rem;font-size:0.82rem;color:var(--muted)">No issues found in this module.</div>';
  } else {
    for (const f of sorted) {
      body.appendChild(renderFinding(f));
    }
  }

  return section;
}

function renderFinding(f) {
  const el = document.createElement('div');
  el.className = 'finding-item';

  const fixBtn = f.autoFixable
    ? '<button class="finding-fixbtn" onclick="applyAllFixes()">⚡ Fix</button>'
    : '';

  el.innerHTML =
    '<div class="finding-header">' +
      '<span class="badge badge-' + sevColor(f.severity) + '">' + escHtml(f.severity) + '</span>' +
      '<span class="finding-id">' + escHtml(f.id) + '</span>' +
      '<span class="finding-title">' + escHtml(f.title) + '</span>' +
      fixBtn +
    '</div>' +
    (f.file ? '<div class="finding-file">' + escHtml(f.file) + (f.line ? ':' + f.line : '') + '</div>' : '') +
    (f.snippet ? '<div class="finding-snippet">' + escHtml(f.snippet) + '</div>' : '') +
    '<div class="finding-remediation">' + escHtml(f.remediation.split('\\n')[0]) + '</div>';

  return el;
}

function renderProbe(p) {
  const el = document.createElement('div');
  el.className = 'probe-item';

  const confirmedHtml = p.confirmed
    ? '<span class="probe-confirmed yes">CONFIRMED</span>'
    : '<span class="probe-confirmed no">not confirmed</span>';

  el.innerHTML =
    '<div class="probe-header">' +
      '<span class="badge badge-' + sevColor(p.severity) + '">' + escHtml(p.severity) + '</span>' +
      confirmedHtml +
      '<span style="font-size:0.85rem;font-weight:500;flex:1">' + escHtml(p.title) + '</span>' +
    '</div>' +
    '<div class="probe-detail">Endpoint: ' + escHtml(p.endpoint) + '</div>' +
    '<div class="probe-detail">Payload:  ' + escHtml(p.payload) + '</div>' +
    '<div class="probe-response">' + escHtml(p.response.slice(0, 400)) + '</div>' +
    '<div class="probe-fix">' + escHtml(p.remediation) + '</div>';

  return el;
}

function toggleModule(section) {
  section.classList.toggle('open');
}

async function applyAllFixes(silent) {
  const btn = document.getElementById('fix-all-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Fixing…'; }

  try {
    const res = await fetch('/api/fix', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (!res.ok) {
      const e = await res.json();
      if (!silent) showError(e.error || 'Fix failed');
      return;
    }
    const fixes = await res.json();
    if (!silent) showFixToast(fixes);
  } catch (err) {
    if (!silent) showError(String(err));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⚡ Apply all auto-fixes'; }
  }
}

function showFixToast(fixes) {
  const list = document.getElementById('fix-list');
  list.innerHTML = '';
  for (const fix of fixes) {
    const li = document.createElement('li');
    if (!fix.applied) li.className = 'failed';
    li.textContent = fix.description;
    list.appendChild(li);
  }
  const toast = document.getElementById('fix-toast');
  toast.classList.add('visible');
  setTimeout(() => toast.classList.remove('visible'), 8000);
}

function showError(msg) {
  const box = document.getElementById('error-box');
  box.textContent = '⚠ ' + msg;
  box.classList.add('visible');
}

// Pre-fill path with cwd on load
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && document.activeElement.id !== 'probe-input') {
    runScan();
  }
});
</script>
</body>
</html>`;
