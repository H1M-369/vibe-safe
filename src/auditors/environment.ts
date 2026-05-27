import * as fs from 'fs';
import * as path from 'path';
import {
  ScanContext, AuditResult, Finding,
} from '../types';
import {
  DEBUG_PATTERNS, SENSITIVE_LOG_PATTERNS, scanContentForPatterns,
} from '../utils/patternMatcher';
import { getFileContent } from '../utils/fileWalker';

async function checkEnvExample(ctx: ScanContext): Promise<Finding[]> {
  const hasEnv = ctx.files.some(f => /^\.env$/.test(f.relativePath));
  const hasExample = ctx.files.some(f => /\.env\.(example|sample|template)$/.test(f.relativePath));

  if (hasEnv && !hasExample) {
    return [{
      id: 'ENV-001',
      severity: 'MEDIUM',
      module: 'environment',
      title: '.env exists but no .env.example found',
      description: 'Without a .env.example file, new developers and deployment pipelines have no idea what environment variables the app needs. This causes broken deployments and makes onboarding painful.',
      remediation: 'Create .env.example with all keys but no values (KEY=). Commit it to git.',
      autoFixable: true,
      fixId: 'create-env-example',
    }];
  }
  return [];
}

async function checkNodeEnv(ctx: ScanContext): Promise<Finding[]> {
  if (ctx.projectType === 'python') return [];

  const pkgPath = path.join(ctx.rootPath, 'package.json');
  if (!fs.existsSync(pkgPath)) return [];

  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as Record<string, unknown>;
    const scripts = (pkg['scripts'] ?? {}) as Record<string, string>;
    const prodScripts = ['build', 'start', 'serve', 'preview'];
    const hasProdScript = prodScripts.some(s => s in scripts);
    if (!hasProdScript) return [];

    const deployFiles = ctx.files.filter(f =>
      /(?:Dockerfile|docker-compose\.yml|fly\.toml|vercel\.json|netlify\.toml|\.github\/workflows\/)/.test(f.relativePath)
    );

    for (const f of deployFiles) {
      const content = await getFileContent(f, ctx.contentCache);
      if (content.includes('NODE_ENV')) return [];
    }

    const hasNodeEnvInScripts = prodScripts.some(s =>
      scripts[s] && scripts[s].includes('NODE_ENV=production')
    );
    if (hasNodeEnvInScripts) return [];

    return [{
      id: 'ENV-002',
      severity: 'MEDIUM',
      module: 'environment',
      title: 'NODE_ENV=production not set in deployment config',
      description: 'Production-related scripts exist but NODE_ENV=production is not explicitly set in scripts or deployment config. Many libraries (Express, React) enable debug/verbose mode when NODE_ENV is not "production", leaking stack traces and slowing down the app.',
      remediation: 'Set NODE_ENV=production in your deployment platform (Vercel, Fly, Docker). In package.json: "start": "NODE_ENV=production node dist/index.js"',
      autoFixable: false,
    }];
  } catch {
    return [];
  }
}

async function checkDebugMode(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const configExtensions = new Set(['.ts', '.js', '.py', '.env', '.toml', '.yml', '.yaml', '.json']);

  for (const entry of ctx.files) {
    if (!configExtensions.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    findings.push(...scanContentForPatterns(content, DEBUG_PATTERNS, entry.relativePath, 'environment'));
    findings.push(...scanContentForPatterns(content, SENSITIVE_LOG_PATTERNS, entry.relativePath, 'environment'));
  }
  return findings;
}

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();
  const [envExample, nodeEnv, debug] = await Promise.all([
    checkEnvExample(ctx),
    checkNodeEnv(ctx),
    checkDebugMode(ctx),
  ]);

  return {
    module: 'environment',
    findings: [...envExample, ...nodeEnv, ...debug],
    duration: Date.now() - start,
  };
}
