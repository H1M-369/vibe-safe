import * as fs from 'fs';
import * as path from 'path';
import { walkProject } from './utils/fileWalker';
import { isGitRepo } from './utils/gitUtils';
import {
  ScanContext, ScanResult, ScanOptions, AuditResult,
  ProjectType, FrameworkHint, AuditModule,
} from './types';
import * as legalAuditor from './auditors/legal';
import * as securityAuditor from './auditors/security';
import * as secretsAuditor from './auditors/secrets';
import * as abuseAuditor from './auditors/abuse';
import * as environmentAuditor from './auditors/environment';
import * as errorPagesAuditor from './auditors/errorPages';
import * as authAuditor from './auditors/auth';
import { getFileContent } from './utils/fileWalker';

async function detectProjectType(rootPath: string): Promise<ProjectType> {
  const hasNode = fs.existsSync(path.join(rootPath, 'package.json'));
  const hasPython = fs.existsSync(path.join(rootPath, 'requirements.txt')) ||
    fs.existsSync(path.join(rootPath, 'pyproject.toml')) ||
    fs.existsSync(path.join(rootPath, 'setup.py'));

  if (hasNode && hasPython) return 'mixed';
  if (hasNode) return 'node';
  if (hasPython) return 'python';
  return 'unknown';
}

async function detectFrameworks(ctx: Pick<ScanContext, 'rootPath' | 'files' | 'contentCache'>): Promise<FrameworkHint[]> {
  const hints: Set<FrameworkHint> = new Set();
  const pkgPath = path.join(ctx.rootPath, 'package.json');

  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as Record<string, unknown>;
      const deps = {
        ...((pkg['dependencies'] ?? {}) as Record<string, string>),
        ...((pkg['devDependencies'] ?? {}) as Record<string, string>),
      };
      if ('express' in deps) hints.add('express');
      if ('next' in deps) hints.add('nextjs');
      if ('@nestjs/core' in deps) hints.add('nestjs');
      if ('react' in deps || 'react-dom' in deps) hints.add('react');
    } catch { /* ignore parse errors */ }
  }

  for (const entry of ctx.files) {
    if (entry.extension !== '.py') continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (/import fastapi|from fastapi/i.test(content)) hints.add('fastapi');
    if (/import flask|from flask/i.test(content)) hints.add('flask');
  }

  const hasNextPages = ctx.files.some(f =>
    /(?:^|\/)pages\/_app\.[tj]sx?$/.test(f.relativePath) ||
    /(?:^|\/)app\/layout\.[tj]sx?$/.test(f.relativePath)
  );
  if (hasNextPages) hints.add('nextjs');

  return Array.from(hints);
}

async function buildScanContext(rootPath: string): Promise<ScanContext> {
  const files = await walkProject(rootPath);
  const contentCache = new Map<string, string>();
  const projectType = await detectProjectType(rootPath);
  const gitAvailable = await isGitRepo(rootPath);
  const frameworks = await detectFrameworks({ rootPath, files, contentCache });

  return { rootPath, files, projectType, frameworks, gitAvailable, contentCache };
}

const MODULE_MAP: Record<AuditModule, (ctx: ScanContext) => Promise<AuditResult>> = {
  legal: legalAuditor.audit,
  security: securityAuditor.audit,
  secrets: secretsAuditor.audit,
  abuse: abuseAuditor.audit,
  environment: environmentAuditor.audit,
  'error-pages': errorPagesAuditor.audit,
  auth: authAuditor.audit,
};

export async function runScan(rootPath: string, _options: ScanOptions): Promise<ScanContext> {
  return buildScanContext(rootPath);
}

export async function runAudits(ctx: ScanContext, options: ScanOptions): Promise<ScanResult> {
  const start = Date.now();

  const modules: AuditModule[] = options.only
    ? (options.only.filter(m => m in MODULE_MAP) as AuditModule[])
    : ['legal', 'security', 'secrets', 'abuse', 'environment', 'error-pages', 'auth'];

  const auditResults = await Promise.all(modules.map(m => MODULE_MAP[m](ctx)));

  const allFindings = auditResults.flatMap(r => r.findings);
  const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = allFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = allFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = allFindings.filter(f => f.severity === 'LOW').length;

  return {
    rootPath: ctx.rootPath,
    projectType: ctx.projectType,
    frameworks: ctx.frameworks,
    auditResults,
    probeResults: [],
    totalFindings: allFindings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    scanDuration: Date.now() - start,
    timestamp: new Date().toISOString(),
  };
}
