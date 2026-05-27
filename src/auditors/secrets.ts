import * as fs from 'fs';
import * as path from 'path';
import {
  ScanContext, AuditResult, Finding,
} from '../types';
import {
  SECRET_PATTERNS, scanContentForPatterns,
} from '../utils/patternMatcher';
import {
  getFileContent, isTestFile, isExampleFile, isPublicDirectory,
} from '../utils/fileWalker';
import { getCommittedEnvFiles, hasGitignoreEntry } from '../utils/gitUtils';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py']);

async function checkHardcodedSecrets(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;
    if (isExampleFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const hits = scanContentForPatterns(content, SECRET_PATTERNS, entry.relativePath, 'secrets');
    findings.push(...hits);
  }
  return findings;
}

async function checkEnvInGitignore(ctx: ScanContext): Promise<Finding[]> {
  const gitignorePath = path.join(ctx.rootPath, '.gitignore');
  try {
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    if (!hasGitignoreEntry(content, '.env')) {
      return [{
        id: 'SCR-010',
        severity: 'HIGH',
        module: 'secrets',
        title: '.env file is not in .gitignore',
        description: 'Your .env file is not listed in .gitignore. If you commit it — even once — all secrets inside are exposed in git history forever.',
        file: '.gitignore',
        remediation: 'Add ".env" and ".env.local" to .gitignore immediately.',
        autoFixable: true,
        fixId: 'add-env-gitignore',
      }];
    }
  } catch {
    const envExists = fs.existsSync(path.join(ctx.rootPath, '.env'));
    if (envExists) {
      return [{
        id: 'SCR-010',
        severity: 'HIGH',
        module: 'secrets',
        title: 'No .gitignore found and .env exists',
        description: 'A .env file exists but there is no .gitignore to prevent it from being committed.',
        remediation: 'Create a .gitignore and add ".env" to it.',
        autoFixable: true,
        fixId: 'add-env-gitignore',
      }];
    }
  }
  return [];
}

async function checkEnvInGitHistory(ctx: ScanContext): Promise<Finding[]> {
  if (!ctx.gitAvailable) return [];
  const committedFiles = await getCommittedEnvFiles(ctx.rootPath);
  if (committedFiles.length === 0) return [];

  return [{
    id: 'SCR-011',
    severity: 'CRITICAL',
    module: 'secrets',
    title: '.env file was committed to git history',
    description: `The following .env files were found in git history: ${committedFiles.join(', ')}. Anyone with access to this repo can read every secret that was ever in those files.`,
    remediation: '1. Rotate ALL secrets that were ever in those files immediately. 2. Remove from history using "git filter-repo --path .env --invert-paths" or BFG Repo Cleaner. 3. Force-push to overwrite remote history. 4. Notify your team.',
    autoFixable: false,
  }];
}

async function checkFrontendSecrets(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const entry of ctx.files) {
    if (!isPublicDirectory(entry.relativePath)) continue;
    if (!SOURCE_EXTENSIONS.has(entry.extension) && entry.extension !== '.html') continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const hits = scanContentForPatterns(content, SECRET_PATTERNS, entry.relativePath, 'secrets');
    for (const hit of hits) {
      findings.push({
        ...hit,
        id: 'SCR-012',
        severity: 'CRITICAL',
        title: `Secret exposed in frontend/public file: ${hit.title}`,
        description: `${hit.description} This file is served to all users — the secret is immediately readable by anyone.`,
      });
    }
  }
  return findings;
}

async function checkSensitiveResponseFields(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const responsePattern = /(?:res\.json|return\s+{|JSON\.stringify)\s*\([^)]*(?:password|passwd|secret|token|hash|salt|ssn|creditCard)[^)]*\)/gi;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const regex = new RegExp(responsePattern.source, 'gi');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const line = content.slice(0, match.index).split('\n').length;
      findings.push({
        id: 'SCR-013',
        severity: 'HIGH',
        module: 'secrets',
        title: 'API response may include sensitive fields (password/token/secret)',
        description: 'A JSON response or return value appears to include sensitive field names. Exposing these to clients is a data leak.',
        file: entry.relativePath,
        line,
        snippet: match[0].trim().slice(0, 120),
        remediation: 'Explicitly select only the fields you need to return. Use a serializer/DTO that excludes sensitive columns.',
        autoFixable: false,
      });
    }
  }
  return findings;
}

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();
  const [hardcoded, gitignore, gitHistory, frontend, response] = await Promise.all([
    checkHardcodedSecrets(ctx),
    checkEnvInGitignore(ctx),
    checkEnvInGitHistory(ctx),
    checkFrontendSecrets(ctx),
    checkSensitiveResponseFields(ctx),
  ]);

  return {
    module: 'secrets',
    findings: [...hardcoded, ...gitignore, ...gitHistory, ...frontend, ...response],
    duration: Date.now() - start,
  };
}
