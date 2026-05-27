import * as fs from 'fs';
import * as path from 'path';
import fg from 'fast-glob';
import ignore from 'ignore';
import { FileEntry } from '../types';

const SCAN_PATTERNS = [
  '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx',
  '**/*.py', '**/*.json', '**/*.md',
  '**/*.env', '**/*.env.*', '.env', '.env.*',
  '**/*.txt', '**/*.html', '**/*.yml', '**/*.yaml',
  '**/*.toml', '**/*.cfg', '**/*.ini',
  '.gitignore', '**/requirements.txt', '**/Dockerfile',
  '**/docker-compose.yml', '**/fly.toml', '**/vercel.json', '**/netlify.toml',
];

const IGNORE_DIRS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/coverage/**',
  '**/.next/**',
  '**/*.vibe-safe.bak',
  '**/vibe-safe-suggestions/**',
];

export const PUBLIC_DIRS = [
  'public/', 'static/', 'dist/', '.next/', 'next/public/',
  'assets/', 'client/', 'frontend/',
];

export function isPublicDirectory(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  return PUBLIC_DIRS.some(d => normalized.startsWith(d));
}

async function loadGitignoreFilter(rootPath: string): Promise<(path: string) => boolean> {
  const gitignorePath = path.join(rootPath, '.gitignore');
  try {
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    const ig = ignore().add(content);
    return (filePath: string) => !ig.ignores(filePath);
  } catch {
    return () => true;
  }
}

export async function walkProject(rootPath: string): Promise<FileEntry[]> {
  const gitignoreFilter = await loadGitignoreFilter(rootPath);

  const rawPaths = await fg(SCAN_PATTERNS, {
    cwd: rootPath,
    ignore: IGNORE_DIRS,
    dot: true,
    followSymbolicLinks: false,
    absolute: false,
  });

  const entries: FileEntry[] = [];

  for (const rel of rawPaths) {
    if (!gitignoreFilter(rel)) continue;
    const ext = path.extname(rel).toLowerCase();
    entries.push({
      absolutePath: path.join(rootPath, rel),
      relativePath: rel,
      extension: ext,
    });
  }

  return entries;
}

export async function getFileContent(
  entry: FileEntry,
  cache: Map<string, string>
): Promise<string> {
  if (cache.has(entry.absolutePath)) {
    return cache.get(entry.absolutePath)!;
  }
  try {
    const content = fs.readFileSync(entry.absolutePath, 'utf-8');
    cache.set(entry.absolutePath, content);
    return content;
  } catch {
    return '';
  }
}

export function isTestFile(relativePath: string): boolean {
  return /\.(test|spec)\.[tj]sx?$/.test(relativePath) ||
    /\/__tests__\//.test(relativePath) ||
    /\/tests?\//.test(relativePath);
}

export function isExampleFile(relativePath: string): boolean {
  return /\.(example|sample|template)/.test(relativePath);
}
