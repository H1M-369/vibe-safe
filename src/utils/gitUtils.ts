import simpleGit from 'simple-git';

export async function isGitRepo(rootPath: string): Promise<boolean> {
  try {
    const git = simpleGit(rootPath);
    return await git.checkIsRepo();
  } catch {
    return false;
  }
}

export async function getCommittedEnvFiles(rootPath: string): Promise<string[]> {
  try {
    const git = simpleGit(rootPath);
    const log = await git.raw([
      'log', '--all', '--name-only', '--diff-filter=A', '--pretty=format:', '--', '*.env', '*.env.*', '.env', '.env.*',
    ]);
    return log
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0 && /\.env/.test(l));
  } catch {
    return [];
  }
}

export async function wasFileEverCommitted(rootPath: string, filePath: string): Promise<boolean> {
  try {
    const git = simpleGit(rootPath);
    const log = await git.raw(['log', '--all', '--oneline', '--', filePath]);
    return log.trim().length > 0;
  } catch {
    return false;
  }
}

export function hasGitignoreEntry(gitignoreContent: string, pattern: string): boolean {
  return gitignoreContent.split('\n').some(line => {
    const trimmed = line.trim();
    return trimmed === pattern || trimmed === `/${pattern}` || trimmed === `${pattern}/`;
  });
}
