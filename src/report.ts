import * as fs from 'fs';
import chalk from 'chalk';
import { ScanResult, Finding, ProbeResult, Severity, ScanOptions } from './types';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const SEVERITY_BADGE: Record<Severity, (s: string) => string> = {
  CRITICAL: (s) => chalk.bgRed.white(` ${s} `),
  HIGH: (s) => chalk.bgYellow.black(` ${s} `),
  MEDIUM: (s) => chalk.bgCyan.black(` ${s} `),
  LOW: (s) => chalk.bgGray.white(` ${s} `),
};

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  CRITICAL: (s) => chalk.red(s),
  HIGH: (s) => chalk.yellow(s),
  MEDIUM: (s) => chalk.cyan(s),
  LOW: (s) => chalk.gray(s),
};

const MODULE_LABELS: Record<string, string> = {
  legal: 'Legal & Privacy',
  security: 'Security Basics',
  secrets: 'Secrets & Keys',
  abuse: 'Abuse Prevention',
  environment: 'Environment',
  'error-pages': 'Error Pages',
  auth: 'Authentication & Authorization',
};

function pad(s: string, n: number): string {
  return s.padEnd(n).slice(0, n);
}

function printBanner(): void {
  console.log(chalk.bold.cyan('\n╔══════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║          vibe-safe  v1.0.0           ║'));
  console.log(chalk.bold.cyan('║   Security audit for vibe-coded apps ║'));
  console.log(chalk.bold.cyan('╚══════════════════════════════════════╝\n'));
}

function printFinding(f: Finding, options: ScanOptions): void {
  const minSeverity = options.severity ?? 'LOW';
  const minIndex = SEVERITY_ORDER.indexOf(minSeverity);
  if (SEVERITY_ORDER.indexOf(f.severity) > minIndex) return;

  const badge = SEVERITY_BADGE[f.severity](f.severity);
  console.log(`  ${badge} ${chalk.bold(f.id)} — ${f.title}`);
  if (f.file) {
    const loc = f.line ? `${f.file}:${f.line}` : f.file;
    console.log(`         ${chalk.gray('File:')} ${chalk.underline(loc)}`);
  }
  if (f.snippet) {
    console.log(`         ${chalk.gray('>')} ${chalk.yellow(f.snippet)}`);
  }
  console.log(`         ${chalk.green('Fix:')} ${f.remediation}`);
  if (f.autoFixable && !options.fix) {
    console.log(`         ${chalk.cyan('→ Run with --fix to auto-apply this fix')}`);
  }
  console.log('');
}

function printProbeResult(p: ProbeResult): void {
  if (!p.confirmed) return;
  const badge = SEVERITY_BADGE[p.severity](p.severity);
  console.log(`  ${badge} ${chalk.bold(p.id)} — ${p.title}`);
  console.log(`         ${chalk.gray('Endpoint:')} ${p.endpoint}`);
  console.log(`         ${chalk.gray('Payload:')}  ${chalk.yellow(p.payload)}`);
  console.log(`         ${chalk.gray('Response:')} ${p.response.slice(0, 150)}`);
  console.log(`         ${chalk.green('Fix:')} ${p.remediation}`);
  console.log('');
}

function printSummaryTable(result: ScanResult): void {
  const col = (n: number, sev: Severity) => {
    const s = String(n).padStart(3);
    return n === 0 ? chalk.gray(s) : SEVERITY_COLOR[sev](s);
  };

  console.log(chalk.bold('\n  Audit Summary'));
  console.log(`  ${'Module'.padEnd(20)} ${'CRIT'.padStart(5)} ${'HIGH'.padStart(5)} ${'MED'.padStart(5)} ${'LOW'.padStart(5)}`);
  console.log(`  ${'─'.repeat(44)}`);

  for (const ar of result.auditResults) {
    const label = pad(MODULE_LABELS[ar.module] ?? ar.module, 20);
    const c = ar.findings.filter(f => f.severity === 'CRITICAL').length;
    const h = ar.findings.filter(f => f.severity === 'HIGH').length;
    const m = ar.findings.filter(f => f.severity === 'MEDIUM').length;
    const l = ar.findings.filter(f => f.severity === 'LOW').length;
    console.log(`  ${label} ${col(c,'CRITICAL')} ${col(h,'HIGH')} ${col(m,'MEDIUM')} ${col(l,'LOW')}`);
  }

  if (result.probeResults.length > 0) {
    const confirmed = result.probeResults.filter(p => p.confirmed);
    const c = confirmed.filter(p => p.severity === 'CRITICAL').length;
    const h = confirmed.filter(p => p.severity === 'HIGH').length;
    const m = confirmed.filter(p => p.severity === 'MEDIUM').length;
    const l = confirmed.filter(p => p.severity === 'LOW').length;
    console.log(`  ${'─'.repeat(44)}`);
    console.log(`  ${'Active Probes'.padEnd(20)} ${col(c,'CRITICAL')} ${col(h,'HIGH')} ${col(m,'MEDIUM')} ${col(l,'LOW')}`);
  }

  console.log(`  ${'─'.repeat(44)}`);
  console.log(
    `  ${'TOTAL'.padEnd(20)} ${col(result.criticalCount,'CRITICAL')} ${col(result.highCount,'HIGH')} ${col(result.mediumCount,'MEDIUM')} ${col(result.lowCount,'LOW')}\n`
  );
}

export function printTerminalReport(result: ScanResult, options: ScanOptions): void {
  printBanner();

  console.log(`  ${chalk.gray('Project:')}   ${result.rootPath}`);
  console.log(`  ${chalk.gray('Scanned:')}   ${result.timestamp}`);
  console.log(`  ${chalk.gray('Type:')}      ${result.projectType}`);
  if (result.frameworks.length > 0) {
    console.log(`  ${chalk.gray('Frameworks:')} ${result.frameworks.join(', ')}`);
  }
  console.log(`  ${chalk.gray('Duration:')}  ${result.scanDuration}ms`);

  printSummaryTable(result);

  for (const ar of result.auditResults) {
    if (ar.findings.length === 0) continue;
    const sorted = [...ar.findings].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
    console.log(chalk.bold(`\n  ── ${MODULE_LABELS[ar.module] ?? ar.module} ──`));
    for (const f of sorted) printFinding(f, options);
  }

  if (result.probeResults.length > 0) {
    const confirmed = result.probeResults.filter(p => p.confirmed);
    if (confirmed.length > 0) {
      console.log(chalk.bold('\n  ── Active Probe Results (CONFIRMED) ──'));
      for (const p of confirmed) printProbeResult(p);
    }
  }

  if (result.criticalCount > 0 || result.highCount > 0) {
    console.log(chalk.bgRed.white.bold(`\n  ⚠ ${result.criticalCount} CRITICAL and ${result.highCount} HIGH findings — fix before deploying.\n`));
  } else {
    console.log(chalk.green('\n  ✓ No CRITICAL or HIGH findings.\n'));
  }
}

export async function writeMarkdownReport(result: ScanResult, outputPath: string): Promise<void> {
  const lines: string[] = [];

  lines.push('# vibe-safe Security Report\n');
  lines.push(`**Project:** \`${result.rootPath}\`  `);
  lines.push(`**Scanned:** ${result.timestamp}  `);
  lines.push(`**Type:** ${result.projectType}  `);
  if (result.frameworks.length > 0) {
    lines.push(`**Frameworks:** ${result.frameworks.join(', ')}  `);
  }
  lines.push(`**Duration:** ${result.scanDuration}ms  `);
  lines.push(`**Total Findings:** ${result.totalFindings} (${result.criticalCount} CRITICAL, ${result.highCount} HIGH, ${result.mediumCount} MEDIUM, ${result.lowCount} LOW)\n`);

  lines.push('## Summary\n');
  lines.push('| Module | CRITICAL | HIGH | MEDIUM | LOW |');
  lines.push('|--------|----------|------|--------|-----|');
  for (const ar of result.auditResults) {
    const c = ar.findings.filter(f => f.severity === 'CRITICAL').length;
    const h = ar.findings.filter(f => f.severity === 'HIGH').length;
    const m = ar.findings.filter(f => f.severity === 'MEDIUM').length;
    const l = ar.findings.filter(f => f.severity === 'LOW').length;
    lines.push(`| ${MODULE_LABELS[ar.module] ?? ar.module} | ${c} | ${h} | ${m} | ${l} |`);
  }
  lines.push('');

  lines.push('## Static Analysis Findings\n');
  for (const ar of result.auditResults) {
    if (ar.findings.length === 0) continue;
    lines.push(`### ${MODULE_LABELS[ar.module] ?? ar.module}\n`);
    const sorted = [...ar.findings].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
    for (const f of sorted) {
      lines.push(`#### [${f.severity}] ${f.id} · ${f.title}\n`);
      if (f.file) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        lines.push(`**File:** \`${loc}\`  `);
      }
      if (f.snippet) {
        lines.push(`**Code:**\n\`\`\`\n${f.snippet}\n\`\`\`\n`);
      }
      lines.push(`**Description:** ${f.description}  `);
      lines.push(`**Remediation:** ${f.remediation}\n`);
      if (f.autoFixable) {
        lines.push('> Auto-fixable with `vibe-safe --fix`\n');
      }
      lines.push('---\n');
    }
  }

  if (result.probeResults.length > 0) {
    lines.push('## Active Probe Results\n');
    const confirmed = result.probeResults.filter(p => p.confirmed);
    if (confirmed.length === 0) {
      lines.push('No confirmed vulnerabilities from active probing.\n');
    } else {
      for (const p of confirmed) {
        lines.push(`#### [${p.severity}] ${p.id} · ${p.title}\n`);
        lines.push(`**Endpoint:** \`${p.endpoint}\`  `);
        lines.push(`**Payload:** \`${p.payload}\`  `);
        lines.push(`**Response:** ${p.response.slice(0, 300)}  `);
        lines.push(`**Remediation:** ${p.remediation}\n`);
        lines.push('---\n');
      }
    }
  }

  lines.push(`\n*Generated by [vibe-safe](https://github.com/vibe-safe/vibe-safe) — ${result.timestamp}*`);

  fs.writeFileSync(outputPath, lines.join('\n'), 'utf-8');
}
