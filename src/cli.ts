#!/usr/bin/env node
import * as path from 'path';
import * as fs from 'fs';
import * as readline from 'readline';
import { Command } from 'commander';
import chalk from 'chalk';
import { runScan, runAudits } from './scanner';
import { runProbes, mergeProbeResults } from './prober';
import { printTerminalReport, writeMarkdownReport } from './report';
import { writePdfReport } from './pdfReport';
import { applyFixes } from './fixer';
import { ScanOptions } from './types';

const program = new Command();

program
  .name('vibe-safe')
  .description('Security audit & active probe tool for vibe-coded web applications')
  .version('1.0.0')
  .argument('[path]', 'Path to scan (defaults to current directory)')
  .option('--fix', 'Apply safe auto-fixes for detected issues')
  .option('--probe <url>', 'Send real attack payloads to a running app (requires authorization)')
  .option('--only <modules>', 'Comma-separated modules to run: legal,security,secrets,abuse,environment')
  .option('--severity <level>', 'Minimum severity to display: CRITICAL|HIGH|MEDIUM|LOW', 'LOW')
  .option('--output <file>', 'Markdown report output path', 'vibe-safe-report.md')
  .option('--json', 'Output raw JSON scan result to stdout')
  .option('--rate-limit-count <n>', 'Number of requests for rate limit probe', '50')
  .option('--pdf [file]', 'Export a PDF report (default: vibe-safe-report.pdf)')
  .option('--ui', 'Launch the web dashboard at http://localhost:4000')
  .action(async (targetPath: string | undefined, opts: Record<string, string | boolean | undefined>) => {
    if (opts['ui']) {
      const { startUI } = await import('./ui');
      await startUI();
      return;
    }

    const resolvedPath = path.resolve(targetPath ?? process.cwd());

    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
      console.error(chalk.red(`Error: "${resolvedPath}" is not a valid directory.`));
      process.exit(2);
    }

    const options: ScanOptions = {
      only: opts['only'] ? String(opts['only']).split(',').map(s => s.trim()) : undefined,
      severity: opts['severity'] as ScanOptions['severity'],
      fix: Boolean(opts['fix']),
      probeUrl: opts['probe'] ? String(opts['probe']) : undefined,
      output: String(opts['output'] ?? 'vibe-safe-report.md'),
      json: Boolean(opts['json']),
      rateLimitCount: parseInt(String(opts['rateLimitCount'] ?? '50'), 10),
    };

    try {
      // Authorization gate for active probing
      if (options.probeUrl) {
        await requireProbeAuthorization(options.probeUrl);
      }

      console.log(chalk.gray(`\n  Scanning ${resolvedPath}...`));

      // Static scan
      const ctx = await runScan(resolvedPath, options);
      let result = await runAudits(ctx, options);

      // Active probes
      if (options.probeUrl) {
        const probeResults = await runProbes(options.probeUrl, ctx, options.rateLimitCount);
        result = mergeProbeResults(result, probeResults);
      }

      // Output
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printTerminalReport(result, options);
      }

      // Write markdown report
      const outputPath = path.isAbsolute(options.output!)
        ? options.output!
        : path.join(process.cwd(), options.output!);
      await writeMarkdownReport(result, outputPath);
      console.log(chalk.gray(`  Report written to: ${outputPath}\n`));

      // Write PDF report if requested
      if (opts['pdf'] !== undefined) {
        const pdfFile = typeof opts['pdf'] === 'string' && opts['pdf']
          ? opts['pdf']
          : 'vibe-safe-report.pdf';
        const pdfPath = path.isAbsolute(pdfFile)
          ? pdfFile
          : path.join(process.cwd(), pdfFile);
        await writePdfReport(result, pdfPath);
        console.log(chalk.gray(`  PDF report written to: ${pdfPath}\n`));
      }

      // Auto-fix
      if (options.fix) {
        console.log(chalk.bold('\n  Applying auto-fixes...\n'));
        await applyFixes(result, ctx);
        console.log('');
      }

      // Exit code for CI integration
      if (result.criticalCount > 0 || result.highCount > 0) {
        process.exit(1);
      }
      process.exit(0);

    } catch (err) {
      console.error(chalk.red('\n  Error: ' + String(err)));
      process.exit(2);
    }
  });

async function requireProbeAuthorization(probeUrl: string): Promise<void> {
  console.log(chalk.bgYellow.black.bold('\n  ⚠  ACTIVE PROBE MODE'));
  console.log(chalk.yellow(`\n  This tool will send real attack payloads to: ${chalk.bold(probeUrl)}`));
  console.log(chalk.yellow('  These include SQL injection strings, XSS payloads, and auth bypass attempts.'));
  console.log(chalk.yellow('\n  You MUST have written authorization to test this target.'));
  console.log(chalk.yellow('  Unauthorized testing is illegal under CFAA, Computer Misuse Act, and similar laws.\n'));
  console.log(chalk.white(`  Type ${chalk.bold('I AGREE')} to confirm you own or have written authorization for this target:`));
  console.log('');

  const answer = await readLine('  > ');

  if (answer.trim() !== 'I AGREE') {
    console.log(chalk.gray('\n  Probe cancelled. No requests were sent.\n'));
    process.exit(3);
  }

  console.log(chalk.green('\n  Authorization confirmed. Starting probes...\n'));
}

function readLine(prompt: string): Promise<string> {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

program.parseAsync(process.argv).catch(err => {
  console.error(chalk.red('Fatal: ' + String(err)));
  process.exit(2);
});
