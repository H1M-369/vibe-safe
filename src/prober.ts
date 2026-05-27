import { ScanContext, ScanResult, ProbeResult } from './types';
import * as headersProbe from './probes/headers';
import * as sensitiveEndpointsProbe from './probes/sensitiveEndpoints';
import * as rateLimitProbe from './probes/rateLimit';
import * as sqlInjectionProbe from './probes/sqlInjection';
import * as xssProbe from './probes/xss';
import * as authBypassProbe from './probes/authBypass';
import * as errorPagesProbe from './probes/errorPages';

export async function runProbes(
  baseUrl: string,
  ctx: ScanContext,
  rateLimitCount = 50
): Promise<ProbeResult[]> {
  // Extract route paths from scanned source files for targeted probing
  const detectedRoutes = extractRoutes(ctx);

  console.log(`\n  Running 6 active probe modules against ${baseUrl}...`);

  const [
    headerResults,
    sensitiveResults,
    rateLimitResults,
    sqlResults,
    xssResults,
    authResults,
    errorPageResults,
  ] = await Promise.all([
    headersProbe.probe(baseUrl),
    sensitiveEndpointsProbe.probe(baseUrl),
    rateLimitProbe.probe(baseUrl, rateLimitCount),
    sqlInjectionProbe.probe(baseUrl, detectedRoutes),
    xssProbe.probe(baseUrl, detectedRoutes),
    authBypassProbe.probe(baseUrl, detectedRoutes),
    errorPagesProbe.probe(baseUrl),
  ]);

  return [
    ...headerResults,
    ...sensitiveResults,
    ...rateLimitResults,
    ...sqlResults,
    ...xssResults,
    ...authResults,
    ...errorPageResults,
  ];
}

export function mergeProbeResults(scanResult: ScanResult, probeResults: ProbeResult[]): ScanResult {
  const allCritical = probeResults.filter(p => p.severity === 'CRITICAL' && p.confirmed).length;
  const allHigh = probeResults.filter(p => p.severity === 'HIGH' && p.confirmed).length;
  const allMedium = probeResults.filter(p => p.severity === 'MEDIUM' && p.confirmed).length;
  const allLow = probeResults.filter(p => p.severity === 'LOW' && p.confirmed).length;

  return {
    ...scanResult,
    probeResults,
    totalFindings: scanResult.totalFindings + probeResults.filter(p => p.confirmed).length,
    criticalCount: scanResult.criticalCount + allCritical,
    highCount: scanResult.highCount + allHigh,
    mediumCount: scanResult.mediumCount + allMedium,
    lowCount: scanResult.lowCount + allLow,
  };
}

function extractRoutes(ctx: ScanContext): string[] {
  const routes = new Set<string>();
  const routePattern = /(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  const pythonRoutePattern = /@app\.route\s*\(\s*['"]([^'"]+)['"]/g;

  for (const entry of ctx.files) {
    const content = ctx.contentCache.get(entry.absolutePath);
    if (!content) continue;

    let match: RegExpExecArray | null;
    const jsRegex = new RegExp(routePattern.source, 'g');
    while ((match = jsRegex.exec(content)) !== null) {
      if (match[1]) routes.add(match[1]);
    }
    const pyRegex = new RegExp(pythonRoutePattern.source, 'g');
    while ((match = pyRegex.exec(content)) !== null) {
      if (match[1]) routes.add(match[1]);
    }
  }

  return Array.from(routes).filter(r => !r.includes(':') && !r.includes('<'));
}
