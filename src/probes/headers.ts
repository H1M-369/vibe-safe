import axios from 'axios';
import { ProbeResult } from '../types';

interface HeaderCheck {
  name: string;
  severity: 'MEDIUM' | 'LOW';
  recommended: string;
}

const REQUIRED_HEADERS: HeaderCheck[] = [
  {
    name: 'content-security-policy',
    severity: 'MEDIUM',
    recommended: "default-src 'self'; script-src 'self'; object-src 'none';",
  },
  {
    name: 'x-frame-options',
    severity: 'MEDIUM',
    recommended: 'DENY',
  },
  {
    name: 'x-content-type-options',
    severity: 'MEDIUM',
    recommended: 'nosniff',
  },
  {
    name: 'strict-transport-security',
    severity: 'MEDIUM',
    recommended: 'max-age=31536000; includeSubDomains',
  },
  {
    name: 'referrer-policy',
    severity: 'LOW',
    recommended: 'strict-origin-when-cross-origin',
  },
  {
    name: 'permissions-policy',
    severity: 'LOW',
    recommended: 'geolocation=(), microphone=(), camera=()',
  },
];

export async function probe(baseUrl: string): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];

  let headers: Record<string, string> = {};
  try {
    const resp = await axios.get(baseUrl, { timeout: 10000, validateStatus: () => true });
    headers = Object.fromEntries(
      Object.entries(resp.headers).map(([k, v]) => [k.toLowerCase(), String(v)])
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    results.push({
      id: 'PROBE-HDR-000',
      module: 'headers',
      severity: 'MEDIUM',
      title: 'Could not connect to target for header check',
      confirmed: false,
      endpoint: baseUrl,
      payload: 'GET /',
      response: msg,
      remediation: 'Ensure the app is running and reachable at the specified URL.',
    });
    return results;
  }

  for (const check of REQUIRED_HEADERS) {
    if (!(check.name in headers)) {
      results.push({
        id: `PROBE-HDR-${check.name.toUpperCase().replace(/-/g, '_')}`,
        module: 'headers',
        severity: check.severity,
        title: `Missing HTTP security header: ${check.name}`,
        confirmed: true,
        endpoint: baseUrl,
        payload: 'GET /',
        response: `Header "${check.name}" not present in response`,
        remediation: `Add header: ${check.name}: ${check.recommended}`,
      });
    }
  }

  return results;
}
