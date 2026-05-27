import axios from 'axios';
import { ProbeResult } from '../types';

// Expired JWT with valid structure but past expiry
const EXPIRED_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjMiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyMn0.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-KQ';

// JWT with alg:none attack
const ALG_NONE_JWT = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0.';

// Common protected endpoints
const PROTECTED_PATHS = [
  '/api/user',
  '/api/users',
  '/api/me',
  '/api/profile',
  '/api/admin',
  '/api/dashboard',
  '/dashboard',
  '/admin',
  '/profile',
];

async function tryEndpoint(url: string, headers: Record<string, string>): Promise<number> {
  try {
    const resp = await axios.get(url, { headers, timeout: 8000, validateStatus: () => true });
    return resp.status;
  } catch {
    return 0;
  }
}

export async function probe(baseUrl: string, endpoints?: string[]): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const base = baseUrl.replace(/\/$/, '');
  const targets = endpoints && endpoints.length > 0 ? endpoints : PROTECTED_PATHS;

  for (const target of targets) {
    const url = base + target;

    // First probe: no auth at all
    const statusNoAuth = await tryEndpoint(url, {});
    if (statusNoAuth === 0 || statusNoAuth === 404) continue;

    if (statusNoAuth === 200) {
      results.push({
        id: 'PROBE-AUTH-001',
        module: 'auth-bypass',
        severity: 'CRITICAL',
        title: `Protected endpoint accessible without authentication: ${target}`,
        confirmed: true,
        endpoint: url,
        payload: 'GET (no Authorization header)',
        response: `HTTP ${statusNoAuth} — endpoint returned success with no credentials`,
        remediation: 'Add authentication middleware to this route. Verify every protected route has auth middleware applied.',
      });
      continue;
    }

    if (statusNoAuth !== 401 && statusNoAuth !== 403) continue;

    // Second probe: expired JWT
    const statusExpired = await tryEndpoint(url, { Authorization: `Bearer ${EXPIRED_JWT}` });
    if (statusExpired === 200) {
      results.push({
        id: 'PROBE-AUTH-002',
        module: 'auth-bypass',
        severity: 'CRITICAL',
        title: `Auth bypass with expired JWT at ${target}`,
        confirmed: true,
        endpoint: url,
        payload: `Authorization: Bearer <expired JWT>`,
        response: `HTTP ${statusExpired} — accepted expired token`,
        remediation: 'Verify token expiry (exp claim) on every request. Use a well-maintained JWT library and never skip signature + expiry validation.',
      });
      continue;
    }

    // Third probe: alg:none attack
    const statusAlgNone = await tryEndpoint(url, { Authorization: `Bearer ${ALG_NONE_JWT}` });
    if (statusAlgNone === 200) {
      results.push({
        id: 'PROBE-AUTH-003',
        module: 'auth-bypass',
        severity: 'CRITICAL',
        title: `JWT alg:none attack succeeded at ${target}`,
        confirmed: true,
        endpoint: url,
        payload: `Authorization: Bearer <alg:none JWT>`,
        response: `HTTP ${statusAlgNone} — accepted unsigned token with alg:none`,
        remediation: 'Explicitly whitelist allowed JWT algorithms. Never accept "none" as algorithm. Use jwt.verify() with an explicit algorithms array: ["HS256"].',
      });
    }
  }

  return results;
}
