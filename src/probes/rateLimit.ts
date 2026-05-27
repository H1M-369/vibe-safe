import axios from 'axios';
import { ProbeResult } from '../types';

export async function probe(baseUrl: string, requestCount = 50): Promise<ProbeResult[]> {
  const url = baseUrl.replace(/\/$/, '') + '/';
  const results: ProbeResult[] = [];

  const requests = Array.from({ length: requestCount }, () =>
    axios.get(url, { timeout: 10000, validateStatus: () => true })
      .then(r => r.status)
      .catch(() => 0)
  );

  const statuses = await Promise.all(requests);
  const has429 = statuses.some(s => s === 429);
  const successCount = statuses.filter(s => s >= 200 && s < 300).length;

  if (!has429 && successCount >= requestCount * 0.8) {
    results.push({
      id: 'PROBE-RATE-001',
      module: 'rate-limit',
      severity: 'HIGH',
      title: 'No rate limiting detected',
      confirmed: true,
      endpoint: url,
      payload: `${requestCount} rapid GET requests`,
      response: `${successCount}/${requestCount} requests returned 200 — no 429 responses observed`,
      remediation: 'Implement rate limiting. Express: express-rate-limit. FastAPI: slowapi. Set limits on all API endpoints, especially auth and AI-powered routes.',
    });
  }

  return results;
}
