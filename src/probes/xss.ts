import axios from 'axios';
import { ProbeResult } from '../types';

const PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><svg onload=alert(1)>",
  'javascript:alert(1)',
  '<iframe src="javascript:alert(1)">',
  '{{7*7}}',
];

function isReflected(payload: string, body: string): boolean {
  // Check if payload appears unencoded in response
  if (body.includes(payload)) return true;
  // Check for partial reflection (tag without encoding)
  if (payload.includes('<script>') && body.includes('<script>alert(1)</script>')) return true;
  if (payload.includes('onerror=') && body.includes('onerror=')) return true;
  if (payload.includes('onload=') && body.includes('onload=')) return true;
  return false;
}

export async function probe(baseUrl: string, endpoints?: string[]): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const base = baseUrl.replace(/\/$/, '');
  const confirmed = new Set<string>();

  const targets = endpoints && endpoints.length > 0
    ? endpoints
    : ['/search', '/api/search', '/', '/comment', '/api/comment'];

  const methods: Array<'GET' | 'POST'> = ['GET', 'POST'];
  const fields = ['q', 'query', 'search', 'input', 'message', 'comment', 'name'];

  for (const target of targets) {
    const url = base + target;

    for (const payload of PAYLOADS) {
      for (const method of methods) {
        for (const field of fields) {
          const endpointKey = `${url}:${field}`;
          if (confirmed.has(endpointKey)) continue;

          try {
            let resp;
            if (method === 'GET') {
              resp = await axios.get(url, {
                params: { [field]: payload },
                timeout: 8000,
                validateStatus: () => true,
              });
            } else {
              resp = await axios.post(url, { [field]: payload }, {
                timeout: 8000,
                validateStatus: () => true,
              });
            }

            const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
            const contentType = String(resp.headers['content-type'] ?? '');

            if (!contentType.includes('html') && !contentType.includes('json')) continue;
            if (!isReflected(payload, body)) continue;

            confirmed.add(endpointKey);
            results.push({
              id: 'PROBE-XSS-001',
              module: 'xss',
              severity: 'CRITICAL',
              title: `Reflected XSS confirmed at ${target} (field: ${field})`,
              confirmed: true,
              endpoint: url,
              payload: `${method} ${field}=${payload}`,
              response: `Payload reflected unencoded in response body: ${body.slice(0, 300)}`,
              remediation: 'HTML-encode all user input before rendering. In React: avoid dangerouslySetInnerHTML. In templates: use auto-escaping. Add Content-Security-Policy header.',
            });
          } catch { /* no reflection via this path */ }
        }
      }
    }
  }

  return results;
}
