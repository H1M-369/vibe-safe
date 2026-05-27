import axios from 'axios';
import { ProbeResult } from '../types';

interface EndpointCheck {
  path: string;
  severity: 'CRITICAL' | 'HIGH';
  description: string;
  isCritical: boolean;
}

const SENSITIVE_PATHS: EndpointCheck[] = [
  { path: '/.env', severity: 'CRITICAL', description: '.env file exposed — contains all your secrets', isCritical: true },
  { path: '/.env.local', severity: 'CRITICAL', description: '.env.local file exposed', isCritical: true },
  { path: '/.git/config', severity: 'CRITICAL', description: '.git directory is publicly accessible — exposes repo structure and may allow full source download', isCritical: true },
  { path: '/.git/HEAD', severity: 'CRITICAL', description: '.git directory is publicly accessible', isCritical: true },
  { path: '/config.json', severity: 'HIGH', description: 'config.json exposed — may contain DB credentials or API keys', isCritical: false },
  { path: '/config.yml', severity: 'HIGH', description: 'config.yml exposed', isCritical: false },
  { path: '/__debug__', severity: 'HIGH', description: 'Debug endpoint exposed in production', isCritical: false },
  { path: '/api/admin', severity: 'HIGH', description: 'Admin API endpoint publicly reachable', isCritical: false },
  { path: '/admin', severity: 'HIGH', description: 'Admin panel reachable without apparent auth gate', isCritical: false },
  { path: '/metrics', severity: 'HIGH', description: 'Metrics endpoint exposed — leaks internal counters and performance data', isCritical: false },
  { path: '/api-docs', severity: 'HIGH', description: 'API documentation exposed — may help attackers map your API', isCritical: false },
  { path: '/swagger', severity: 'HIGH', description: 'Swagger UI exposed publicly', isCritical: false },
  { path: '/swagger.json', severity: 'HIGH', description: 'Swagger JSON exposed publicly', isCritical: false },
  { path: '/openapi.json', severity: 'HIGH', description: 'OpenAPI schema exposed publicly', isCritical: false },
  { path: '/phpinfo.php', severity: 'CRITICAL', description: 'phpinfo() page exposed — reveals full server configuration', isCritical: true },
  { path: '/server-status', severity: 'HIGH', description: 'Apache/Nginx server status page exposed', isCritical: false },
];

export async function probe(baseUrl: string): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const base = baseUrl.replace(/\/$/, '');

  const checks = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (check) => {
      const url = base + check.path;
      try {
        const resp = await axios.get(url, {
          timeout: 8000,
          validateStatus: () => true,
          maxRedirects: 0,
        });

        if (resp.status === 200) {
          const body = typeof resp.data === 'string'
            ? resp.data.slice(0, 300)
            : JSON.stringify(resp.data).slice(0, 300);

          return {
            id: `PROBE-EXPOSE-${check.path.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
            module: 'sensitive-endpoints' as const,
            severity: check.severity,
            title: `Sensitive path accessible: ${check.path}`,
            confirmed: true,
            endpoint: url,
            payload: `GET ${check.path}`,
            response: `HTTP 200 — ${body}`,
            remediation: check.isCritical
              ? `CRITICAL: Block access to ${check.path} immediately. Add to your web server deny rules or move the file out of the public root.`
              : `Restrict access to ${check.path} — require authentication or block via web server config.`,
          } satisfies ProbeResult;
        }
        return null;
      } catch {
        return null;
      }
    })
  );

  for (const result of checks) {
    if (result.status === 'fulfilled' && result.value !== null) {
      results.push(result.value);
    }
  }

  return results;
}
