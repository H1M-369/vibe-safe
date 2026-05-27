import axios from 'axios';
import { ProbeResult } from '../types';

const PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1 --",
  "'; DROP TABLE users; --",
  "1' AND '1'='1",
  "' UNION SELECT null,null,null --",
  "admin'--",
  "1 OR 1=1",
];

const DB_ERROR_PATTERNS = [
  /syntax error/i,
  /sql.*error/i,
  /ORA-\d{5}/,
  /MySQL.*error/i,
  /pg_query\(\)/i,
  /sqlite.*exception/i,
  /microsoft.*sql.*server/i,
  /unclosed.*quotation/i,
  /unterminated.*string/i,
  /column.*does not exist/i,
  /table.*doesn.*exist/i,
  /SQLSTATE/i,
];

async function getBaseline(url: string, field: string): Promise<{ size: number; status: number }> {
  try {
    const resp = await axios.post(url, { [field]: 'normalinput' }, {
      timeout: 8000, validateStatus: () => true,
    });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
    return { size: body.length, status: resp.status };
  } catch {
    return { size: 0, status: 0 };
  }
}

export async function probe(baseUrl: string, endpoints?: string[]): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const base = baseUrl.replace(/\/$/, '');

  const targets = endpoints && endpoints.length > 0
    ? endpoints
    : ['/api/login', '/api/users', '/login', '/search', '/api/search'];

  const commonFields = ['username', 'email', 'id', 'query', 'search', 'name'];

  for (const target of targets) {
    const url = base + target;

    for (const field of commonFields) {
      const baseline = await getBaseline(url, field);
      if (baseline.status === 0) continue;

      for (const payload of PAYLOADS) {
        try {
          const resp = await axios.post(url, { [field]: payload }, {
            timeout: 8000, validateStatus: () => true,
          });

          const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);

          const hasDbError = DB_ERROR_PATTERNS.some(p => p.test(body));
          const unexpectedData = resp.status === 200 && body.length > baseline.size * 2 && baseline.size > 0;

          if (hasDbError || unexpectedData) {
            results.push({
              id: 'PROBE-SQL-001',
              module: 'sql-injection',
              severity: 'CRITICAL',
              title: `SQL Injection confirmed at ${target} (field: ${field})`,
              confirmed: true,
              endpoint: url,
              payload: `${field}=${payload}`,
              response: hasDbError
                ? `DB error in response: ${body.slice(0, 300)}`
                : `Unexpected data returned (${body.length} bytes vs baseline ${baseline.size} bytes): ${body.slice(0, 200)}`,
              remediation: 'Use parameterized queries immediately. Audit all database calls in this route handler.',
            });
            break;
          }
        } catch { /* network error = not injectable via this path */ }
      }
    }
  }

  return results;
}
