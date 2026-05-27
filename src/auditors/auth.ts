import {
  ScanContext, AuditResult, Finding,
} from '../types';
import { getFileContent, isTestFile } from '../utils/fileWalker';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py']);
const AUTH_FILE_PATTERN = /(?:auth|login|register|signup|sign-up|password|user|account|session)/i;

// ── AUTH-001: Weak / missing password hashing ─────────────────────────────────

const SECURE_HASH_LIBS = [
  'bcrypt', 'bcryptjs', 'argon2', 'scrypt', 'pbkdf2',
  'passlib', 'werkzeug.security',
];

const WEAK_HASH_DEFS: Array<{ regex: RegExp; algo: string }> = [
  { regex: /createHash\s*\(\s*['"]md5['"]/gi,  algo: 'MD5' },
  { regex: /createHash\s*\(\s*['"]sha1['"]/gi, algo: 'SHA-1' },
  { regex: /md5\s*\(\s*(?:\$?password|passwd|pwd)/gi,  algo: 'MD5' },
  { regex: /sha1\s*\(\s*(?:\$?password|passwd|pwd)/gi, algo: 'SHA-1' },
  { regex: /hashlib\s*\.\s*md5\s*\(/gi,  algo: 'MD5 (Python)' },
  { regex: /hashlib\s*\.\s*sha1\s*\(/gi, algo: 'SHA-1 (Python)' },
];

async function checkPasswordHashing(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  let hasSecureLib = false;
  let hasAuthCode   = false;
  let authFile: string | undefined;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (SECURE_HASH_LIBS.some(lib => content.includes(lib))) { hasSecureLib = true; }
    if (AUTH_FILE_PATTERN.test(entry.relativePath) ||
        /(?:password|passwd|createUser|registerUser|hashPassword)/i.test(content)) {
      hasAuthCode = true;
      authFile = entry.relativePath;
    }
  }

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const { regex, algo } of WEAK_HASH_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-001',
          severity: 'CRITICAL',
          module: 'auth',
          title: `Weak password hashing: ${algo}`,
          description: `${algo} is a fast checksum algorithm — not designed for passwords. Attackers with a GPU can crack billions of ${algo} hashes per second using rainbow tables or brute force.`,
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation: 'Replace with bcrypt: npm install bcryptjs  →  const hash = await bcrypt.hash(password, 12). Verify with bcrypt.compare(plain, hash).',
          autoFixable: false,
        });
      }
    }
  }

  // Auth code present but no secure hashing lib and no explicit weak hash found
  if (hasAuthCode && !hasSecureLib && findings.length === 0) {
    findings.push({
      id: 'AUTH-001',
      severity: 'HIGH',
      module: 'auth',
      title: 'No secure password hashing library detected',
      description: 'Auth-related code found but no bcrypt, argon2, or scrypt library is imported. Passwords may be stored as plain text or with a weak algorithm.',
      file: authFile,
      remediation: 'Install bcryptjs and hash every password before storage: const hash = await bcrypt.hash(password, 12). Verify with bcrypt.compare(input, hash).',
      autoFixable: false,
    });
  }

  return findings;
}

// ── AUTH-002: Hardcoded credentials ──────────────────────────────────────────

const HARDCODED_CRED_DEFS: Array<{ regex: RegExp; title: string }> = [
  {
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"](?:admin|password|123456|secret|changeme|test|default|letmein|qwerty|abc123|pass|pass123|root|toor|administrator|welcome)['"]/gi,
    title: 'Hardcoded weak/default password in source',
  },
  {
    regex: /(?:adminPassword|admin_password|ADMIN_PASSWORD|rootPassword|ROOT_PASSWORD)\s*[:=]\s*['"][^'"]{1,40}['"]/gi,
    title: 'Hardcoded admin password in source',
  },
  {
    regex: /(?:defaultPassword|DEFAULT_PASSWORD|initialPassword|INITIAL_PASSWORD)\s*[:=]\s*['"][^'"]{1,40}['"]/gi,
    title: 'Hardcoded default/initial password in source',
  },
];

async function checkHardcodedCredentials(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const { regex, title } of HARDCODED_CRED_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-002',
          severity: 'CRITICAL',
          module: 'auth',
          title,
          description: 'A hardcoded credential was found in source code. Anyone with repo access — including a leaked GitHub repo — can read it immediately.',
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation: 'Move to environment variables: process.env.ADMIN_PASSWORD. Set in .env (never commit .env to git).',
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// ── AUTH-003 & AUTH-004: JWT security ─────────────────────────────────────────

const JWT_WEAK_SECRET_DEFS = [
  /(?:jwt\.sign|new SignJWT)\s*\([^)]*,\s*['"](?:secret|changeme|your[-_]?secret|mysecret|jwt[-_]?secret|supersecret|password|123456|abc123|key|mykey|jwtkey|tokenkey)['"]/gi,
  /(?:JWT_SECRET|JWT_KEY|TOKEN_SECRET)\s*[:=]\s*['"](?:secret|changeme|your[-_]?secret|mysecret|jwt[-_]?secret|supersecret|password|123456|abc123|key)['"]/gi,
];

async function checkJwtSecurity(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    if (!content.includes('jwt') && !content.includes('JWT')) continue;

    // AUTH-003: weak/hardcoded secret
    for (const pattern of JWT_WEAK_SECRET_DEFS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-003',
          severity: 'CRITICAL',
          module: 'auth',
          title: 'JWT signed with weak or hardcoded secret',
          description: 'A guessable string is used as the JWT signing secret. Anyone who knows the secret can forge valid tokens for any user — including admin accounts.',
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation: 'Use a random 256-bit secret: crypto.randomBytes(32).toString("hex"). Store in JWT_SECRET env var and never commit it.',
          autoFixable: false,
        });
      }
    }

    // AUTH-004: missing expiresIn
    const jwtSignRe = /jwt\.sign\s*\(([^;]{1,400})\)/gs;
    let signMatch: RegExpExecArray | null;
    while ((signMatch = jwtSignRe.exec(content)) !== null) {
      const body = signMatch[1] ?? '';
      if (!body.includes('expiresIn') && !body.includes('"exp"') && !body.includes("'exp'")) {
        const line = content.slice(0, signMatch.index).split('\n').length;
        findings.push({
          id: 'AUTH-004',
          severity: 'HIGH',
          module: 'auth',
          title: 'JWT token has no expiry (expiresIn missing)',
          description: 'jwt.sign() called without expiresIn. Tokens with no expiry are valid forever — a stolen token can never be invalidated without rotating the signing secret.',
          file: entry.relativePath,
          line,
          snippet: signMatch[0].trim().slice(0, 100),
          remediation: 'Always set expiresIn: jwt.sign(payload, secret, { expiresIn: "15m" }). Pair short-lived access tokens with a refresh token strategy.',
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// ── AUTH-005: Admin routes without role checks ────────────────────────────────

const ADMIN_ROUTE_DEFS = [
  /(?:router|app)\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*['"`][^'"`]*(?:\/admin|\/dashboard|\/manage|\/management)[^'"`]*['"`]/gi,
  /@(?:Get|Post|Put|Delete|Patch)\s*\(\s*['"`][^'"`]*admin[^'"`]*['"`]\s*\)/gi,
  /@app\.route\s*\(\s*['"][^'"]*\/admin[^'"]*['"]/gi,
];

const ROLE_CHECK_DEFS = [
  /isAdmin|requireAdmin|adminOnly|checkAdmin|hasRole|requireRole|checkPermission|authoriz/i,
  /Roles\s*\.|@Roles\s*\(|@RequiresRole|PermissionGuard|RolesGuard/i,
  /user\.role\s*===|user\.isAdmin|req\.user\.role|user\.permissions/i,
  /RBAC|role-based|roleMiddleware/i,
];

async function checkAdminRouteProtection(ctx: ScanContext): Promise<Finding[]> {
  let hasAdminRoutes = false;
  let hasRoleChecks  = false;
  let adminFile: string | undefined;
  let adminLine: number | undefined;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    for (const pattern of ADMIN_ROUTE_DEFS) {
      const re = new RegExp(pattern.source, pattern.flags);
      const match = re.exec(content);
      if (match) {
        hasAdminRoutes = true;
        adminFile = entry.relativePath;
        adminLine = content.slice(0, match.index).split('\n').length;
        break;
      }
    }

    if (ROLE_CHECK_DEFS.some(p => p.test(content))) hasRoleChecks = true;
  }

  if (hasAdminRoutes && !hasRoleChecks) {
    return [{
      id: 'AUTH-005',
      severity: 'HIGH',
      module: 'auth',
      title: 'Admin routes found without role/permission checks',
      description: 'Admin or management routes detected but no RBAC, role-checking middleware (isAdmin, requireRole), or permission guards found. Any authenticated user may reach admin functionality.',
      file: adminFile,
      line: adminLine,
      remediation: 'Wrap all admin routes with a role middleware: app.use("/admin", requireAuth, requireRole("admin"), adminRouter). Never rely on obscurity (hidden URL) alone.',
      autoFixable: false,
    }];
  }

  return [];
}

// ── AUTH-006: Mass assignment ─────────────────────────────────────────────────

const MASS_ASSIGN_DEFS: Array<{ regex: RegExp; desc: string }> = [
  {
    regex: /\.(?:create|update|save|insert)\s*\(\s*\.\.\.\s*req\.body/gi,
    desc: 'Spreading req.body directly into a DB operation',
  },
  {
    regex: /Object\.assign\s*\(\s*\w[\w.]*\s*,\s*req\.body\s*\)/gi,
    desc: 'Object.assign(model, req.body) allows attacker to set any field',
  },
  {
    regex: /(?:User|Admin|Account|Profile|Member)\s*\.\s*(?:create|update|findOneAndUpdate)\s*\(\s*req\.body/gi,
    desc: 'Mongoose/Sequelize model operation using raw req.body',
  },
  {
    regex: /prisma\s*\.\s*\w+\s*\.\s*(?:create|update|upsert)\s*\(\s*\{\s*data\s*:\s*req\.body/gi,
    desc: 'Prisma mutation using raw req.body as data payload',
  },
];

async function checkMassAssignment(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const { regex, desc } of MASS_ASSIGN_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-006',
          severity: 'HIGH',
          module: 'auth',
          title: 'Mass assignment — req.body passed directly to database',
          description: `${desc}. An attacker can add "isAdmin": true or "role": "admin" to the request body and have it written to the database, granting themselves elevated privileges.`,
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation: 'Explicitly pick only safe fields: const { name, email } = req.body. Never pass req.body directly to create/update. Use an allowlist/DTO.',
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// ── AUTH-007: Insecure session cookies ────────────────────────────────────────

async function checkSessionCookies(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const usesSession =
      content.includes('express-session') ||
      content.includes('cookie-session') ||
      /session\s*\(\s*\{/.test(content);

    if (!usesSession) continue;

    // Try to isolate the cookie config block; fall back to full file
    const cookieCfgMatch = /cookie\s*:\s*\{([^}]{0,400})\}/s.exec(content);
    const scope = cookieCfgMatch ? cookieCfgMatch[1] : content;

    const missing: string[] = [];
    if (!/httpOnly\s*:\s*true/i.test(scope))  missing.push('httpOnly: true');
    if (!/secure\s*:\s*true/i.test(scope))    missing.push('secure: true');
    if (!/sameSite/i.test(scope))             missing.push("sameSite: 'strict'");

    if (missing.length > 0) {
      const lineIdx = content.split('\n').findIndex(
        l => l.includes('express-session') || l.includes('cookie-session')
      );
      findings.push({
        id: 'AUTH-007',
        severity: 'HIGH',
        module: 'auth',
        title: `Session cookie missing security flags: ${missing.join(', ')}`,
        description: [
          missing.includes('httpOnly: true')  && 'Without httpOnly, JavaScript can steal the cookie (XSS session hijack).',
          missing.includes('secure: true')    && 'Without secure, the cookie is sent over plain HTTP and can be intercepted.',
          missing.includes("sameSite: 'strict'") && 'Without sameSite, cross-site requests can carry the session cookie (CSRF).',
        ].filter(Boolean).join(' '),
        file: entry.relativePath,
        line: lineIdx >= 0 ? lineIdx + 1 : undefined,
        remediation: "Set all flags: cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 86400000 }",
        autoFixable: false,
      });
    }
  }

  return findings;
}

// ── AUTH-008: Missing password complexity ─────────────────────────────────────

const REGISTER_ROUTE_DEFS = [
  /(?:router|app)\s*\.\s*post\s*\(\s*['"`][^'"`]*(?:register|signup|sign-up|create[-_]?account)[^'"`]*['"`]/gi,
  /@app\.route\s*\(\s*['"][^'"]*(?:register|signup)[^'"]*['"].*POST/gi,
  /def\s+(?:register|signup|create_user)\s*\(/gi,
  /async\s+function\s+(?:register|signup|createUser)\s*\(/gi,
];

const PASSWORD_COMPLEXITY_DEFS = [
  /password\.length\s*[<>]=?\s*\d+/i,
  /minLength.*password|password.*minLength/i,
  /\.min\s*\(\s*\d+\s*\)/i,                     // zod/yup .min(8)
  /min_length\s*=\s*\d+/i,                       // Python validators
  /password.*regex|regex.*password/i,
  /PASS(?:WORD)?_MIN|MIN_PASS/i,
];

async function checkPasswordComplexity(ctx: ScanContext): Promise<Finding[]> {
  let hasRegisterRoute = false;
  let hasComplexity    = false;
  let registerFile: string | undefined;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    for (const pattern of REGISTER_ROUTE_DEFS) {
      if (new RegExp(pattern.source, pattern.flags).exec(content)) {
        hasRegisterRoute = true;
        registerFile = entry.relativePath;
        break;
      }
    }

    if (PASSWORD_COMPLEXITY_DEFS.some(p => p.test(content))) hasComplexity = true;
  }

  if (hasRegisterRoute && !hasComplexity) {
    return [{
      id: 'AUTH-008',
      severity: 'MEDIUM',
      module: 'auth',
      title: 'No password complexity requirements detected',
      description: 'A registration route was found but no minimum length or complexity check on passwords. Users can create accounts with passwords like "a" or "1", making credential stuffing trivial.',
      file: registerFile,
      remediation: 'Enforce minimum length (≥8 chars) and optionally complexity. With zod: z.string().min(8). Consider checking against HaveIBeenPwned via the k-anonymity API.',
      autoFixable: false,
    }];
  }

  return [];
}

// ── AUTH-009: Account enumeration ─────────────────────────────────────────────

const ENUMERATION_DEFS = [
  /['"](?:user not found|username not found|no such user|email not found|account not found|email does not exist)['"]/gi,
  /['"](?:invalid username|wrong username|user does not exist|no user with that email)['"]/gi,
];

async function checkAccountEnumeration(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;
    if (!AUTH_FILE_PATTERN.test(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const pattern of ENUMERATION_DEFS) {
      const re = new RegExp(pattern.source, pattern.flags);
      const match = re.exec(content);
      if (match) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-009',
          severity: 'MEDIUM',
          module: 'auth',
          title: 'Account enumeration: distinct error message reveals whether user exists',
          description: 'Returning different messages for "user not found" vs "wrong password" lets attackers enumerate valid emails/usernames without ever logging in.',
          file: entry.relativePath,
          line,
          snippet: match[0].trim(),
          remediation: 'Always return the same generic message: "Invalid email or password." regardless of whether the user exists. Apply the same artificial delay (e.g. bcrypt compare) to both paths.',
          autoFixable: false,
        });
        break; // one finding per file is enough
      }
    }
  }

  return findings;
}

// ── AUTH-010: No token revocation on logout ───────────────────────────────────

const LOGOUT_ROUTE_DEFS = [
  /(?:router|app)\s*\.\s*(?:post|get)\s*\(\s*['"`][^'"`]*(?:logout|sign-?out)[^'"`]*['"`]/gi,
  /def\s+(?:logout|signout|sign_out)\s*\(/gi,
  /@app\.route\s*\(\s*['"][^'"]*(?:logout|sign-?out)[^'"]*['"]/gi,
];

const REVOCATION_DEFS = [
  /blacklist|tokenBlacklist|revokedTokens|invalidatedTokens/i,
  /redis\s*\.\s*set.*token|token.*redis\s*\.\s*set/i,
  /refreshToken.*delete|deleteRefreshToken|revokeToken/i,
  /TOKEN_BLACKLIST|REVOKED_TOKENS/i,
];

async function checkTokenRevocation(ctx: ScanContext): Promise<Finding[]> {
  let usesJwt     = false;
  let hasLogout   = false;
  let hasRevoke   = false;

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);

    if (content.includes('jwt') || content.includes('JWT')) usesJwt = true;
    if (LOGOUT_ROUTE_DEFS.some(p => new RegExp(p.source, p.flags).exec(content))) hasLogout = true;
    if (REVOCATION_DEFS.some(p => p.test(content))) hasRevoke = true;
  }

  if (usesJwt && hasLogout && !hasRevoke) {
    return [{
      id: 'AUTH-010',
      severity: 'MEDIUM',
      module: 'auth',
      title: 'JWT logout route found but no token revocation/blacklist',
      description: 'A logout endpoint exists but no token blacklist or revocation mechanism detected. After logout the old JWT remains cryptographically valid until it expires — a stolen token stays usable.',
      remediation: "On logout, store the token's JTI in Redis with the token's remaining TTL: await redis.setEx(jti, ttlSeconds, '1'). Reject blacklisted JTIs in your auth middleware.",
      autoFixable: false,
    }];
  }

  return [];
}

// ── AUTH-011: Insecure password reset tokens ──────────────────────────────────

const RESET_FILE_PATTERN = /(?:reset|forgot|recover)/i;

async function checkPasswordResetSecurity(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const isResetFile = RESET_FILE_PATTERN.test(entry.relativePath) ||
      /(?:resetToken|reset_token|forgotPassword|password.?reset)/i.test(content);

    if (!isResetFile) continue;

    // Flag Math.random() used to create a reset token
    const mathRandRe = /(?:token|resetToken|reset_token|verifyToken)\s*[:=][^\n;]*Math\.random\s*\(\s*\)/gi;
    let match: RegExpExecArray | null;
    while ((match = mathRandRe.exec(content)) !== null) {
      const line = content.slice(0, match.index).split('\n').length;
      findings.push({
        id: 'AUTH-011',
        severity: 'HIGH',
        module: 'auth',
        title: 'Password reset token uses Math.random() — not cryptographically secure',
        description: 'Math.random() is a predictable PRNG. An attacker who can observe token patterns may predict the next token and hijack any account password reset.',
        file: entry.relativePath,
        line,
        snippet: match[0].trim().slice(0, 100),
        remediation: 'Use crypto.randomBytes(32).toString("hex") for all security tokens. Always set a short expiry (≤1 hour) and invalidate the token after use.',
        autoFixable: false,
      });
    }
  }

  return findings;
}

// ── AUTH-012: Open redirect after login ──────────────────────────────────────

const OPEN_REDIRECT_DEFS = [
  /res\.redirect\s*\(\s*req\.(?:query|body|params)\s*\.\s*(?:redirect|returnUrl|next|url|destination|return_to)/gi,
  /window\.location\s*=\s*[^'"]*(?:req\.query|req\.body|searchParams)/gi,
];

async function checkOpenRedirect(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;
    if (!AUTH_FILE_PATTERN.test(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const pattern of OPEN_REDIRECT_DEFS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-012',
          severity: 'MEDIUM',
          module: 'auth',
          title: 'Open redirect after login — user-controlled redirect destination',
          description: 'A redirect URL is taken directly from user-supplied input (query string, body). Attackers craft login links that silently redirect victims to phishing sites after authentication.',
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation: 'Use an allowlist of valid redirect paths. Reject any redirect that starts with http:// or // or points to a different domain: if (!url.startsWith("/")) url = "/dashboard".',
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// ── AUTH-013: IDOR — Insecure Direct Object Reference ────────────────────────
// Detects when req.params IDs are used in DB queries without any ownership check

const IDOR_DB_DEFS: Array<{ regex: RegExp; label: string }> = [
  { regex: /\.findById\s*\(\s*req\.params\.\w+/gi,             label: 'findById(req.params.id)' },
  { regex: /\.findByIdAndUpdate\s*\(\s*req\.params\.\w+/gi,    label: 'findByIdAndUpdate(req.params.id)' },
  { regex: /\.findByIdAndDelete\s*\(\s*req\.params\.\w+/gi,    label: 'findByIdAndDelete(req.params.id)' },
  { regex: /\.findByIdAndRemove\s*\(\s*req\.params\.\w+/gi,    label: 'findByIdAndRemove(req.params.id)' },
  { regex: /\.findByPk\s*\(\s*req\.params\.\w+/gi,             label: 'findByPk(req.params.id)' },
  { regex: /\.findOne\s*\(\s*\{[^}]{0,60}_id\s*:\s*req\.params\.\w+/gi, label: 'findOne({ _id: req.params.id })' },
  { regex: /prisma\s*\.\s*\w+\s*\.\s*(?:findUnique|update|delete)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*req\.params\.\w+/gi, label: 'Prisma operation with req.params.id' },
];

// Signals that an ownership check IS present nearby → suppress the finding
const OWNERSHIP_SIGNALS = [
  /req\.user\s*\.\s*(?:id|_id|userId)/i,
  /\.userId\s*(?:!==?|===?)\s*req\.user|req\.user\.(?:id|_id)\s*(?:!==?|===?)/i,
  /checkOwner|isOwner|verifyOwner|belongsTo|ownedBy/i,
  /status\s*\(\s*403\s*\)|Forbidden|not authorized|unauthorized/i,
];

async function checkIDOR(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const lines = content.split('\n');

    for (const { regex, label } of IDOR_DB_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const lineNum = content.slice(0, match.index).split('\n').length;

        // Inspect ±20 lines around the match for an ownership check
        const start  = Math.max(0, lineNum - 20);
        const end    = Math.min(lines.length, lineNum + 20);
        const window = lines.slice(start, end).join('\n');

        if (!OWNERSHIP_SIGNALS.some(p => p.test(window))) {
          findings.push({
            id: 'AUTH-013',
            severity: 'HIGH',
            module: 'auth',
            title: `IDOR: ${label} without ownership check`,
            description:
              'A database record is fetched or mutated using an ID from req.params (user-supplied). ' +
              'Without an ownership check, User A can supply User B\'s ID and read, update, or delete B\'s data.',
            file: entry.relativePath,
            line: lineNum,
            snippet: match[0].trim().slice(0, 100),
            remediation:
              'After fetching the record verify the caller owns it:\n' +
              '  if (record.userId.toString() !== req.user.id)\n' +
              '    return res.status(403).json({ error: "Forbidden" });',
            autoFixable: false,
          });
        }
      }
    }
  }

  return findings;
}

// ── AUTH-014: Unprotected mutating routes (no auth middleware) ────────────────
// Matches DELETE/PUT/PATCH where the path string is followed immediately by an
// arrow/function literal — meaning no middleware sits between path and handler.

const UNPROTECTED_MUTATION_DEFS: Array<{ regex: RegExp; method: string }> = [
  {
    regex: /(?:app|router)\s*\.\s*delete\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)/gi,
    method: 'DELETE',
  },
  {
    regex: /(?:app|router)\s*\.\s*put\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)/gi,
    method: 'PUT',
  },
  {
    regex: /(?:app|router)\s*\.\s*patch\s*\(\s*['"`][^'"`]*['"`]\s*,\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)/gi,
    method: 'PATCH',
  },
  {
    regex: /(?:app|router)\s*\.\s*post\s*\(\s*['"`][^'"`]*(?:delete|remove|destroy|update|edit)[^'"`]*['"`]\s*,\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)/gi,
    method: 'POST (destructive action)',
  },
];

// If a file uses app.use() with an auth middleware, consider all routes covered
const GLOBAL_AUTH_SIGNALS = [
  /app\s*\.\s*use\s*\([^)]*(?:auth|authenticate|requireAuth|verifyToken|protect|isLoggedIn)/i,
  /router\s*\.\s*use\s*\([^)]*(?:auth|authenticate|requireAuth|verifyToken|protect)/i,
];

async function checkUnprotectedRoutes(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  // If a global auth middleware covers all routes, skip
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (GLOBAL_AUTH_SIGNALS.some(p => p.test(content))) return [];
  }

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const { regex, method } of UNPROTECTED_MUTATION_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-014',
          severity: 'HIGH',
          module: 'auth',
          title: `${method} route has no authentication middleware`,
          description:
            `A ${method} route goes directly from path to handler with no middleware in between. ` +
            'Any unauthenticated user — or another authenticated user — can call this endpoint and modify or delete data.',
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation:
            `Add auth middleware before the handler:\n` +
            `  router.${method.split(' ')[0].toLowerCase()}('/path', authenticate, handler)\n` +
            'Then verify the caller owns the resource (see AUTH-013).',
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// ── AUTH-015: Unguarded data listing — returns all user records ───────────────

const DATA_LISTING_DEFS: Array<{ regex: RegExp; desc: string }> = [
  {
    regex: /(?:User|Account|Profile|Member|Customer|Admin)\s*\.\s*find\s*\(\s*\{\s*\}\s*\)/gi,
    desc: 'Mongoose .find({}) returns every document',
  },
  {
    regex: /(?:User|Account|Profile|Member|Customer|Admin)\s*\.\s*findAll\s*\(\s*\)/gi,
    desc: 'Sequelize .findAll() returns every row',
  },
  {
    regex: /prisma\s*\.\s*(?:user|account|profile|member|customer)\s*\.\s*findMany\s*\(\s*\)/gi,
    desc: 'Prisma .findMany() returns every record',
  },
  {
    regex: /SELECT\s+\*\s+FROM\s+(?:users|accounts|profiles|members|customers)\s*[;'"` \n]/gi,
    desc: 'Raw SQL SELECT * FROM users',
  },
];

// If nearby code checks for admin role or filters by userId, it is intentional
const DATA_LISTING_SAFE_SIGNALS = [
  /req\.user\s*\.\s*(?:id|_id|role)/i,
  /where.*(?:userId|user_id)|(?:userId|user_id).*where/i,
  /isAdmin|requireAdmin|role\s*===?\s*['"]admin['"]/i,
  /admin.*route|route.*admin/i,
];

async function checkUnguardedDataListing(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    const lines = content.split('\n');

    for (const { regex, desc } of DATA_LISTING_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const lineNum = content.slice(0, match.index).split('\n').length;

        // Look ±15 lines for an admin check or user filter
        const windowStart = Math.max(0, lineNum - 15);
        const windowEnd   = Math.min(lines.length, lineNum + 10);
        const window = lines.slice(windowStart, windowEnd).join('\n');

        if (!DATA_LISTING_SAFE_SIGNALS.some(p => p.test(window))) {
          findings.push({
            id: 'AUTH-015',
            severity: 'HIGH',
            module: 'auth',
            title: `Unguarded data listing: ${desc}`,
            description:
              'A query that returns ALL records of a sensitive model was found without a user-scoped filter or admin-role guard. ' +
              'Any caller — or any authenticated user — could retrieve every other user\'s data.',
            file: entry.relativePath,
            line: lineNum,
            snippet: match[0].trim().slice(0, 100),
            remediation:
              'Filter by the authenticated user: Model.find({ userId: req.user.id })\n' +
              'Or restrict the route to admins only and add a role check before this query.',
            autoFixable: false,
          });
        }
      }
    }
  }

  return findings;
}

// ── AUTH-016: GET routes with no auth and user-specific path params ───────────

const UNAUTH_GET_DEFS = [
  /(?:app|router)\s*\.\s*get\s*\(\s*['"`][^'"`]*:(?:id|userId|accountId|profileId|orderId|postId)[^'"`]*['"`]\s*,\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)/gi,
];

async function checkUnprotectedGetRoutes(ctx: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Skip if global auth detected
  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (GLOBAL_AUTH_SIGNALS.some(p => p.test(content))) return [];
  }

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    if (isTestFile(entry.relativePath)) continue;

    const content = await getFileContent(entry, ctx.contentCache);
    for (const regex of UNAUTH_GET_DEFS) {
      const re = new RegExp(regex.source, regex.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          id: 'AUTH-016',
          severity: 'HIGH',
          module: 'auth',
          title: 'GET route with user-specific path param has no auth middleware',
          description:
            'A GET route that accepts a user-specific ID (userId, profileId, etc.) has no authentication middleware. ' +
            'Any unauthenticated visitor can query any user\'s data by guessing or iterating IDs.',
          file: entry.relativePath,
          line,
          snippet: match[0].trim().slice(0, 100),
          remediation:
            'Add authentication middleware: router.get("/:userId", authenticate, handler)\n' +
            'Then check ownership: if (params.userId !== req.user.id) return res.status(403).json({ error: "Forbidden" })',
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();

  const [
    hashing,
    credentials,
    jwt,
    adminRoutes,
    massAssign,
    sessionCookies,
    complexity,
    enumeration,
    revocation,
    resetSecurity,
    openRedirect,
    idor,
    unprotectedRoutes,
    dataListing,
    unprotectedGet,
  ] = await Promise.all([
    checkPasswordHashing(ctx),
    checkHardcodedCredentials(ctx),
    checkJwtSecurity(ctx),
    checkAdminRouteProtection(ctx),
    checkMassAssignment(ctx),
    checkSessionCookies(ctx),
    checkPasswordComplexity(ctx),
    checkAccountEnumeration(ctx),
    checkTokenRevocation(ctx),
    checkPasswordResetSecurity(ctx),
    checkOpenRedirect(ctx),
    checkIDOR(ctx),
    checkUnprotectedRoutes(ctx),
    checkUnguardedDataListing(ctx),
    checkUnprotectedGetRoutes(ctx),
  ]);

  return {
    module: 'auth',
    findings: [
      ...hashing,
      ...credentials,
      ...jwt,
      ...adminRoutes,
      ...massAssign,
      ...sessionCookies,
      ...complexity,
      ...enumeration,
      ...revocation,
      ...resetSecurity,
      ...openRedirect,
      ...idor,
      ...unprotectedRoutes,
      ...dataListing,
      ...unprotectedGet,
    ],
    duration: Date.now() - start,
  };
}
