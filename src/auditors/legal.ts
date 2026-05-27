import {
  ScanContext, AuditResult, Finding,
} from '../types';
import { getFileContent } from '../utils/fileWalker';

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py']);
const PII_PATTERN = /['"]?(?:email|phone|phoneNumber|firstName|lastName|first_name|last_name|ssn|socialSecurity|dateOfBirth|dob|address|creditCard|credit_card)['"]?\s*[:=]/gi;
const COOKIE_WRITE_PATTERN = /(?:res\.cookie\s*\(|document\.cookie\s*=|set_cookie\s*\()/g;

async function checkPrivacyPolicy(ctx: ScanContext): Promise<Finding[]> {
  const hasPrivacyFile = ctx.files.some(f =>
    /privacy/i.test(f.relativePath) && /\.(md|html|txt|jsx?|tsx?)$/.test(f.relativePath)
  );
  if (hasPrivacyFile) return [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (/['"\/]privacy['"\/]/i.test(content)) return [];
  }

  return [{
    id: 'LEGAL-001',
    severity: 'MEDIUM',
    module: 'legal',
    title: 'No privacy policy detected',
    description: 'If you collect ANY user data (emails, names, usage analytics), you are legally required to have a privacy policy in most jurisdictions. Missing one exposes you to regulatory action under GDPR, CCPA, and other laws.',
    remediation: 'Add a /privacy route or privacy.md/privacy.html file. Use a privacy policy generator (privacypolicies.com) and customize it to match what your app actually collects.',
    autoFixable: true,
    fixId: 'create-privacy-policy',
  }];
}

async function checkTermsOfService(ctx: ScanContext): Promise<Finding[]> {
  const hasTermsFile = ctx.files.some(f =>
    /terms/i.test(f.relativePath) && /\.(md|html|txt|jsx?|tsx?)$/.test(f.relativePath)
  );
  if (hasTermsFile) return [];

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (/['"\/]terms['"\/]/i.test(content)) return [];
  }

  return [{
    id: 'LEGAL-002',
    severity: 'MEDIUM',
    module: 'legal',
    title: 'No terms of service detected',
    description: 'Without a Terms of Service, you have no legal agreement with your users. This leaves you unprotected if users misuse your service, demand refunds, or make legal claims.',
    remediation: 'Add a /terms route or terms.md/terms.html file. A ToS should cover: acceptable use, limitation of liability, dispute resolution, and termination conditions.',
    autoFixable: true,
    fixId: 'create-terms-of-service',
  }];
}

async function checkPIICollection(ctx: ScanContext): Promise<Finding[]> {
  let piiFound = false;
  let piiFile = '';

  for (const entry of ctx.files) {
    if (!SOURCE_EXTENSIONS.has(entry.extension)) continue;
    const content = await getFileContent(entry, ctx.contentCache);
    if (PII_PATTERN.test(content)) {
      piiFound = true;
      piiFile = entry.relativePath;
      break;
    }
  }

  if (!piiFound) return [];

  // Check if privacy policy exists
  const hasPrivacy = ctx.files.some(f => /privacy/i.test(f.relativePath));

  if (!hasPrivacy) {
    return [{
      id: 'LEGAL-003',
      severity: 'HIGH',
      module: 'legal',
      title: 'PII collected without a privacy policy',
      description: `Personal data fields (email, phone, name, etc.) were found in ${piiFile} but no privacy policy exists. Collecting PII without disclosing how it is used and stored is illegal under GDPR, CCPA, and most privacy laws.`,
      file: piiFile,
      remediation: '1. Add a privacy policy that describes what data you collect and why. 2. Implement a consent mechanism before collecting data. 3. Add a data deletion endpoint (required by GDPR).',
      autoFixable: false,
    }];
  }

  return [{
    id: 'LEGAL-003',
    severity: 'LOW',
    module: 'legal',
    title: 'PII collection detected — verify your privacy policy covers it',
    description: `Personal data fields found in ${piiFile}. A privacy policy exists, but confirm it accurately describes what you collect, why, and how long you keep it.`,
    file: piiFile,
    remediation: 'Review your privacy policy against the actual data fields you collect. Ensure GDPR compliance: include data subject rights, retention periods, and data processor agreements.',
    autoFixable: false,
  }];
}

async function checkCookieConsent(ctx: ScanContext): Promise<Finding[]> {
  let setsCookies = false;
  const consentKeywords = [
    'cookie-consent', 'cookieConsent', 'CookieConsent',
    'react-cookie-consent', 'js-cookie', 'cookie_consent',
    'cookiebanner', 'cookie-banner',
  ];

  for (const entry of ctx.files) {
    const content = await getFileContent(entry, ctx.contentCache);
    if (COOKIE_WRITE_PATTERN.test(content)) setsCookies = true;
    if (consentKeywords.some(kw => content.includes(kw))) return [];
  }

  if (!setsCookies) return [];

  return [{
    id: 'LEGAL-004',
    severity: 'LOW',
    module: 'legal',
    title: 'Cookies set without detected consent mechanism',
    description: 'The app sets cookies but no cookie consent banner or library was detected. GDPR and ePrivacy Directive require informed user consent before setting non-essential cookies for EU users.',
    remediation: 'Add a cookie consent banner. For React: react-cookie-consent. Ensure non-essential cookies are only set after consent.',
    autoFixable: false,
  }];
}

export async function audit(ctx: ScanContext): Promise<AuditResult> {
  const start = Date.now();
  const [privacy, terms, pii, cookies] = await Promise.all([
    checkPrivacyPolicy(ctx),
    checkTermsOfService(ctx),
    checkPIICollection(ctx),
    checkCookieConsent(ctx),
  ]);

  return {
    module: 'legal',
    findings: [...privacy, ...terms, ...pii, ...cookies],
    duration: Date.now() - start,
  };
}
