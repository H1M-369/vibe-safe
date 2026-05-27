export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AuditModule = 'legal' | 'security' | 'secrets' | 'abuse' | 'environment' | 'error-pages' | 'auth';
export type ProbeModule = 'sql-injection' | 'xss' | 'headers' | 'rate-limit' | 'auth-bypass' | 'sensitive-endpoints' | 'error-pages';
export type ProjectType = 'node' | 'python' | 'mixed' | 'unknown';
export type FrameworkHint = 'express' | 'nextjs' | 'nestjs' | 'fastapi' | 'flask' | 'react';

export interface FileEntry {
  absolutePath: string;
  relativePath: string;
  extension: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  module: AuditModule;
  title: string;
  description: string;
  file?: string;
  line?: number;
  snippet?: string;
  remediation: string;
  autoFixable: boolean;
  fixId?: string;
}

export interface ProbeResult {
  id: string;
  module: ProbeModule;
  severity: Severity;
  title: string;
  confirmed: boolean;
  endpoint: string;
  payload: string;
  response: string;
  remediation: string;
}

export interface ScanContext {
  rootPath: string;
  files: FileEntry[];
  projectType: ProjectType;
  frameworks: FrameworkHint[];
  gitAvailable: boolean;
  contentCache: Map<string, string>;
}

export interface AuditResult {
  module: AuditModule;
  findings: Finding[];
  duration: number;
}

export interface ScanResult {
  rootPath: string;
  projectType: ProjectType;
  frameworks: FrameworkHint[];
  auditResults: AuditResult[];
  probeResults: ProbeResult[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scanDuration: number;
  timestamp: string;
}

export interface FixResult {
  fixId: string;
  applied: boolean;
  description: string;
  error?: string;
}

export interface ScanOptions {
  only?: string[];
  severity?: Severity;
  fix?: boolean;
  probeUrl?: string;
  output?: string;
  json?: boolean;
  rateLimitCount?: number;
}
