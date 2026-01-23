/**
 * Common types shared across all agents
 */

export type VulnerabilityType =
  | 'RCE'
  | 'COMMAND_INJECTION'
  | 'AUTH_BYPASS'
  | 'ARBITRARY_FILE_READ'
  | 'PATH_TRAVERSAL';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type Confidence = 'HIGH_CONFIDENCE' | 'MEDIUM_CONFIDENCE' | 'LOW_CONFIDENCE';

export interface CodeLocation {
  filePath: string;
  lineNumber: number;
  columnNumber?: number;
  functionName?: string;
}

export interface AuthInfo {
  requiresAuth: boolean;
  authType?: 'JWT' | 'SESSION' | 'API_KEY' | 'OAUTH' | 'BASIC' | 'NONE';
  authMiddleware?: string[];
  rbacChecks?: string[];
}

export interface Endpoint {
  filePath: string;
  lineNumber: number;
  httpMethod?: string;
  routePattern: string;
  handlerFunction: string;
  framework: string;
  language: string;
  requiresAuth: boolean;
  priorityScore: number;
}

export interface ScanOptions {
  codebasePath: string;
  outputDir: string;
  concurrency?: number;
  topN?: number;
  includeLowConfidence?: boolean;
  languages?: string[];
}

export interface ScanResult {
  sarifReportPath: string;
  summary: {
    totalEndpoints: number;
    analyzedEndpoints: number;
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    byType: Record<VulnerabilityType, number>;
    byConfidence: Record<Confidence, number>;
  };
  executionTime: number;
  errors: string[];
}
