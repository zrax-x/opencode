/**
 * Types for VulnVerifier agent
 */

import type { Severity, VulnerabilityType } from './common.js';
import type { Finding } from './endpoint-analyzer.js';
import type { DataFlowPath, SanitizationInfo, ValidationInfo } from './dataflow-tracer.js';

export interface VerificationResult {
  originalFinding: Finding;
  confidence: 'CONFIRMED' | 'UNCERTAIN' | 'REJECTED';
  reasoning: string;
  additionalEvidence?: string[];
  updatedSeverity?: Severity;
}

export interface VulnVerifier {
  verifyVulnerability(finding: Finding): Promise<VerificationResult>;
  reanalyzeDataFlow(path: DataFlowPath): Promise<DataFlowPath>;
  assessSanitization(sanitization: SanitizationInfo, vulnType: VulnerabilityType): boolean;
  assessValidation(validation: ValidationInfo, vulnType: VulnerabilityType): boolean;
}
