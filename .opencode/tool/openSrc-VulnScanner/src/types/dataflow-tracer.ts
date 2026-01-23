/**
 * Types for DataFlowTracer agent
 */

import type { CodeLocation } from './common.js';

export interface TraceRequest {
  sourceLocation: CodeLocation;
  sinkLocation: CodeLocation;
  sourceVariable: string;
  sinkFunction: string;
  maxDepth?: number;
}

export interface DataFlowStep {
  type: 'assignment' | 'function_call' | 'return' | 'parameter';
  location: CodeLocation;
  code: string;
  variable?: string;
  operation?: string;
}

export interface SanitizationInfo {
  functionName: string;
  location: CodeLocation;
  effectiveness: 'STRONG' | 'WEAK' | 'UNKNOWN';
}

export interface ValidationInfo {
  type: 'type_check' | 'range_check' | 'regex' | 'whitelist' | 'blacklist';
  location: CodeLocation;
  effectiveness: 'STRONG' | 'WEAK' | 'UNKNOWN';
}

export interface DataFlowPath {
  source: CodeLocation;
  sink: CodeLocation;
  steps: DataFlowStep[];
  hasSanitization: boolean;
  hasValidation: boolean;
  classification: 'CONFIRMED' | 'LIKELY' | 'POSSIBLE';
}

export type ExploitabilityScore = number;

export interface DataFlowTracer {
  traceDataFlow(request: TraceRequest): Promise<DataFlowPath>;
  detectSanitization(path: DataFlowPath): SanitizationInfo[];
  detectValidation(path: DataFlowPath): ValidationInfo[];
  assessExploitability(path: DataFlowPath): ExploitabilityScore;
}
