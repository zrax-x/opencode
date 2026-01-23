/**
 * Types for EndpointAnalyzer agent
 */

import type {
  CodeLocation,
  VulnerabilityType,
  Severity,
  Endpoint,
  AuthInfo,
} from './common.js';
import type { DataFlowPath } from './dataflow-tracer.js';

export interface AnalysisTask {
  endpoint: Endpoint;
  focusAreas?: VulnerabilityType[];
}

export interface InputSource {
  type: 'query' | 'body' | 'header' | 'cookie' | 'path';
  name: string;
  location: CodeLocation;
}

export interface DangerousSink {
  type: VulnerabilityType;
  functionName: string;
  location: CodeLocation;
  cweId: number;
}

export interface Finding {
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
  cweId: number;
  location: CodeLocation;
  dataFlowPath: DataFlowPath;
  codeSnippet: string;
  confidence: 'INITIAL';
}

export interface AnalysisResult {
  endpoint: Endpoint;
  findings: Finding[];
  authInfo: AuthInfo;
  analysisTime: number;
  errors?: string[];
}

export interface EndpointAnalyzer {
  analyzeEndpoint(task: AnalysisTask): Promise<AnalysisResult>;
  identifyInputSources(endpoint: Endpoint): InputSource[];
  identifyDangerousSinks(code: string): DangerousSink[];
  detectAuthMechanism(endpoint: Endpoint): AuthInfo;
}
