/**
 * Types for OpenSrc-VulnScanner main orchestrator agent
 */

import type { Endpoint, ScanOptions, ScanResult, Confidence } from './common.js';
import type { AnalysisResult, Finding } from './endpoint-analyzer.js';

export interface AggregatedFindings {
  findings: FindingWithConfidence[];
  statistics: {
    totalEndpoints: number;
    analyzedEndpoints: number;
    totalFindings: number;
    bySeverity: Record<string, number>;
    byType: Record<string, number>;
    byConfidence: Record<Confidence, number>;
  };
}

export interface FindingWithConfidence extends Omit<Finding, 'confidence'> {
  confidence: Confidence;
}

export interface SARIFReport {
  version: '2.1.0';
  $schema: string;
  runs: SARIFRun[];
}

export interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri?: string;
    };
  };
  results: SARIFResult[];
  invocations?: SARIFInvocation[];
}

export interface SARIFResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: {
    text: string;
  };
  locations: SARIFLocation[];
  codeFlows?: SARIFCodeFlow[];
  properties?: Record<string, any>;
}

export interface SARIFLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
    region: {
      startLine: number;
      startColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
}

export interface SARIFCodeFlow {
  threadFlows: Array<{
    locations: Array<{
      location: SARIFLocation;
      state?: Record<string, string>;
    }>;
  }>;
}

export interface SARIFInvocation {
  executionSuccessful: boolean;
  startTimeUtc: string;
  endTimeUtc: string;
}

export interface OpenSrcVulnScanner {
  scanCodebase(options: ScanOptions): Promise<ScanResult>;
  discoverEndpoints(codebasePath: string): Promise<Endpoint[]>;
  calculatePriority(endpoint: Endpoint): number;
  dispatchAnalysis(endpoints: Endpoint[], concurrency: number): Promise<AnalysisResult[]>;
  aggregateResults(
    results: AnalysisResult[],
    options?: { includeLowConfidence?: boolean; verifyFindings?: boolean }
  ): Promise<AggregatedFindings>;
  generateSARIF(
    findings: AggregatedFindings,
    options: { outputDir: string; codebasePath: string }
  ): Promise<{ report: SARIFReport; filePath: string }>;
}
